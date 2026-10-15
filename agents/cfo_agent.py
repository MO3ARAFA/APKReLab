"""AI CFO: strict seed-capital allocation, hard caps, circuit breaker and ROI telemetry.

Capital matrix at the default $10.00 seed (fractions scale if SEED_CAPITAL_USD changes):
  Group A  $8.00: PRJ-03 $3.50 | PRJ-01 $2.50 | PRJ-02 $2.00
  Group B  $0.50: PRJ-04 $0.25 | PRJ-05 $0.25   (local/deterministic only until Group A logs real revenue)
  Reserve  $1.50: locked; auto-released to the first Group A project that logs real revenue.
The $10 ceiling is absolute: logged revenue (an unverified CLI input) can never raise it. The 60% Group A profit ->
Group B reinvestment only moves quota into *unallocated headroom under the seed* (none at the default matrix, since
the reserve vault is the scaling mechanism); raise SEED_CAPITAL_USD (and --reset) to deliberately re-seed.
Revenue is never invented: it is logged explicitly (`main.py --log-revenue PRJ-03 --amount 1500`).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass

from config import roi_values
from llm import LLMResult
from state import PROJECT_META, AgencyState, now

REINVEST_RATE = 0.60
TRIP_EPSILON = 1e-4  # global remaining at/below this => breaker TRIPPED
LEDGER_MAX = 2000


@dataclass
class AuditResult:
    approved: bool
    status: str
    reasons: list[str]


def compute_summary(snap: dict) -> dict:
    """Pure function of a state snapshot: everything the dashboard / CFO summary shows."""
    projects = snap["projects"].values()
    seed = snap.get("seed_usd", snap["budget_usd"])
    burn = sum(p["spent_usd"] for p in projects)
    ceiling = seed  # hard cap: revenue never raises it
    remaining = ceiling - burn
    vals = roi_values()
    pipeline = sum(n * vals.get(unit, 0.0) for p in projects for unit, n in p.get("units", {}).items())
    tripped = remaining <= TRIP_EPSILON
    v = snap.get("vault", {})
    return {
        "seed_usd": seed, "burn_usd": burn, "remaining_seed_usd": seed - burn, "ceiling_usd": ceiling,
        "global_remaining_usd": remaining, "cache_savings_usd": snap.get("cache_savings_usd", 0.0),
        "cache_hits": snap.get("cache_hits", 0), "blocked_calls": snap.get("blocked_calls", 0),
        "pipeline_usd": pipeline, "roi_multiple": (pipeline / burn) if burn > 0 else None,
        "breaker": "TRIPPED (Hard Cap Reached)" if tripped else f"ACTIVE (${remaining:.2f} remaining)",
        "breaker_tripped": tripped,
        "vault": ("LOCKED $%.2f" % v["amount"]) if v.get("locked") else f"RELEASED ${v.get('amount', 0):.2f} -> {v.get('released_to')}",
        "units": {pid: dict(p.get("units", {})) for pid, p in snap["projects"].items() if p.get("units")},
    }


class ProjectGate:
    """BudgetGate bound to one project; handed to that project's LLMClient."""

    def __init__(self, cfo: "CFOAgent", pid: str):
        self.cfo, self.pid = cfo, pid

    def try_reserve(self, est_usd: float) -> tuple[bool, str]:
        return self.cfo.reserve(self.pid, est_usd)

    def release(self, est_usd: float) -> None:
        self.cfo.release(self.pid, est_usd)


class CFOAgent:
    def __init__(self, state: AgencyState, compute_rate_per_hour: float = 0.0):
        self.state = state
        self.rate = compute_rate_per_hour
        self._reserved: dict[str, float] = {pid: 0.0 for pid in PROJECT_META}
        self._rlock = threading.Lock()

    def gate(self, pid: str) -> ProjectGate:
        return ProjectGate(self, pid)

    # -- circuit breaker -------------------------------------------------------------------
    def reserve(self, pid: str, est_usd: float) -> tuple[bool, str]:
        """Atomically reserve worst-case cost of a live call, or refuse (caller falls back to local execution)."""
        with self.state._lock, self._rlock:
            d = self.state.data
            p = d["projects"][pid]
            if p["group"] == "B" and not any(q["revenue_usd"] > 0 for q in d["projects"].values() if q["group"] == "A"):
                return False, f"{pid} is local-only until Group A logs revenue"
            proj_left = p["quota_usd"] - p["spent_usd"] - self._reserved[pid]
            if est_usd > proj_left + 1e-12:
                return False, f"call est ${est_usd:.5f} exceeds {pid} sub-budget (${max(proj_left, 0):.5f} left)"
            burn = sum(q["spent_usd"] for q in d["projects"].values())
            glob_left = d.get("seed_usd", d["budget_usd"]) - burn - sum(self._reserved.values())
            if est_usd > glob_left + 1e-12:
                return False, f"call est ${est_usd:.5f} exceeds global hard cap (${max(glob_left, 0):.5f} left)"
            self._reserved[pid] += est_usd
            return True, ""

    def release(self, pid: str, est_usd: float) -> None:
        with self._rlock:
            self._reserved[pid] = max(0.0, self._reserved[pid] - est_usd)

    # -- accounting ------------------------------------------------------------------------
    def record_usage(self, pid: str, res: LLMResult) -> None:
        def f(d):
            p = d["projects"][pid]
            entry = {"t": now(), "project": pid, "kind": "api", "provider": res.provider, "model": res.model, "tier": res.tier}
            if res.blocked:
                p["blocked_calls"] += 1
                d["blocked_calls"] = d.get("blocked_calls", 0) + 1
                p["last_block"] = res.blocked
                entry.update(kind="blocked", usd=0.0, reason=res.blocked)
            elif res.cached:
                p["cache_hits"] += 1
                p["cache_saved_usd"] = round(p["cache_saved_usd"] + res.saved_usd, 8)
                d["cache_hits"] = d.get("cache_hits", 0) + 1
                d["cache_savings_usd"] = round(d.get("cache_savings_usd", 0.0) + res.saved_usd, 8)
                entry.update(kind="cache_hit", usd=0.0, saved_usd=res.saved_usd)
            else:
                if res.provider != "offline":
                    p["api_calls"] += 1
                p["tokens_in"] += res.tokens_in
                p["tokens_out"] += res.tokens_out
                p["spent_usd"] = round(p["spent_usd"] + res.cost_usd, 8)
                entry.update(tokens_in=res.tokens_in, tokens_out=res.tokens_out, usd=res.cost_usd)
            d["ledger"].append(entry)
            del d["ledger"][:-LEDGER_MAX]
        self.state.update(f)

    def record_compute(self, pid: str, seconds: float) -> None:
        usd = seconds / 3600 * self.rate

        def f(d):
            p = d["projects"][pid]
            p["compute_s"] = round(p["compute_s"] + seconds, 3)
            p["spent_usd"] = round(p["spent_usd"] + usd, 8)
        self.state.update(f)

    def log_revenue(self, pid: str, amount: float, note: str = "") -> None:
        if pid not in PROJECT_META:
            raise ValueError(f"unknown project {pid}")
        if amount <= 0:
            raise ValueError("amount must be positive")

        def f(d):
            p = d["projects"][pid]
            p["revenue_usd"] = round(p["revenue_usd"] + amount, 2)
            d["revenue"].append({"t": now(), "project": pid, "usd": amount, "note": note})
            v = d["vault"]
            if v["locked"] and p["group"] == "A":  # first real dollar from Group A unlocks the reserve for that project
                p["quota_usd"] = round(p["quota_usd"] + v["amount"], 6)
                v["locked"], v["released_to"] = False, pid
                d["ledger"].append({"t": now(), "kind": "vault_release", "project": pid, "usd": v["amount"]})
        self.state.update(f)
        self.rebalance()

    # -- cross-subsidization ---------------------------------------------------------------
    def group_profit(self, group: str = "A") -> float:
        ps = [p for p in self.state.snapshot()["projects"].values() if p["group"] == group]
        return sum(p["revenue_usd"] - p["spent_usd"] for p in ps)

    def group_b_unlocked(self) -> bool:
        return any(p["revenue_usd"] > 0 for p in self.state.snapshot()["projects"].values() if p["group"] == "A")

    def rebalance(self) -> float:
        """Reinvest 60% of positive Group A profit into Group B quotas, but only into headroom under the seed cap.
        Idempotent: `reinvested_usd` tracks what was actually applied."""
        profit = max(0.0, self.group_profit("A"))

        def f(d):
            target = round(REINVEST_RATE * profit, 6)
            committed = sum(p["quota_usd"] for p in d["projects"].values()) + (d["vault"]["amount"] if d["vault"]["locked"] else 0.0)
            headroom = max(0.0, round(d.get("seed_usd", d["budget_usd"]) - committed, 6))
            delta = min(round(target - d["reinvested_usd"], 6), headroom)
            if delta <= 0:
                return 0.0
            b = [p for p in d["projects"].values() if p["group"] == "B"]
            for p in b:
                p["quota_usd"] = round(p["quota_usd"] + delta / len(b), 6)
            d["reinvested_usd"] = target
            d["ledger"].append({"t": now(), "kind": "reinvest", "usd": delta})
            return delta
        return self.state.update(f)

    # -- gates -----------------------------------------------------------------------------
    def run_mode(self, pid: str) -> str:
        if PROJECT_META[pid]["group"] == "A":
            return "production"
        return "reinvested" if self.group_b_unlocked() else "dry-run"

    def preflight(self, pid: str) -> AuditResult:
        """Only an accounting breach (spend above quota) blocks a run. An exhausted API sub-budget just means the
        breaker keeps the project on free local execution."""
        p = self.state.project(pid)
        if p["spent_usd"] > p["quota_usd"] + 1e-9:
            return AuditResult(False, "OVER BUDGET", [f"{pid} quota ${p['quota_usd']:.4f} exceeded"])
        return AuditResult(True, "OK", [])

    def audit(self, pid: str) -> AuditResult:
        """Post-run financial audit (second gate)."""
        p = self.state.project(pid)
        reasons: list[str] = []
        used = p["spent_usd"] / p["quota_usd"] if p["quota_usd"] else 1.0
        if p["spent_usd"] > p["quota_usd"] + 1e-9:
            return AuditResult(False, "OVER BUDGET", [f"spent ${p['spent_usd']:.4f} > quota ${p['quota_usd']:.4f}"])
        if p["group"] == "B" and not self.group_b_unlocked():
            status = "DRY-RUN"
            reasons.append("Group B limited to local execution until Group A logs revenue")
        elif p["blocked_calls"] > 0:
            status = "BREAKER"
            reasons.append(f"{p['blocked_calls']} live call(s) blocked; deterministic fallback used: {p['last_block']}")
        elif used >= 0.8:
            status = "WATCH"
            reasons.append(f"{used:.0%} of quota used")
        else:
            status = "HEALTHY"
        self.state.set_project(pid, cfo_status=status)
        return AuditResult(True, status, reasons)

    def burn_rate(self, pid: str) -> float:
        """USD per hour of active compute/API time (0 if the project has not run)."""
        p = self.state.project(pid)
        return p["spent_usd"] / (p["compute_s"] / 3600) if p["compute_s"] > 0 else 0.0

    def summary(self) -> dict:
        return compute_summary(self.state.snapshot())
