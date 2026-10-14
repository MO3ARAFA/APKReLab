"""AI CFO: cost tracking and the Cross-Subsidization Financial Model.

* 85% of the initial quota goes to Group A (3 cash cows, split evenly).
* 15% goes to Group B (2 deep-tech projects, split evenly) and Group B runs *dry-run* only
  until Group A has logged revenue.
* Once Group A is profitable, 60% of Group A profit is reinvested into Group B quotas.
Revenue is never invented: it is logged explicitly (`main.py --log-revenue PRJ-01 --amount 250`).
"""
from __future__ import annotations

from dataclasses import dataclass

from llm import LLMResult
from state import PROJECT_META, AgencyState, now

REINVEST_RATE = 0.60


@dataclass
class AuditResult:
    approved: bool
    status: str
    reasons: list[str]


class CFOAgent:
    def __init__(self, state: AgencyState, compute_rate_per_hour: float):
        self.state = state
        self.rate = compute_rate_per_hour

    # -- accounting ------------------------------------------------------------------------
    def record_usage(self, pid: str, res: LLMResult) -> None:
        def f(d):
            p = d["projects"][pid]
            p["api_calls"] += 1
            p["tokens_in"] += res.tokens_in
            p["tokens_out"] += res.tokens_out
            p["spent_usd"] = round(p["spent_usd"] + res.cost_usd, 8)
            d["ledger"].append({"t": now(), "project": pid, "kind": "api", "provider": res.provider,
                                "tokens_in": res.tokens_in, "tokens_out": res.tokens_out,
                                "usd": res.cost_usd})
        self.state.update(f)

    def record_compute(self, pid: str, seconds: float) -> None:
        usd = seconds / 3600 * self.rate

        def f(d):
            p = d["projects"][pid]
            p["compute_s"] = round(p["compute_s"] + seconds, 3)
            p["spent_usd"] = round(p["spent_usd"] + usd, 8)
            d["ledger"].append({"t": now(), "project": pid, "kind": "compute", "seconds": seconds, "usd": usd})
        self.state.update(f)

    def log_revenue(self, pid: str, amount: float, note: str = "") -> None:
        if pid not in PROJECT_META:
            raise ValueError(f"unknown project {pid}")
        if amount <= 0:
            raise ValueError("amount must be positive")

        def f(d):
            d["projects"][pid]["revenue_usd"] = round(d["projects"][pid]["revenue_usd"] + amount, 2)
            d["revenue"].append({"t": now(), "project": pid, "usd": amount, "note": note})
        self.state.update(f)
        self.rebalance()

    # -- cross-subsidization ---------------------------------------------------------------
    def group_profit(self, group: str = "A") -> float:
        d = self.state.snapshot()
        ps = [p for p in d["projects"].values() if p["group"] == group]
        return sum(p["revenue_usd"] - p["spent_usd"] for p in ps)

    def group_b_unlocked(self) -> bool:
        d = self.state.snapshot()
        return any(p["revenue_usd"] > 0 for p in d["projects"].values() if p["group"] == "A")

    def rebalance(self) -> float:
        """Reinvest 60% of positive Group A profit into Group B quotas. Idempotent: only the delta is added."""
        profit = max(0.0, self.group_profit("A"))

        def f(d):
            target = round(REINVEST_RATE * profit, 6)
            delta = round(target - d["reinvested_usd"], 6)
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
        p = self.state.project(pid)
        if p["spent_usd"] >= p["quota_usd"]:
            return AuditResult(False, "OVER BUDGET", [f"{pid} quota ${p['quota_usd']:.4f} exhausted"])
        return AuditResult(True, "OK", [])

    def audit(self, pid: str) -> AuditResult:
        """Post-run financial audit (second gate)."""
        p = self.state.project(pid)
        reasons: list[str] = []
        used = p["spent_usd"] / p["quota_usd"] if p["quota_usd"] else 1.0
        if p["spent_usd"] > p["quota_usd"]:
            return AuditResult(False, "OVER BUDGET", [f"spent ${p['spent_usd']:.4f} > quota ${p['quota_usd']:.4f}"])
        if p["group"] == "B" and not self.group_b_unlocked():
            status = "DRY-RUN"
            reasons.append("Group B limited to dry-run until Group A logs revenue")
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
