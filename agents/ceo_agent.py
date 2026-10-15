"""AI CEO: final quality gate (>=95%) and the live Executive Dashboard."""
from __future__ import annotations

import ast
import json
from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.text import Text

from agents.cfo_agent import compute_summary
from llm import LLMClient
from projects.prj_03_deal_closer import prospects
from state import AgencyState, now


@dataclass
class QCReport:
    score: float
    approved: bool
    feedback: list[str] = field(default_factory=list)
    breakdown: dict[str, float] = field(default_factory=dict)


class CEOAgent:
    WEIGHTS = {"artifacts": 40.0, "verification": 50.0, "reporting": 10.0}

    def __init__(self, state: AgencyState, threshold: float = 95.0):
        self.state = state
        self.threshold = threshold

    # -- planning --------------------------------------------------------------------------
    def dispatch_plan(self) -> list[str]:
        """Group A first (cash), Group B limited by the CFO."""
        return ["PRJ-01", "PRJ-02", "PRJ-03", "PRJ-04", "PRJ-05"]

    # -- campaign management: lead dispatch to PM-03 -----------------------------------------
    def audited_urls(self) -> set[str]:
        return set(self.state.snapshot().get("prospects", {}).get("audited", {}))

    def pool_status(self) -> dict:
        return prospects.pool_status(prospects.load_pool(), self.audited_urls())

    def mark_audited(self, results: list[dict]) -> int:
        """Record which prospects have been through PM-03's batch audit (success or not) so the next batch moves on."""
        def f(d):
            book = d.setdefault("prospects", {}).setdefault("audited", {})
            for r in results:
                if r.get("url"):
                    book[prospects.norm_url(r["url"])] = {"t": now(), "ready": bool(r.get("ready")), "error": str(r.get("error", ""))[:120]}
        self.state.update(f)
        return len(results)

    def discover_prospects(self, llm: LLMClient, n: int, exclude: set[str]) -> list[dict]:
        """Ask the tier-1 model for fresh leads. Suggestions are unverified: validated, fetched, and greeted with 'there'."""
        known = ", ".join(sorted(u.split("//")[-1] for u in exclude))[:600] or "none"
        res = llm.complete(
            f"Suggest {n + 3} real, currently operating B2B SaaS companies or digital marketing agencies with a public marketing "
            f"website, small to mid-size, not in this list: {known}. Reply with ONLY a JSON array like "
            f'[{{"company": "Name", "url": "https://example.com"}}]. Use only companies you are confident exist.',
            system="You are a careful B2B market researcher. Never invent companies or URLs; if unsure, return fewer.",
            fallback="[]", max_tokens=600)
        out = []
        for row in prospects.parse_discovered(res.text, exclude, n + 3):
            if self.verify_reachable(row["url"]):
                out.append(row)
            if len(out) >= n:
                break
        return out

    @staticmethod
    def verify_reachable(url: str) -> bool:
        from projects.prj_03_deal_closer import b2b_sniper as bs
        try:
            bs.assert_auditable(bs.fetch(url, timeout=10))
            return True
        except Exception:
            return False

    def dispatch_targets(self, targets_path, n: int = 5, rotate: bool = False, discover: bool = False,
                         llm: LLMClient | None = None) -> dict:
        """Make sure PM-03 has a fresh, un-audited batch in targets.csv without any human data entry.

        * existing rows with at least one un-audited target are kept (the human's choice wins);
        * empty/missing file, an all-audited file, or rotate=True loads the next `n` from the curated pool;
        * discover=True lets the tier-1 model suggest additional (unverified, reachability-checked) prospects.
        """
        n = max(1, min(int(n), 10))
        path = Path(targets_path)
        rows = prospects.read_targets(path)
        audited = self.audited_urls()
        pending = [r for r in rows if prospects.norm_url(r["url"]) not in audited]
        pool = prospects.load_pool()
        if rows and pending and not rotate:
            result = {"targets": rows, "seeded": False, "source": "existing",
                      "note": f"kept {len(rows)} existing targets ({len(pending)} not yet audited)"}
        else:
            picks = [prospects.row_from_pool(p) for p in prospects.select_next(pool, audited, n)]
            source = "pool"
            if discover and llm is not None:
                want = max(n - len(picks), min(2, n))
                extra = self.discover_prospects(llm, want, audited | {prospects.norm_url(r["url"]) for r in picks})
                if extra:
                    picks = picks[: n - len(extra)] + extra
                    source = "pool+llm" if picks[: n - len(extra)] else "llm"
            if not picks:
                if rows:
                    result = {"targets": rows, "seeded": False, "source": "existing",
                              "note": "prospect pool exhausted - kept the current targets (enable discovery to find new ones)"}
                    self.state.set_project("PRJ-03", targets_assigned=len(rows))
                    return {**result, **self.pool_status()}
                raise RuntimeError("no targets available: the prospect pool is exhausted and discovery found nothing")
            prospects.write_targets(path, picks)
            result = {"targets": picks, "seeded": True, "source": source,
                      "note": f"CEO loaded {len(picks)} new prospects ({source})"}
        self.state.set_project("PRJ-03", targets_assigned=len(result["targets"]))  # assigned to PM-03
        return {**result, **self.pool_status()}

    # -- QC gate ---------------------------------------------------------------------------
    def _artifact_ok(self, path: Path) -> str | None:
        """Independent re-verification of one artifact. Returns an error string or None."""
        if not path.exists():
            return "missing"
        if path.is_dir():
            return None if any(path.iterdir()) else "empty directory"
        if path.stat().st_size == 0:
            return "empty file"
        try:
            if path.suffix == ".json":
                json.loads(path.read_text())
            elif path.suffix == ".py":
                ast.parse(path.read_text())
        except (ValueError, SyntaxError) as exc:
            return f"invalid content: {exc}"
        return None

    def review(self, pid: str, result: dict, llm: LLMClient) -> QCReport:
        """`llm` is the project's metered client so CEO calls are billed to the project they review."""
        feedback: list[str] = []
        artifacts = result.get("artifacts", {})
        checks = result.get("checks", [])

        bad = {n: e for n, p in artifacts.items() if (e := self._artifact_ok(Path(p)))}
        for n, e in bad.items():
            feedback.append(f"Artifact '{n}' failed independent verification: {e}")
        a_ratio = (len(artifacts) - len(bad)) / len(artifacts) if artifacts else 0.0
        if not artifacts:
            feedback.append("No artifacts were produced.")

        failed = [c for c in checks if not c["passed"]]
        c_ratio = (len(checks) - len(failed)) / len(checks) if checks else 0.0
        for c in failed:
            feedback.append(f"Check failed: {c['name']} - {c.get('detail', '')}".rstrip(" -"))
        if not checks:
            feedback.append("No verification checks were reported.")

        r_ratio = 1.0 if result.get("summary") and any(Path(p).suffix in {".md", ".txt"} for p in artifacts.values()) else 0.0
        if not r_ratio:
            feedback.append("Missing human-readable summary/report artifact.")

        w = self.WEIGHTS
        score = round(w["artifacts"] * a_ratio + w["verification"] * c_ratio + w["reporting"] * r_ratio, 2)
        approved = score >= self.threshold
        if approved:
            # Optional qualitative note; never alters the score.
            note = llm.complete(  # tier 2: the flagship model is reserved for this quality gate
                f"In one sentence, comment on this deliverable summary for {pid}: {result.get('summary', '')}",
                system="You are a CEO reviewing deliverables. Be brief.", fallback="", max_tokens=200, tier=2).text
            if note:
                feedback.append(f"CEO note: {note.strip()}")
        elif not feedback:
            feedback.append("Below threshold without specific failures; tighten deliverable quality.")
        return QCReport(score, approved, feedback,
                        {"artifacts": a_ratio * 100, "verification": c_ratio * 100, "reporting": r_ratio * 100})

    # -- dashboard -------------------------------------------------------------------------
    def build_summary(self) -> Table:
        """CFO ROI telemetry banner."""
        c = compute_summary(self.state.snapshot())
        t = Table(title="CFO Summary - $%.2f seed capital" % c["seed_usd"], show_header=False, box=None, padding=(0, 2))
        for _ in range(4):
            t.add_column()
        roi = f"{c['roi_multiple']:.0f}x burn" if c["roi_multiple"] else "n/a"
        t.add_row("Remaining Seed Capital", Text(f"${c['remaining_seed_usd']:.4f}", style="bold green"),
                  "Total Burn", f"${c['burn_usd']:.5f}")
        t.add_row("Cache Savings", Text(f"${c['cache_savings_usd']:.5f} ({c['cache_hits']} hits)", style="cyan"),
                  "Est. Revenue Pipeline*", f"${c['pipeline_usd']:,.2f} ({roi})")
        t.add_row("Circuit Breaker", Text(c["breaker"], style="red bold" if c["breaker_tripped"] else "green"),
                  "Reserve Vault", c["vault"])
        t.add_row("Blocked Live Calls", str(c["blocked_calls"]), "Sellable units",
                  ", ".join(f"{k}={v}" for u in c["units"].values() for k, v in u.items()) or "-")
        return t

    def build_renderable(self):
        from rich.console import Group
        return Group(self.build_summary(),
                     Text("* assumption-based projection of sellable artifacts (config.roi_values) - NOT revenue",
                          style="dim"), self.build_table())

    def build_table(self) -> Table:
        snap = self.state.snapshot()
        t = Table(title=f"AI Agency - Executive Dashboard  (reinvested ${snap['reinvested_usd']:.4f})", show_lines=True)
        for col in ["Project", "PM Agent", "Progress %", "Burn Rate $", "CFO Health", "CEO QC", "Active Blockers"]:
            t.add_column(col, overflow="fold")
        colors = {"HEALTHY": "green", "WATCH": "yellow", "DRY-RUN": "cyan", "OVER BUDGET": "red",
                  "BREAKER": "magenta", "PENDING": "dim", "APPROVED": "green", "REJECTED": "red", "REVISING": "yellow", "RUNNING": "blue"}
        for pid, p in snap["projects"].items():
            filled = int(p["progress"] / 10)
            bar = "█" * filled + "░" * (10 - filled)
            qc = p["ceo_status"] + (f" ({p['ceo_score']:.1f}%)" if p["ceo_score"] is not None else "")
            blockers = "; ".join(p["blockers"]) if p["blockers"] else "-"
            rate = p["spent_usd"] / (p["compute_s"] / 3600) if p["compute_s"] > 0 else 0.0
            t.add_row(f"{pid} [{p['group']}]\n{p['name']}", p["pm"], f"{bar} {p['progress']}%\n{p['stage']}",
                      f"${p['spent_usd']:.5f} / ${p['quota_usd']:.4f}\n${rate:.3f}/hr | rev ${p['revenue_usd']:.2f}\ncache ${p['cache_saved_usd']:.4f} | blocked {p['blocked_calls']}",
                      Text(p["cfo_status"], style=colors.get(p["cfo_status"], "white")),
                      Text(qc, style=colors.get(p["ceo_status"], "white")), blockers)
        return t

    def render_dashboard(self, console: Console | None = None) -> None:
        console = console or Console()
        if not console.is_terminal and console.width < 140:
            console = Console(width=140)  # piped output: avoid a collapsed table
        console.print(self.build_renderable())

    def live(self, console: Console | None = None):
        from rich.live import Live
        return Live(self.build_renderable(), console=console, refresh_per_second=4, get_renderable=self.build_renderable)
