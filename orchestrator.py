"""Master Orchestrator: runs sprint cycles with the Triple-Gate loop PM pre-check -> CFO audit -> CEO QC."""
from __future__ import annotations

import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

from agents.ceo_agent import CEOAgent
from agents.cfo_agent import CFOAgent
from agents.growth_agent import GrowthAgent
from agents.pm_agents import build_pms
from config import ROOT, Settings
from llm import LLMCache, LLMClient
from state import PROJECT_META, AgencyState

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class Orchestrator:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or Settings.load()
        self.state = AgencyState(self.s.state_path, self.s.budget_usd)
        self.cfo = CFOAgent(self.state, self.s.compute_rate_per_hour)
        self.ceo = CEOAgent(self.state, self.s.qc_threshold)
        self.cache = LLMCache(self.s.cache_path)  # shared by all PMs: identical prompts cost $0.00
        self.growth = GrowthAgent(self.state, self.s, cache=self.cache, slot=self.cfo.free_allowed)  # PM-06
        self.cfo.policy_hook = self.growth.assess  # re-evaluated before every routing decision
        self.pms = build_pms(self.s.output_dir,
                             lambda pid: LLMClient(self.s, lambda r, pid=pid: self.cfo.record_usage(pid, r),
                                                   budget=self.cfo.gate(pid), cache=self.cache))

    # -- one project through the triple gate ----------------------------------------------
    def run_project(self, pid: str) -> dict:
        pm = self.pms[pid]
        st, cfo = self.state, self.cfo
        self.growth.assess()
        feedback: list[str] = []
        st.set_project(pid, stage="starting", progress=0, cycle=0, blockers=[], feedback=[],
                       ceo_status="RUNNING", cfo_status="PENDING", ceo_score=None)

        pre = cfo.preflight(pid)
        if not pre.approved:
            st.set_project(pid, stage="blocked", cfo_status=pre.status, ceo_status="REJECTED", blockers=pre.reasons,
                           units={})
            return st.project(pid)

        mode = cfo.run_mode(pid)
        dry = mode == "dry-run"
        st.set_project(pid, mode=mode)
        final_report = None
        for cycle in range(1, self.s.max_cycles + 1):
            st.set_project(pid, cycle=cycle, stage=f"PM building ({mode})", progress=10, ceo_status="RUNNING")
            result, secs = pm.execute(dry, feedback)
            cfo.record_compute(pid, secs)

            # Gate 1: PM pre-check
            st.set_project(pid, stage="PM pre-check", progress=45)
            ok, issues = pm.precheck(result)
            if not ok:
                feedback = issues
                st.set_project(pid, stage="PM pre-check failed", progress=45, blockers=issues, feedback=issues,
                               ceo_status="REVISING")
                self._log(pid, cycle, "pm_precheck", False, issues)
                continue

            # Gate 2: CFO financial audit
            st.set_project(pid, stage="CFO audit", progress=70, blockers=[])
            audit = cfo.audit(pid)
            if not audit.approved:
                st.set_project(pid, stage="CFO rejected", progress=70, blockers=audit.reasons,
                               ceo_status="REJECTED", cfo_status=audit.status)
                self._log(pid, cycle, "cfo_audit", False, audit.reasons)
                return st.project(pid)

            # Gate 3: CEO quality gate
            st.set_project(pid, stage="CEO QC", progress=90)
            final_report = self.ceo.review(pid, result, pm.llm)
            self._log(pid, cycle, "ceo_qc", final_report.approved, final_report.feedback, final_report.score)
            if final_report.approved:
                st.set_project(pid, stage="delivered", progress=100, ceo_status="APPROVED",
                               ceo_score=final_report.score, blockers=[], feedback=final_report.feedback,
                               artifacts=result.get("artifacts", {}), last_run=result.get("summary", ""),
                               units=result.get("units", {}))
                return st.project(pid)
            feedback = final_report.feedback
            st.set_project(pid, stage="CEO rejected - revising", progress=60, ceo_status="REVISING",
                           ceo_score=final_report.score, feedback=feedback, blockers=feedback[:3])

        st.set_project(pid, stage="rejected after max cycles", ceo_status="REJECTED", units={},
                       ceo_score=final_report.score if final_report else None,
                       blockers=feedback[:3] or ["max revision cycles reached"])
        return st.project(pid)

    def _log(self, pid, cycle, gate, passed, notes, score=None):
        self.state.update(lambda d: d["projects"][pid]["history"].append(
            {"cycle": cycle, "gate": gate, "passed": passed, "score": score, "notes": notes[:5]}))

    # -- sprint ----------------------------------------------------------------------------
    def run_sprint(self, pids: list[str] | None = None, parallel: bool = True) -> dict[str, dict]:
        pids = pids or self.ceo.dispatch_plan()
        for pid in pids:
            if pid not in PROJECT_META:
                raise ValueError(f"unknown project {pid}")
        if not parallel or len(pids) == 1:
            return {pid: self.run_project(pid) for pid in pids}
        with ThreadPoolExecutor(max_workers=len(pids), thread_name_prefix="pm") as ex:
            futs = {pid: ex.submit(self.run_project, pid) for pid in pids}
            return {pid: f.result() for pid, f in futs.items()}

    # -- AI CEO auto-pilot ---------------------------------------------------------------
    def run_autopilot(self, targets_path=None, live: bool = False, discover: bool = False, rotate: bool = False,
                      n_targets: int = 5, on_step=None) -> dict:
        """The whole campaign in one call, run by the AI CEO with PM-03 / PM-01 / PM-02 (no manual data entry):

          0. PM-06 growth check   - cost report + free-lane routing policy for this run
          1. CEO target dispatch  - make sure targets.csv holds fresh, un-audited prospects (pool, optionally LLM-discovered)
          2. PRJ-03 batch audit   - real HTTP diagnostics + outreach drafts (live LLM or deterministic templates)
          3. Group A sprint       - PRJ-01 audit package and PRJ-02 extension kit through the CFO and CEO gates
          4. Sell sheet           - rebuild output/READY_TO_SELL_NOW.md

        Each step is isolated: a failure is recorded and the later steps still run when they can. One CFO run cap (set by
        the caller via cfo.set_run_cap) covers the whole chain.
        """
        from tools.build_ready_to_sell import build

        targets_path = targets_path or self.s.targets_path
        steps: list[dict] = []
        start = len(self.state.snapshot()["ledger"])

        def notify() -> None:
            if on_step:
                on_step(steps)

        def run_step(key: str, label: str, fn) -> dict:
            entry = {"key": key, "label": label, "status": "running", "detail": ""}
            steps.append(entry)
            notify()
            try:
                entry["detail"] = fn()
                entry["status"] = "done"
            except Exception as exc:  # recorded, never raised: later steps may still succeed
                entry["status"], entry["detail"] = "failed", f"{type(exc).__name__}: {exc}"
            notify()
            return entry

        def growth() -> str:
            pol = self.growth.assess()
            rep = self.growth.cost_report()
            lane = ", ".join(pol["free_lane"]) or "none (templates only)"
            return (f"policy {pol['mode'].upper()} - {pol['reason']}; ${rep['remaining_usd']:.2f} left "
                    f"({rep['remaining_pct']:.0f}%); free lane: {lane}")

        def dispatch() -> str:
            llm = self.pms["PRJ-03"].llm if (discover and live) else None
            d = self.ceo.dispatch_targets(targets_path, n=n_targets, rotate=rotate, discover=discover and live, llm=llm)
            names = ", ".join(r["company"] or r["url"] for r in d["targets"][:5])
            return f"{len(d['targets'])} targets for PM-03 ({d['source']}): {names}"

        def audit() -> str:
            saved = os.environ.get("TARGETS_FILE")
            os.environ["TARGETS_FILE"] = str(targets_path)
            try:
                final = self.run_project("PRJ-03")
            finally:
                if saved is None:
                    os.environ.pop("TARGETS_FILE", None)
                else:
                    os.environ["TARGETS_FILE"] = saved
            batch_file = self.s.output_dir / "PRJ-03" / "outreach_batch.json"
            batch = json.loads(batch_file.read_text()) if batch_file.exists() else []
            self.ceo.mark_audited(batch)
            ready = sum(1 for r in batch if r.get("ready"))
            if final["ceo_status"] != "APPROVED":
                raise RuntimeError(f"PRJ-03 {final['ceo_status']}: {'; '.join(final['blockers'][:2])}")
            return f"PRJ-03 APPROVED ({final['ceo_score']:.0f}%): {ready}/{len(batch)} outreach messages ready"

        def group_a() -> str:
            res = self.run_sprint(["PRJ-01", "PRJ-02"])
            bad = [pid for pid, p in res.items() if p["ceo_status"] != "APPROVED"]
            line = ", ".join(f"{pid} {p['ceo_status']} ({(p['ceo_score'] or 0):.0f}%)" for pid, p in res.items())
            if bad:
                raise RuntimeError(line)
            return line

        def sheet() -> str:
            r = build(self.s)
            return f"{r['outreach_ready']} messages assembled -> {r['path']}"

        run_step("growth", "PM-06: cost check + free-lane routing", growth)
        run_step("dispatch", "CEO: dispatch targets to PM-03", dispatch)
        run_step("audit", "PM-03: live batch audit + outreach drafts" if live else "PM-03: batch audit + outreach drafts (offline templates)", audit)
        run_step("group_a", "PM-01 / PM-02: legacy audit + extension kit", group_a)
        run_step("sheet", "CEO: assemble master sell sheet", sheet)

        ledger = self.state.snapshot()["ledger"][start:]
        api = [e for e in ledger if e["kind"] == "api" and e.get("provider") != "offline"]
        failed = [s_["key"] for s_ in steps if s_["status"] == "failed"]
        return {"status": "complete" if not failed else "partial", "failed_steps": failed, "steps": steps,
                "llm": {"live_calls": len(api), "cache_hits": sum(1 for e in ledger if e["kind"] == "cache_hit"),
                        "blocked": sum(1 for e in ledger if e["kind"] == "blocked"), "errors": sum(1 for e in ledger if e.get("error")),
                        "spent_usd": round(sum(e.get("usd", 0.0) for e in api), 6)},
                "sell_sheet": str(self.s.output_dir / "READY_TO_SELL_NOW.md")}
