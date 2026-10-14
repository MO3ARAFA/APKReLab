"""Master Orchestrator: runs sprint cycles with the Triple-Gate loop PM pre-check -> CFO audit -> CEO QC."""
from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor

from agents.ceo_agent import CEOAgent
from agents.cfo_agent import CFOAgent
from agents.pm_agents import build_pms
from config import ROOT, Settings
from llm import LLMClient
from state import PROJECT_META, AgencyState

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class Orchestrator:
    def __init__(self, settings: Settings | None = None):
        self.s = settings or Settings.load()
        self.state = AgencyState(self.s.state_path, self.s.budget_usd)
        self.cfo = CFOAgent(self.state, self.s.compute_rate_per_hour)
        self.ceo = CEOAgent(self.state, self.s.qc_threshold)
        self.pms = build_pms(self.s.output_dir,
                             lambda pid: LLMClient(self.s, lambda r, pid=pid: self.cfo.record_usage(pid, r)))

    # -- one project through the triple gate ----------------------------------------------
    def run_project(self, pid: str) -> dict:
        pm = self.pms[pid]
        st, cfo = self.state, self.cfo
        feedback: list[str] = []
        st.set_project(pid, stage="starting", progress=0, cycle=0, blockers=[], feedback=[],
                       ceo_status="RUNNING", cfo_status="PENDING", ceo_score=None)

        pre = cfo.preflight(pid)
        if not pre.approved:
            st.set_project(pid, stage="blocked", cfo_status=pre.status, ceo_status="REJECTED", blockers=pre.reasons)
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
                               artifacts=result.get("artifacts", {}), last_run=result.get("summary", ""))
                return st.project(pid)
            feedback = final_report.feedback
            st.set_project(pid, stage="CEO rejected - revising", progress=60, ceo_status="REVISING",
                           ceo_score=final_report.score, feedback=feedback, blockers=feedback[:3])

        st.set_project(pid, stage="rejected after max cycles", ceo_status="REJECTED",
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
