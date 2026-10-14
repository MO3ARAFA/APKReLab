"""Five sub-Project Managers. Each PM runs one project inside projects/prj_0X/ and pre-checks its own work."""
from __future__ import annotations

import importlib
import time
import traceback
from pathlib import Path

from llm import LLMClient
from state import PROJECT_META


class ProjectManager:
    def __init__(self, pid: str, out_root: Path, llm: LLMClient):
        self.pid = pid
        self.meta = PROJECT_META[pid]
        self.name = f"PM-{pid[-2:]}"
        self.out_dir = Path(out_root) / pid
        self.llm = llm

    def _module(self):
        return importlib.import_module(f"projects.{self.meta['dir']}.pipeline")

    def execute(self, dry_run: bool, feedback: list[str]) -> tuple[dict, float]:
        """Run the project pipeline; returns (result, elapsed_seconds)."""
        self.out_dir.mkdir(parents=True, exist_ok=True)
        t0 = time.perf_counter()
        try:
            result = self._module().run(self.out_dir, self.llm, dry_run=dry_run, feedback=feedback)
        except Exception as exc:  # a crashing pipeline is a blocker, not an orchestrator crash
            result = {"artifacts": {}, "checks": [{"name": "pipeline executed", "passed": False,
                                                   "detail": f"{type(exc).__name__}: {exc}"}],
                      "summary": "", "metrics": {}, "traceback": traceback.format_exc()}
        return result, time.perf_counter() - t0

    def precheck(self, result: dict) -> tuple[bool, list[str]]:
        """PM pre-check gate: cheap sanity before spending CFO/CEO attention."""
        issues: list[str] = []
        arts = result.get("artifacts", {})
        if not arts:
            issues.append("no artifacts produced")
        for n, p in arts.items():
            if not Path(p).exists():
                issues.append(f"artifact '{n}' missing at {p}")
        for c in result.get("checks", []):
            if not c["passed"]:
                issues.append(f"self-check failed: {c['name']} {c.get('detail', '')}".strip())
        return (not issues), issues


def build_pms(out_root: Path, llm_factory) -> dict[str, ProjectManager]:
    """llm_factory(pid) -> LLMClient that records usage against that project."""
    return {pid: ProjectManager(pid, out_root, llm_factory(pid)) for pid in PROJECT_META}
