"""Thread-safe, atomically persisted agency state (state/agency_state.json)."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable

PROJECT_META = {
    "PRJ-01": {"dir": "prj_01_legacy_migrator", "name": "Legacy-Code Modernization Lab", "group": "A"},
    "PRJ-02": {"dir": "prj_02_gap_cloner", "name": "Competitor Gap Cloner & CRM Clipper", "group": "A"},
    "PRJ-03": {"dir": "prj_03_deal_closer", "name": "B2B Digital-Twin Deal Closer", "group": "A"},
    "PRJ-04": {"dir": "prj_04_zeroday_hunter", "name": "Self-Healing Vulnerability Scanner", "group": "B"},
    "PRJ-05": {"dir": "prj_05_synthetic_foundry", "name": "Synthetic Data Foundry", "group": "B"},
}


def now() -> float:
    return time.time()


def blank_project(pid: str, quota: float) -> dict[str, Any]:
    return {
        "id": pid, "name": PROJECT_META[pid]["name"], "group": PROJECT_META[pid]["group"],
        "pm": f"PM-{pid[-2:]}", "stage": "idle", "progress": 0, "cycle": 0, "mode": "pending",
        "quota_usd": round(quota, 6), "spent_usd": 0.0, "api_calls": 0, "tokens_in": 0, "tokens_out": 0,
        "compute_s": 0.0, "revenue_usd": 0.0, "cfo_status": "PENDING", "ceo_status": "PENDING",
        "ceo_score": None, "blockers": [], "feedback": [], "artifacts": {}, "history": [],
        "last_run": None,
    }


class AgencyState:
    def __init__(self, path: Path, budget: float):
        self.path = Path(path)
        self.budget = budget
        self._lock = threading.RLock()
        self.data: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        with self._lock:
            if self.path.exists():
                try:
                    self.data = json.loads(self.path.read_text())
                    if self.data.get("version") == 1 and self.data.get("projects"):
                        return
                except (json.JSONDecodeError, OSError):
                    pass  # corrupt state -> rebuild below (original is overwritten on next save)
            self.data = self._fresh()
            self.save()

    def _fresh(self) -> dict[str, Any]:
        a = self.budget * 0.85 / 3
        b = self.budget * 0.15 / 2
        return {
            "version": 1, "created": now(), "budget_usd": self.budget,
            "reinvested_usd": 0.0, "ledger": [], "revenue": [],
            "projects": {pid: blank_project(pid, a if m["group"] == "A" else b)
                         for pid, m in PROJECT_META.items()},
        }

    def save(self) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".state-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as fh:
                    json.dump(self.data, fh, indent=2, default=str)
                os.replace(tmp, self.path)  # atomic
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise

    def update(self, fn: Callable[[dict[str, Any]], Any]) -> Any:
        """Run fn(data) under the lock, then persist."""
        with self._lock:
            out = fn(self.data)
            self.save()
            return out

    def project(self, pid: str) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self.data["projects"][pid])

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return deepcopy(self.data)

    def set_project(self, pid: str, **fields: Any) -> None:
        self.update(lambda d: d["projects"][pid].update(fields))
