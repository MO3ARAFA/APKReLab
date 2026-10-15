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


# Share of the seed capital per project (sums to 0.85) + the locked emergency reserve (0.15).
# At $10: PRJ-03 $3.50, PRJ-01 $2.50, PRJ-02 $2.00 (Group A $8.00); PRJ-04/05 $0.25 each; reserve $1.50.
ALLOCATION = {"PRJ-03": 0.35, "PRJ-01": 0.25, "PRJ-02": 0.20, "PRJ-04": 0.025, "PRJ-05": 0.025}
RESERVE_SHARE = 0.15
STATE_VERSION = 2


def now() -> float:
    return time.time()


def blank_project(pid: str, quota: float) -> dict[str, Any]:
    return {
        "id": pid, "name": PROJECT_META[pid]["name"], "group": PROJECT_META[pid]["group"],
        "pm": f"PM-{pid[-2:]}", "stage": "idle", "progress": 0, "cycle": 0, "mode": "pending",
        "quota_usd": round(quota, 6), "spent_usd": 0.0, "api_calls": 0, "tokens_in": 0, "tokens_out": 0,
        "compute_s": 0.0, "revenue_usd": 0.0, "blocked_calls": 0, "last_block": "",
        "cache_hits": 0, "cache_saved_usd": 0.0, "units": {}, "cfo_status": "PENDING", "ceo_status": "PENDING",
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
                    if self.data.get("version") == STATE_VERSION and self.data.get("projects"):
                        return
                except (json.JSONDecodeError, OSError):
                    pass  # corrupt state -> rebuild below (original is overwritten on next save)
            self.data = self._fresh()
            self.save()

    def _fresh(self) -> dict[str, Any]:
        return {
            "version": STATE_VERSION, "created": now(), "budget_usd": self.budget, "seed_usd": self.budget,
            "reinvested_usd": 0.0, "ledger": [], "revenue": [],
            "cache_savings_usd": 0.0, "cache_hits": 0, "blocked_calls": 0,
            "vault": {"amount": round(self.budget * RESERVE_SHARE, 6), "locked": True, "released_to": None},
            "projects": {pid: blank_project(pid, self.budget * ALLOCATION[pid]) for pid in PROJECT_META},
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
