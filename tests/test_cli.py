"""End-to-end CLI tests (real subprocess, real pipelines, isolated state/output dirs)."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def env(tmp_path):
    e = {**os.environ, "AGENCY_STATE_PATH": str(tmp_path / "state.json"), "AGENCY_OUTPUT_DIR": str(tmp_path / "out"),
         "LLM_PROVIDER": "offline", "API_KEY": "", "COLUMNS": "200"}
    return e, tmp_path


def cli(env, *args):
    return subprocess.run([sys.executable, "main.py", *args], cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)


def test_no_args_prints_help(env):
    r = cli(env[0])
    assert r.returncode == 2 and "--run-all" in r.stdout


def test_dashboard_renders_columns(env):
    r = cli(env[0], "--dashboard")
    assert r.returncode == 0
    for col in ("Project", "PM Agent", "Progress", "Burn Rate", "CFO Health", "CEO QC", "Active Blockers"):
        assert col in r.stdout
    assert r.stdout.count("PRJ-0") >= 5


def test_single_project_run_produces_artifacts(env):
    e, tmp = env
    r = cli(e, "--project", "PRJ-03")
    assert r.returncode == 0, r.stdout + r.stderr
    out = tmp / "out" / "PRJ-03"
    assert (out / "outreach.txt").read_text().split().__len__() < 110
    state = json.loads((tmp / "state.json").read_text())
    assert state["projects"]["PRJ-03"]["ceo_status"] == "APPROVED"
    assert state["projects"]["PRJ-01"]["ceo_status"] == "PENDING"


def test_unknown_project_exits_nonzero(env):
    assert cli(env[0], "--project", "PRJ-77").returncode == 2


def test_run_all_then_revenue_unlocks_group_b(env):
    e, tmp = env
    r = cli(e, "--run-all")
    assert r.returncode == 0, r.stdout + r.stderr
    s = json.loads((tmp / "state.json").read_text())
    assert all(p["ceo_status"] == "APPROVED" and p["progress"] == 100 for p in s["projects"].values())
    assert s["projects"]["PRJ-04"]["mode"] == "dry-run" and s["projects"]["PRJ-05"]["cfo_status"] == "DRY-RUN"
    for pid in ("PRJ-01", "PRJ-02", "PRJ-03", "PRJ-04", "PRJ-05"):
        assert any((tmp / "out" / pid).iterdir())
    assert cli(e, "--log-revenue", "PRJ-01", "--amount", "200").returncode == 0
    s = json.loads((tmp / "state.json").read_text())
    assert s["reinvested_usd"] == pytest.approx(0.6 * (200 - s["projects"]["PRJ-01"]["spent_usd"] - sum(
        p["spent_usd"] for p in s["projects"].values() if p["group"] == "A" and p["id"] != "PRJ-01")), rel=1e-3)
    assert cli(e, "--run-all", "--sequential").returncode == 0
    s = json.loads((tmp / "state.json").read_text())
    assert s["projects"]["PRJ-04"]["mode"] == "reinvested"


def test_log_revenue_requires_amount(env):
    assert cli(env[0], "--log-revenue", "PRJ-01").returncode == 2
