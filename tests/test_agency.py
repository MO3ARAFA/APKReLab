"""Framework tests: state, CFO model, CEO gate, orchestrator revision loop, CLI."""
import json
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from agents.ceo_agent import CEOAgent
from agents.cfo_agent import CFOAgent
from config import Settings
from llm import LLMClient, LLMResult
from orchestrator import Orchestrator
from state import AgencyState


@pytest.fixture
def settings(tmp_path):
    return replace(Settings.load(), provider="offline", budget_usd=100.0, state_path=tmp_path / "state.json",
                   output_dir=tmp_path / "out", max_cycles=3)


def test_state_persists_atomically(tmp_path):
    p = tmp_path / "s.json"
    st = AgencyState(p, 100)
    st.set_project("PRJ-01", stage="x", progress=42)
    assert AgencyState(p, 100).project("PRJ-01")["progress"] == 42
    assert json.loads(p.read_text())["version"] == 2
    assert not list(tmp_path.glob(".state-*"))  # no leftover temp files


def test_corrupt_state_recovers(tmp_path):
    p = tmp_path / "s.json"
    p.write_text("{not json")
    assert AgencyState(p, 100).project("PRJ-02")["quota_usd"] > 0


def test_state_is_thread_safe(tmp_path):
    st = AgencyState(tmp_path / "s.json", 100)
    cfo = CFOAgent(st, 0.1)
    res = LLMResult("x", "openai", "m", 10, 5, 0.001)
    ts = [threading.Thread(target=lambda: [cfo.record_usage("PRJ-01", res) for _ in range(25)]) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    p = st.project("PRJ-01")
    assert p["api_calls"] == 200 and p["spent_usd"] == pytest.approx(0.2)


def test_cross_subsidy_split(tmp_path):
    st = AgencyState(tmp_path / "s.json", 100)
    q = {pid: p["quota_usd"] for pid, p in st.snapshot()["projects"].items()}
    assert sum(q[p] for p in ("PRJ-01", "PRJ-02", "PRJ-03")) == pytest.approx(80)  # 80% Group A
    assert sum(q[p] for p in ("PRJ-04", "PRJ-05")) == pytest.approx(5)            # 5% Group B (+15% locked vault)


def test_group_b_gated_until_revenue_and_reinvest_respects_hard_cap(tmp_path):
    st = AgencyState(tmp_path / "s.json", 100)
    cfo = CFOAgent(st, 0.1)
    assert cfo.run_mode("PRJ-04") == "dry-run" and cfo.run_mode("PRJ-01") == "production"
    before = st.project("PRJ-04")["quota_usd"]
    cfo.log_revenue("PRJ-01", 1000)
    assert cfo.run_mode("PRJ-04") == "reinvested"
    # default matrix commits the whole seed (vault is released into PRJ-01), so there is no headroom:
    # revenue must NOT raise quotas or the cap
    assert st.snapshot()["reinvested_usd"] == 0 and st.project("PRJ-04")["quota_usd"] == pytest.approx(before)
    assert cfo.summary()["ceiling_usd"] == pytest.approx(100)
    # deliberately re-seeding creates headroom; then 60% of Group A profit flows to Group B, idempotently
    st.update(lambda d: d.__setitem__("seed_usd", 1000.0))
    cfo.rebalance()
    cfo.rebalance()
    assert st.snapshot()["reinvested_usd"] == pytest.approx(600)  # 60% of $1000 profit, within headroom (1000 - 100)
    assert st.project("PRJ-04")["quota_usd"] == pytest.approx(before + 300)
    assert cfo.summary()["ceiling_usd"] == pytest.approx(1000)


def test_revenue_validation(tmp_path):
    cfo = CFOAgent(AgencyState(tmp_path / "s.json", 100), 0.1)
    with pytest.raises(ValueError):
        cfo.log_revenue("PRJ-99", 5)
    with pytest.raises(ValueError):
        cfo.log_revenue("PRJ-01", -5)


def test_cfo_blocks_over_budget(tmp_path):
    st = AgencyState(tmp_path / "s.json", 1.0)
    cfo = CFOAgent(st, 0.1)
    cfo.record_usage("PRJ-01", LLMResult("", "openai", "m", 0, 0, 5.0))
    assert not cfo.preflight("PRJ-01").approved
    assert cfo.audit("PRJ-01").status == "OVER BUDGET"


def test_ceo_rejects_below_95(tmp_path):
    st = AgencyState(tmp_path / "s.json", 100)
    ceo = CEOAgent(st, 95.0)
    llm = LLMClient(Settings(provider="offline"))
    f = tmp_path / "report.md"
    f.write_text("# ok")
    good = {"artifacts": {"report": str(f)}, "checks": [{"name": "a", "passed": True}], "summary": "s"}
    assert ceo.review("PRJ-01", good, llm).approved
    bad = {**good, "checks": [{"name": "a", "passed": True}, {"name": "tests", "passed": False, "detail": "2 failed"}]}
    r = ceo.review("PRJ-01", bad, llm)
    assert not r.approved and r.score < 95 and any("tests" in x for x in r.feedback)
    empty = {"artifacts": {"x": str(tmp_path / "missing.json")}, "checks": [], "summary": ""}
    r = ceo.review("PRJ-01", empty, llm)
    assert not r.approved and any("missing" in x for x in r.feedback)


def test_ceo_independently_verifies_artifacts(tmp_path):
    ceo = CEOAgent(AgencyState(tmp_path / "s.json", 100), 95.0)
    bad_json = tmp_path / "a.json"
    bad_json.write_text("{nope")
    bad_py = tmp_path / "b.py"
    bad_py.write_text("def (:")
    assert "invalid" in ceo._artifact_ok(bad_json) and "invalid" in ceo._artifact_ok(bad_py)


class FakePM:
    """Pipeline that fails QC on the first N cycles, then succeeds."""
    def __init__(self, tmp_path, fail_cycles):
        self.calls, self.fail, self.tmp, self.llm = 0, fail_cycles, tmp_path, LLMClient(Settings(provider="offline"))
        self.feedback_seen = []

    def execute(self, dry_run, feedback):
        self.calls += 1
        self.feedback_seen.append(list(feedback))
        f = self.tmp / "r.md"
        f.write_text("# r")
        ok = self.calls > self.fail
        return ({"artifacts": {"r": str(f)}, "checks": [{"name": "quality", "passed": ok, "detail": "bad"}], "summary": "s"}, 0.01)

    def precheck(self, result):
        return True, []


def test_revision_loop_returns_feedback_to_pm(settings, tmp_path):
    o = Orchestrator(settings)
    pm = FakePM(tmp_path, fail_cycles=1)
    # force the CEO gate (not the PM pre-check) to be the one that rejects
    o.pms["PRJ-01"] = pm
    final = o.run_project("PRJ-01")
    assert final["ceo_status"] == "APPROVED" and final["cycle"] == 2 and final["ceo_score"] >= 95
    assert pm.feedback_seen[0] == [] and any("quality" in x for x in pm.feedback_seen[1])
    gates = [(h["cycle"], h["gate"], h["passed"]) for h in final["history"]]
    assert (1, "ceo_qc", False) in gates and (2, "ceo_qc", True) in gates


def test_rejected_after_max_cycles(settings, tmp_path):
    o = Orchestrator(settings)
    o.pms["PRJ-01"] = FakePM(tmp_path, fail_cycles=99)
    final = o.run_project("PRJ-01")
    assert final["ceo_status"] == "REJECTED" and final["cycle"] == 3 and final["blockers"]


def test_pm_precheck_failure_loops_before_cfo(settings, tmp_path):
    o = Orchestrator(settings)

    class PM(FakePM):
        def precheck(self, result):
            return (self.calls > 1), ["self-check failed"]
    pm = PM(tmp_path, 0)
    o.pms["PRJ-02"] = pm
    final = o.run_project("PRJ-02")
    assert final["ceo_status"] == "APPROVED" and pm.calls == 2
    assert any(h["gate"] == "pm_precheck" and not h["passed"] for h in final["history"])


def test_crashing_pipeline_becomes_blocker_not_crash(settings, monkeypatch):
    o = Orchestrator(settings)
    pm = o.pms["PRJ-03"]
    monkeypatch.setattr(pm, "_module", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    final = o.run_project("PRJ-03")
    assert final["ceo_status"] == "REJECTED" and any("boom" in b for b in final["blockers"])


def test_over_budget_project_blocked_before_running(settings, tmp_path):
    o = Orchestrator(settings)
    o.cfo.record_usage("PRJ-01", LLMResult("", "openai", "m", 0, 0, 1e6))
    pm = FakePM(tmp_path, 0)
    o.pms["PRJ-01"] = pm
    final = o.run_project("PRJ-01")
    assert pm.calls == 0 and final["cfo_status"] == "OVER BUDGET" and final["ceo_status"] == "REJECTED"


def test_unknown_project_rejected(settings):
    with pytest.raises(ValueError):
        Orchestrator(settings).run_sprint(["PRJ-42"])


def test_dashboard_has_required_columns(settings):
    from rich.console import Console
    o = Orchestrator(settings)
    c = Console(width=180, record=True)
    o.ceo.render_dashboard(c)
    text = c.export_text()
    for col in ("Project", "PM Agent", "Progress", "Burn Rate", "CFO Health", "CEO QC", "Active Blockers"):
        assert col in text
    for pid in ("PRJ-01", "PRJ-05"):
        assert pid in text


def test_llm_offline_fallback_and_recording():
    seen = []
    llm = LLMClient(Settings(provider="offline"), seen.append)
    r = llm.complete("hello", fallback="fallback text")
    assert r.text == "fallback text" and not r.live and r.cost_usd == 0 and len(seen) == 1


def test_llm_provider_failure_falls_back(monkeypatch, tmp_path):
    s = replace(Settings.load(), provider="openai", api_key="k", fallback_ollama=False, cache_path=tmp_path / "c.json")
    llm = LLMClient(s)
    from llm import LLMError
    monkeypatch.setattr(llm, "_openai", lambda *a: (_ for _ in ()).throw(LLMError("down")))
    assert llm.complete("x", fallback="FB").text == "FB"


def test_llm_cost_accounting(monkeypatch, tmp_path):
    s = replace(Settings.load(), provider="anthropic", api_key="k", fallback_ollama=False, cache_path=tmp_path / "c.json")
    llm = LLMClient(s)
    monkeypatch.setattr(llm, "_anthropic", lambda m, *a: LLMResult("t", "anthropic", m, 1_000_000, 1_000_000, live=True))
    assert llm.complete("x").cost_usd == pytest.approx(0.60)  # claude-haiku-5-5: $0.10 in + $0.50 out per 1M


def test_settings_without_key_go_offline(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    for v in ("API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(v, raising=False)
    assert Settings.load().provider == "offline"
