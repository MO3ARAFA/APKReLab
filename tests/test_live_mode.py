"""Live-mode safety: nothing spends without --live, errors are visible, caps hold, real-site claims stay honest."""
import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from config import Settings, detect_provider
from llm import LLMCache, LLMClient, LLMError, LLMResult
from orchestrator import Orchestrator
from projects.prj_03_deal_closer import b2b_sniper as bs

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def settings(tmp_path):
    return replace(Settings.load(), provider="anthropic", api_key="k", fallback_ollama=False, budget_usd=10.0,
                   model_t1="", model_t2="", compute_rate_per_hour=0.0, state_path=tmp_path / "s.json",
                   cache_path=tmp_path / "c.json", output_dir=tmp_path / "out")


# ---- credentials / provider detection ------------------------------------------------------
def test_provider_detected_from_key_prefix():
    assert detect_provider("sk-ant-api03-xyz") == "anthropic"
    assert detect_provider("sk-proj-abc") == "openai"
    assert detect_provider("AIzaSyXYZ") == "gemini"
    assert detect_provider("random") is None


def test_settings_prefix_beats_stale_provider_and_accepts_vendor_var_names(monkeypatch):
    for v in ("API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("LLM_PROVIDER", "openai")  # stale
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-test")
    s = Settings.load()
    assert s.provider == "anthropic" and s.api_key == "sk-ant-api03-test"
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    monkeypatch.setenv("GEMINI_API_KEY", "AIzaSyTest")
    assert Settings.load().provider == "gemini"
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    assert Settings.load().provider == "ollama"  # explicit local provider is respected


def test_tests_are_hermetic_from_real_env_and_files():
    assert os.environ.get("AGENCY_SKIP_DOTENV") == "1"
    assert "agency-tests-" in os.environ["AGENCY_STATE_PATH"] and "agency-tests-" in os.environ["AGENCY_CACHE_PATH"]


def test_cli_never_goes_live_without_the_flag(tmp_path):
    env = {**os.environ, "ANTHROPIC_API_KEY": "sk-ant-api03-not-a-real-key", "LLM_PROVIDER": "anthropic",
           "AGENCY_STATE_PATH": str(tmp_path / "s.json"), "AGENCY_OUTPUT_DIR": str(tmp_path / "o"),
           "AGENCY_CACHE_PATH": str(tmp_path / "c.json"), "COLUMNS": "200"}
    r = subprocess.run([sys.executable, "main.py", "--project", "PRJ-03"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0 and "offline deterministic" in r.stdout and "LIVE" not in r.stdout
    assert not (tmp_path / "c.json").exists()  # no live call ever cached anything
    state = json.loads((tmp_path / "s.json").read_text())
    assert not [e for e in state["ledger"] if e.get("provider") not in (None, "offline")]


def test_dashboard_watch_flag_replaces_old_live_meaning():
    r = subprocess.run([sys.executable, "main.py", "--help"], cwd=ROOT, capture_output=True, text=True)
    assert "--live" in r.stdout and "--watch" in r.stdout and "--max-spend" in r.stdout


# ---- per-run spend cap ---------------------------------------------------------------------
def test_max_spend_caps_this_run_only(settings):
    o = Orchestrator(settings)
    o.state.set_project("PRJ-03", spent_usd=1.0)  # earlier spend must not count against this run
    o.cfo.set_run_cap(0.0005)
    llm = o.pms["PRJ-03"].llm
    calls = []
    llm._anthropic = lambda m, s, p, t: calls.append(m) or LLMResult("ok", "anthropic", m, 100, 100, live=True)
    assert llm.complete("a", fallback="FB", max_tokens=512).live  # est ~$0.00027
    r = llm.complete("b", fallback="FB", max_tokens=5000)  # est $0.0025 > remaining run budget
    assert r.blocked and "--max-spend" in r.blocked and len(calls) == 1
    o.cfo.set_run_cap(None)
    assert llm.complete("c", fallback="FB", max_tokens=5000).live


# ---- failures are visible and billed correctly ---------------------------------------------
def test_empty_but_billed_response_books_cost_uses_fallback_and_is_not_cached(settings):
    o = Orchestrator(settings)
    llm = o.pms["PRJ-01"].llm
    llm._anthropic = lambda m, s, p, t: LLMResult("   ", "anthropic", m, 1000, 500, live=True)
    r = llm.complete("x", fallback="LOCAL")
    assert r.text == "LOCAL" and not r.live and "billed" in r.error
    assert o.state.project("PRJ-01")["spent_usd"] == pytest.approx(0.00035)  # the money was spent, so it is recorded
    assert not Path(settings.cache_path).exists()


def test_provider_error_is_surfaced_in_result_and_ledger(settings):
    o = Orchestrator(settings)
    llm = o.pms["PRJ-01"].llm

    def boom(*a):
        raise LLMError("HTTP 400 invalid request")
    llm._anthropic = boom
    r = llm.complete("x", fallback="LOCAL")
    assert r.text == "LOCAL" and "HTTP 400" in r.error and "claude-haiku-5-5" in r.error
    d = o.state.snapshot()
    assert d["llm_errors"] == 1 and any("HTTP 400" in e.get("error", "") for e in d["ledger"])


def test_min_max_tokens_floor_applies_to_estimate_and_request(settings):
    o = Orchestrator(settings)
    llm = o.pms["PRJ-03"].llm
    seen = []
    llm._anthropic = lambda m, s, p, t: seen.append(t) or LLMResult("ok", "anthropic", m, 10, 10, live=True)
    llm.complete("x", max_tokens=50)
    assert seen == [512]


def test_haiku_request_disables_thinking_and_opus_does_not(settings, monkeypatch):
    bodies = []
    import llm as llm_mod
    monkeypatch.setattr(llm_mod, "_post", lambda url, payload, headers, timeout=60.0: bodies.append(payload) or
                        {"content": [{"type": "text", "text": "ok"}], "usage": {"input_tokens": 5, "output_tokens": 2}})
    c = LLMClient(settings, cache=LLMCache(settings.cache_path))
    c.complete("a", tier=1)
    c.complete("b", tier=2)
    assert bodies[0]["model"] == "claude-haiku-5-5" and bodies[0]["thinking"] == {"type": "disabled"}
    assert bodies[1]["model"] == "claude-opus-5-5" and "thinking" not in bodies[1]
    assert all(b["output_config"] == {"effort": "low"} for b in bodies)


# ---- honest auditing of real sites ---------------------------------------------------------
def _fr(html, status=200):
    return bs.FetchResult("https://prospect.example/", status, 0.3, 0.5, len(html.encode()), len(html.encode()), True, True, {}, html)


def test_error_challenge_and_shell_pages_are_not_audited():
    with pytest.raises(bs.NotAuditable):
        bs.assert_auditable(_fr("<html>" + "x" * 5000, status=403))
    with pytest.raises(bs.NotAuditable):
        bs.assert_auditable(_fr("<html><title>Just a moment...</title>" + "x" * 5000))
    with pytest.raises(bs.NotAuditable):
        bs.assert_auditable(_fr("<html><body><div id=root></div></body></html>"))
    bs.assert_auditable(_fr("<html>" + "x" * 5000 + "</html>"))


def test_remote_outreach_only_cites_objective_checkable_findings(monkeypatch):
    html = (Path(bs.__file__).parent / "fixtures" / "bad_site.html").read_text() + "<!--" + "x" * 2000 + "-->"
    monkeypatch.setattr(bs, "fetch", lambda url, allow_private=False, timeout=15.0: _fr(html))
    monkeypatch.setattr(bs, "check_url_safe", lambda *a, **k: None)

    class LLM:
        def complete(self, *a, **k):
            return LLMResult("", "offline", "m", live=False)  # forces the deterministic template
    r = bs.run_sniper("https://prospect.example/", "Dana", "Prospect", llm=LLM())
    cited = {f["keyword"] for f in r["outreach_findings"]}
    assert cited and cited <= bs.CITABLE_REMOTE
    assert not cited & {"social proof", "call to action", "contact", "title", "server", "load"}
    assert "social proof" in {f["keyword"] for f in r["findings"]}  # still in diagnostics, just not cited


def test_proof_markup_hint_prevents_false_no_social_proof():
    page = bs.parse_page('<html><body><div class="customer-logos"><img src=a.svg alt=a></div><p>hello</p></body></html>')
    assert page["social_proof"] is True


def test_timing_text_is_bucketed_so_cache_keys_are_stable():
    assert bs._secs(0.903) == bs._secs(0.921) == bs._secs(1.1) == "1.0s"
    assert bs._secs(0.6) == "0.5s"
