"""PM-06 (AI Growth & Cost-Hacking Agent): routing policy, free lane, accounting, web, CLI. No real network, no spend."""
import io
import json
import os
import subprocess
import sys
import time
import urllib.error
from dataclasses import replace
from pathlib import Path

import pytest

import llm as llm_mod
from agents.growth_agent import GrowthAgent
from agents.policy import classify_paid_failure, free_limits, paid_allowed
from config import Settings
from llm import LLMClient, LLMError
from orchestrator import Orchestrator
from state import AgencyState
from tests.test_web_dashboard import Web, mk_settings

ROOT = Path(__file__).resolve().parents[1]
FREE_KEY = "gsk" + "_TESTFREEKEY0123456789abcdefABCDEF"  # assembled at runtime: a fake, kept out of secret scanners


@pytest.fixture
def s(tmp_path, monkeypatch):
    for v in ("GROQ_API_KEY", "OPENROUTER_API_KEY", "GEMINI_FREE_API_KEY", "MISTRAL_API_KEY", "FREE_PROVIDERS"):
        monkeypatch.delenv(v, raising=False)
    return replace(Settings.load(), provider="anthropic", api_key="sk-ant-api03-test-key-0000", fallback_ollama=False,
                   budget_usd=10.0, model_t1="", model_t2="", compute_rate_per_hour=0.0, state_path=tmp_path / "s.json",
                   cache_path=tmp_path / "c.json", output_dir=tmp_path / "out", free_lane=True)


class FakeNet:
    """Replaces llm._post: records (url, payload, headers) and answers per-host."""

    def __init__(self, monkeypatch):
        self.calls = []
        self.fail = {}  # host substring -> LLMError
        monkeypatch.setattr(llm_mod, "_post", self)

    def __call__(self, url, payload, headers, timeout=60.0):
        self.calls.append((url, payload, headers))
        for host, exc in self.fail.items():
            if host in url:
                raise exc
        if "anthropic" in url:
            return {"content": [{"type": "text", "text": "paid answer"}], "usage": {"input_tokens": 100, "output_tokens": 50}}
        return {"choices": [{"message": {"content": "free answer"}}], "usage": {"prompt_tokens": 120, "completion_tokens": 40}}

    def hosts(self):
        return [u.split("/")[2] for u, _, _ in self.calls]


def set_policy(orch, **kw):
    orch.cfo.policy_hook = None  # pin the policy: the live hook would re-derive it from the (healthy) budget
    orch.state.update(lambda d: d.__setitem__("policy", {"mode": "normal", "heavy": [], **kw}))


# ------------------------------------------------------------------ pure policy
def test_paid_allowed_rules():
    assert paid_allowed(None, "PRJ-01", 2) == (True, "")
    assert paid_allowed({"mode": "free", "reason": "x"}, "PRJ-01", 1)[0] is False
    c = {"mode": "conserve", "heavy": ["PRJ-03"]}
    assert paid_allowed(c, "PRJ-03", 1)[0] is False and paid_allowed(c, "PRJ-01", 2)[0] is False
    assert paid_allowed(c, "PRJ-01", 1) == (True, "")


def test_classify_paid_failure():
    assert classify_paid_failure(401, "invalid x-api-key") == "auth"
    assert classify_paid_failure(400, "Your credit balance is too low to access the API") == "exhausted"
    assert classify_paid_failure(402, "") == "exhausted"
    assert classify_paid_failure(429, "rate limited") == ""  # transient, not a budget problem
    assert classify_paid_failure(500, "boom") == ""


def test_free_limits_defaults_and_override(monkeypatch):
    assert free_limits("groq")["rpd"] == 500
    monkeypatch.setenv("FREE_LIMITS_JSON", '{"groq": {"rpd": 7}}')
    assert free_limits("groq") == {"rpm": 20, "rpd": 7}
    monkeypatch.setenv("FREE_LIMITS_JSON", "not json")
    assert free_limits("groq")["rpd"] == 500


def test_post_surfaces_the_api_error_body(monkeypatch):
    def boom(req, timeout=0):
        raise urllib.error.HTTPError("u", 400, "Bad Request", {}, io.BytesIO(json.dumps(
            {"error": {"type": "invalid_request_error", "message": "Your credit balance is too low"}}).encode()))
    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", boom)
    with pytest.raises(LLMError) as e:
        llm_mod._post("https://x", {}, {})
    assert e.value.status == 400 and "credit balance is too low" in str(e.value)


# ------------------------------------------------------------------ modes + hysteresis
def test_modes_follow_remaining_budget_with_hysteresis(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    o = Orchestrator(s)
    g = o.growth

    def spend(total):  # put `total` USD on PRJ-03 and tokens on two projects
        def f(d):
            d["projects"]["PRJ-03"].update(spent_usd=total, tokens_in=9000, tokens_out=1000)
            d["projects"]["PRJ-01"].update(tokens_in=500, tokens_out=100)
            d["projects"]["PRJ-02"].update(tokens_in=10, tokens_out=10)
        o.state.update(f)
    assert g.assess()["mode"] == "normal"
    spend(7.0)                                   # 30% left
    assert g.assess()["mode"] == "normal"
    spend(7.6)                                   # 24% left -> conserve; the two most token-hungry projects are "heavy"
    p = g.assess()
    assert p["mode"] == "conserve" and p["heavy"] == ["PRJ-03", "PRJ-01"] and p["free_lane"] == ["groq"]
    spend(7.3)                                   # 27%: inside the hysteresis band -> stays in conserve
    assert g.assess()["mode"] == "conserve"
    spend(6.9)                                   # 31% -> back to normal
    assert g.assess()["mode"] == "normal"
    spend(9.6)                                   # $0.40 left (<= $0.50) -> free
    assert g.assess()["mode"] == "free"
    kinds = [(e["from"], e["to"]) for e in o.state.snapshot()["ledger"] if e["kind"] == "policy"]
    assert kinds == [("normal", "conserve"), ("conserve", "normal"), ("normal", "free")]  # logged once per change, not per call


def test_no_diversion_when_there_is_nowhere_free_to_go(s):
    o = Orchestrator(s)  # no free keys, no ollama
    o.state.update(lambda d: d["projects"]["PRJ-03"].update(spent_usd=9.7, tokens_in=1000))
    p = o.growth.assess()
    assert p["mode"] == "normal" and p["free_lane"] == []   # templates would only lower quality while paid budget remains
    o.state.update(lambda d: d["projects"]["PRJ-03"].update(spent_usd=10.0))
    assert o.growth.assess()["mode"] == "free"              # breaker tripped: paid is blocked regardless


def test_paid_failure_flag_switches_to_free_and_expires(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    o = Orchestrator(s)
    o.state.update(lambda d: d.setdefault("policy_flags", {}).__setitem__(
        "paid_failure", {"t": time.time(), "reason": "exhausted: credit balance too low", "provider": "offline"}))
    p = o.growth.assess()
    assert p["mode"] == "free" and "credit balance" in p["reason"]
    o.state.update(lambda d: d["policy_flags"]["paid_failure"].update(t=time.time() - 7 * 3600))
    assert o.growth.assess()["mode"] == "normal"            # PAID_RETRY_HOURS (6h) elapsed: try the paid provider again


def test_offline_or_disabled_lane_stays_normal(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    o = Orchestrator(replace(s, free_lane=False))
    o.state.update(lambda d: d["projects"]["PRJ-03"].update(spent_usd=9.9))
    assert o.growth.assess()["mode"] == "normal"
    o2 = Orchestrator(replace(s, provider="offline"))
    assert o2.growth.assess()["mode"] == "normal"


# ------------------------------------------------------------------ routing through the CFO + LLM client
def test_conserve_moves_heavy_project_to_free_lane_and_pauses_flagship(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    net = FakeNet(monkeypatch)
    o = Orchestrator(s)
    set_policy(o, mode="conserve", heavy=["PRJ-03"], reason="test")
    heavy, light = o.pms["PRJ-03"].llm, o.pms["PRJ-01"].llm
    r = heavy.complete("heavy prompt", fallback="fb")
    assert r.provider == "groq" and r.free and r.cost_usd == 0 and r.text == "free answer"
    r = light.complete("light prompt", fallback="fb", tier=1)
    assert r.provider == "anthropic" and r.cost_usd > 0
    r = light.complete("flagship prompt", fallback="fb", tier=2)       # tier-2 is paused in conserve mode
    assert r.provider == "groq"
    assert net.hosts() == ["api.groq.com", "api.anthropic.com", "api.groq.com"]


def test_free_mode_never_calls_the_paid_provider_and_books_zero(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    net = FakeNet(monkeypatch)
    o = Orchestrator(s)
    set_policy(o, mode="free", reason="test")
    for i in range(3):
        r = o.pms["PRJ-01"].llm.complete(f"p{i}", fallback="fb")
        assert r.provider == "groq"
    assert "api.anthropic.com" not in net.hosts()
    d = o.state.snapshot()
    assert d["projects"]["PRJ-01"]["spent_usd"] == 0 and d["projects"]["PRJ-01"]["free_calls"] == 3
    day = next(iter(d["free_usage"]["groq"].values()))
    assert day["requests"] == 3 and day["tokens"] == 3 * 160 and d["free_savings_usd"] > 0
    led = [e for e in d["ledger"] if e["kind"] == "api"]
    assert all(e["free"] and e["usd"] == 0 and e["avoided_usd"] > 0 for e in led)
    assert o.cfo.summary()["burn_usd"] == 0 and o.cfo.summary()["free_requests"] == 3


def test_free_answers_are_cached_per_model_for_zero_cost(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    net = FakeNet(monkeypatch)
    o = Orchestrator(s)
    set_policy(o, mode="free", reason="test")
    a = o.pms["PRJ-01"].llm.complete("same prompt", fallback="fb")
    b = o.pms["PRJ-01"].llm.complete("same prompt", fallback="fb")
    assert not a.cached and b.cached and b.text == a.text and len(net.calls) == 1
    assert o.state.snapshot()["free_usage"]["groq"][time.strftime("%Y-%m-%d", time.gmtime())]["requests"] == 1  # cache hit used no quota


def test_paid_failure_flips_policy_and_next_call_goes_free(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    net = FakeNet(monkeypatch)
    net.fail["anthropic"] = LLMError("HTTP 400: Your credit balance is too low to access the Anthropic API", status=400)
    o = Orchestrator(s)
    r = o.pms["PRJ-01"].llm.complete("first", fallback="fb")
    assert r.provider == "groq" and r.paid_failure.startswith("exhausted")      # same call is rescued by the free lane
    flag = o.state.snapshot()["policy_flags"]["paid_failure"]
    assert "credit balance" in flag["reason"]
    net.calls.clear()
    r = o.pms["PRJ-02"].llm.complete("second", fallback="fb")
    assert r.provider == "groq" and "api.anthropic.com" not in net.hosts()      # PM-06 now routes away from the dead provider
    assert o.growth.assess()["mode"] == "free"
    # the error text (with the real reason) is in the ledger for the first call
    assert any("credit balance" in (e.get("error") or "") for e in o.state.snapshot()["ledger"])


def test_successful_paid_call_clears_the_failure_flag(s, monkeypatch):
    FakeNet(monkeypatch)
    o = Orchestrator(s)
    o.state.update(lambda d: d.setdefault("policy_flags", {}).__setitem__(
        "paid_failure", {"t": time.time() - 99999, "reason": "auth: x", "provider": "anthropic"}))
    r = o.pms["PRJ-01"].llm.complete("ok now", fallback="fb")
    assert r.provider == "anthropic" and "paid_failure" not in o.state.snapshot()["policy_flags"]


def test_daily_cap_rpm_and_cooldown(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    monkeypatch.setenv("FREE_LIMITS_JSON", '{"groq": {"rpm": 2, "rpd": 3}}')
    net = FakeNet(monkeypatch)
    o = Orchestrator(s)
    set_policy(o, mode="free", reason="test")
    llm = o.pms["PRJ-01"].llm
    got = [llm.complete(f"q{i}", fallback="fb") for i in range(4)]
    assert [r.provider for r in got] == ["groq", "groq", "offline", "offline"]   # rpm=2 (the 3rd/4th are refused locally)
    assert "self-limit" in got[2].blocked and len(net.calls) == 2
    # a 429 puts the provider on cool-down: no hammering
    monkeypatch.setenv("FREE_LIMITS_JSON", "{}")
    net.fail["groq"] = LLMError("HTTP 429: rate limit", status=429)
    o2 = Orchestrator(s)
    set_policy(o2, mode="free", reason="test")
    l2 = o2.pms["PRJ-02"].llm
    n = len(net.calls)
    assert l2.complete("a1", fallback="fb").provider == "offline"
    assert l2.complete("a2", fallback="fb").provider == "offline"
    assert len(net.calls) == n + 1                                               # second call skipped the cooling provider


def test_free_lane_requests_never_contain_the_paid_key(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    net = FakeNet(monkeypatch)
    o = Orchestrator(s)
    set_policy(o, mode="free", reason="test")
    o.pms["PRJ-01"].llm.complete("hello", fallback="fb")
    url, payload, headers = net.calls[0]
    assert headers == {"authorization": f"Bearer {FREE_KEY}"} and s.api_key not in json.dumps([url, payload, headers])
    assert FREE_KEY not in json.dumps(o.state.snapshot())                        # nothing key-shaped is persisted


def test_free_only_install_goes_live_on_the_free_lane(tmp_path, monkeypatch):
    for v in ("API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_PROVIDER"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    st = replace(Settings.load(), state_path=tmp_path / "s.json", cache_path=tmp_path / "c.json", output_dir=tmp_path / "o")
    assert st.provider == "free"
    FakeNet(monkeypatch)
    o = Orchestrator(st)
    r = o.pms["PRJ-01"].llm.complete("x", fallback="fb")
    assert r.provider == "groq" and r.cost_usd == 0
    monkeypatch.delenv("GROQ_API_KEY")
    assert Settings.load().provider == "offline"


def test_ollama_alone_is_a_free_provider(s, monkeypatch):
    net = FakeNet(monkeypatch)
    monkeypatch.setattr(LLMClient, "_ollama", lambda self, m, sy, p, mt: llm_mod.LLMResult("local", "ollama", m, 10, 5, live=True))
    monkeypatch.setattr(GrowthAgent, "_ollama_up", lambda self: True)
    o = Orchestrator(replace(s, fallback_ollama=True))
    assert o.growth.free_lane() == ["ollama"]
    set_policy(o, mode="free", reason="test")
    r = o.pms["PRJ-01"].llm.complete("x", fallback="fb")
    assert r.provider == "ollama" and r.free and not net.calls


def test_existing_budget_guards_still_hold_with_the_free_lane_on(s, monkeypatch):
    """Free lane must not weaken the $10 hard cap or the per-project quota for paid calls."""
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    FakeNet(monkeypatch)
    o = Orchestrator(s)
    o.state.update(lambda d: d["projects"]["PRJ-04"].update(spent_usd=0.0))
    r = o.pms["PRJ-04"].llm.complete("group B is local only", fallback="fb")     # Group B cannot spend paid money
    assert r.provider == "groq" and r.cost_usd == 0 and o.state.project("PRJ-04")["spent_usd"] == 0


# ------------------------------------------------------------------ reports
def test_cost_report_numbers(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    FakeNet(monkeypatch)
    o = Orchestrator(s)
    o.pms["PRJ-01"].llm.complete("a", fallback="fb")
    o.pms["PRJ-01"].llm.complete("b", fallback="fb")
    set_policy(o, mode="free", reason="test")
    o.pms["PRJ-02"].llm.complete("c", fallback="fb")
    r = o.growth.cost_report()
    assert r["paid_calls"] == 2 and r["by_model"][0]["model"].startswith("anthropic/claude-haiku") and r["by_model"][0]["calls"] == 2
    assert r["by_model"][0]["usd"] == pytest.approx(r["spent_usd"]) and r["avg_cost_per_call_usd"] == pytest.approx(r["spent_usd"] / 2)
    assert r["runway_calls"] == int(r["remaining_usd"] / r["avg_cost_per_call_usd"])
    assert r["free"]["requests"] == 1 and r["free"]["avoided_usd"] > 0
    assert r["by_project"][0]["project"] == "PRJ-01" and abs(r["remaining_usd"] + r["spent_usd"] - 10.0) < 1e-9


def test_provider_status_reports_presence_never_the_key(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    rows = {p["name"]: p for p in Orchestrator(s).growth.providers()}
    assert rows["groq"]["configured"] and rows["groq"]["active"] and not rows["mistral"]["configured"]
    assert FREE_KEY not in json.dumps(rows) and rows["groq"]["signup_url"].startswith("https://")
    assert rows["gemini_free"]["data_note"] and rows["openrouter"]["rpd"] == 45


def test_probe_uses_a_quota_slot_and_reports(s, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    net = FakeNet(monkeypatch)
    o = Orchestrator(s)
    assert o.growth.probe() == [{"name": "groq", "ok": True, "detail": "llama-3.1-8b-instant replied in 40 tokens"}]
    assert o.state.snapshot()["free_usage"]["groq"][time.strftime("%Y-%m-%d", time.gmtime())]["requests"] == 1
    net.fail["groq"] = LLMError("HTTP 401: invalid api key", status=401)
    bad = o.growth.probe()[0]
    assert bad["ok"] is False and "401" in bad["detail"]


# ------------------------------------------------------------------ web
@pytest.fixture
def web(tmp_path):
    return Web(mk_settings(tmp_path))


def test_growth_endpoint_is_read_only_and_keyless(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    w = Web(mk_settings(tmp_path))
    before = w.settings.state_path.read_text()
    d = w.get("/api/growth").json()
    assert d["policy"]["mode"] == "normal" and {p["name"] for p in d["providers"]} >= {"groq", "ollama", "mistral"}
    assert "docs/FREE_TIERS" in d["guide_html"] or "Free" in d["guide_html"]
    assert FREE_KEY not in json.dumps(d) and w.settings.state_path.read_text() == before     # a web view never writes state
    assert w.post("/api/growth").status_code == 405
    st = w.get("/api/state").json()
    assert st["summary"]["policy"]["mode"] == "normal" and "free_requests" in st["summary"]


def test_growth_check_requires_csrf_and_probes_only_configured_providers(tmp_path, monkeypatch):
    w = Web(mk_settings(tmp_path))
    assert w.c.post("/api/growth/check", json={}).status_code == 403
    assert w.post("/api/growth/check").json() == {"results": []}                             # nothing configured -> nothing sent
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    net = FakeNet(monkeypatch)
    w2 = Web(mk_settings(tmp_path))
    res = w2.post("/api/growth/check").json()["results"]
    assert res and res[0]["name"] == "groq" and res[0]["ok"] and net.hosts() == ["api.groq.com"]


def test_scrubber_redacts_free_provider_keys(tmp_path, monkeypatch):
    fake = "-".join(["not", "a", "real", "mistral", "key", "0123456789"])  # assembled at runtime (kept out of secret scanners)
    monkeypatch.setenv("MISTRAL_API_KEY", fake)
    w = Web(mk_settings(tmp_path))
    out = json.dumps(w.app.scrub({"x": f"key {fake} and {FREE_KEY}"}))
    assert fake not in out and FREE_KEY not in out


def test_ledger_endpoint_includes_policy_and_free_rows(s, monkeypatch, tmp_path):
    monkeypatch.setenv("GROQ_API_KEY", FREE_KEY)
    FakeNet(monkeypatch)
    o = Orchestrator(s)
    o.state.update(lambda d: d["projects"]["PRJ-03"].update(spent_usd=9.7, tokens_in=100))
    o.growth.assess()
    o.pms["PRJ-01"].llm.complete("x", fallback="fb")
    w = Web(replace(s, state_path=s.state_path))
    rows = w.get("/api/ledger").json()["entries"]
    assert {r["kind"] for r in rows} >= {"policy", "api"} and any(r["free"] for r in rows)
    assert any(r["note"] == "normal -> free" for r in rows)


def test_ui_has_pm06_card_tab_and_no_inline_script(web):
    html = web.get("/").text
    assert 'id="c-policy"' in html and 'data-tab="growth"' in html and 'id="tab-growth"' in html and 'id="g-check"' in html
    js = web.get("/static/app.js").text
    assert "/api/growth" in js and "renderGrowth" in js and "textContent" in js


# ------------------------------------------------------------------ CLI + docs
def cli(tmp_path, *args, **env):
    e = {**os.environ, "AGENCY_STATE_PATH": str(tmp_path / "s.json"), "AGENCY_OUTPUT_DIR": str(tmp_path / "o"),
         "AGENCY_CACHE_PATH": str(tmp_path / "c.json"), "COLUMNS": "200", "AGENCY_SKIP_DOTENV": "1", **env}
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY", "LLM_PROVIDER"):
        if k not in env:
            e.pop(k, None)
    return subprocess.run([sys.executable, "main.py", *args], cwd=ROOT, env=e, capture_output=True, text=True, timeout=120)


def test_cli_growth_and_free_tiers_views(tmp_path):
    r = cli(tmp_path, "--growth")
    assert r.returncode == 0 and "PM-06 policy" in r.stdout and "NORMAL" in r.stdout and "PRJ-03" in r.stdout
    r = cli(tmp_path, "--free-tiers", GROQ_API_KEY=FREE_KEY)
    assert r.returncode == 0 and "Groq" in r.stdout and "ACTIVE" in r.stdout and FREE_KEY not in r.stdout + r.stderr
    assert "never signs up" in r.stdout.replace("\n", " ") and "console.groq.com" in r.stdout
    r = cli(tmp_path, "--free-tiers", "--check")
    assert r.returncode == 0 and "No free provider is configured" in r.stdout.replace("\n", " ")
    assert cli(tmp_path, "--check").returncode == 2                                           # argparse error


def test_free_tiers_guide_is_honest_and_sourced():
    g = (ROOT / "docs" / "FREE_TIERS.md").read_text()
    for must in ("console.groq.com", "openrouter.ai", "aistudio.google.com", "console.mistral.ai", "developers.cloudflare.com",
                 "one account per person", "never", "verify"):
        assert must in g
    assert "no guarantee" in g.lower() and "CAPTCHA" in g and "terms" in g.lower()
