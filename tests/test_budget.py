"""$10 seed-capital controls: allocation, circuit breaker, response cache, 2-tier router, ROI telemetry."""
import json
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from agents.cfo_agent import compute_summary
from config import Settings
from llm import LLMCache, LLMClient, LLMResult, compress_system, distill, est_tokens, strip_html
from orchestrator import Orchestrator
from state import AgencyState

HAIKU, OPUS = "claude-haiku-5-5", "claude-opus-5-5"


@pytest.fixture
def settings(tmp_path):
    return replace(Settings.load(), provider="anthropic", api_key="k", fallback_ollama=False, budget_usd=10.0,
                   model_t1="", model_t2="", compute_rate_per_hour=0.0, state_path=tmp_path / "state.json",
                   cache_path=tmp_path / "cache.json", output_dir=tmp_path / "out")


def fake_provider(client, tin=1000, tout=500, text="draft"):
    """Replace the paid HTTP call; records every call that would have cost money."""
    calls = []

    def f(model, system, prompt, max_tokens):
        calls.append({"model": model, "system": system, "prompt": prompt, "max_tokens": max_tokens})
        return LLMResult(text, "anthropic", model, tin, tout, live=True)
    client._anthropic = f
    return calls


def on_disk(settings):
    return json.loads(Path(settings.state_path).read_text())


# ---------------------------------------------------------------- 1. allocation matrix
def test_capital_allocation_matrix_is_exact(settings):
    d = Orchestrator(settings).state.snapshot()
    q = {p: v["quota_usd"] for p, v in d["projects"].items()}
    assert q == pytest.approx({"PRJ-03": 3.50, "PRJ-01": 2.50, "PRJ-02": 2.00, "PRJ-04": 0.25, "PRJ-05": 0.25})
    assert d["vault"] == {"amount": 1.5, "locked": True, "released_to": None}
    assert sum(q.values()) + d["vault"]["amount"] == pytest.approx(10.0)
    assert q["PRJ-01"] + q["PRJ-02"] + q["PRJ-03"] == pytest.approx(8.0)


def test_old_state_version_is_rebuilt(tmp_path):
    p = tmp_path / "s.json"
    p.write_text(json.dumps({"version": 1, "projects": {"PRJ-01": {}}}))
    assert AgencyState(p, 10).project("PRJ-03")["quota_usd"] == pytest.approx(3.5)


def test_revenue_can_never_raise_the_hard_cap(settings):
    o = Orchestrator(settings)
    o.cfo.log_revenue("PRJ-03", 1_000_000)  # CLI revenue is unverified input
    d = o.state.snapshot()
    assert d["reinvested_usd"] == 0
    assert d["projects"]["PRJ-04"]["quota_usd"] == pytest.approx(0.25)
    s = compute_summary(d)
    assert s["ceiling_usd"] == pytest.approx(10.0) and s["breaker"] == "ACTIVE ($10.00 remaining)"
    llm = o.pms["PRJ-04"].llm
    calls = fake_provider(llm)
    assert llm.complete("x", max_tokens=800).live and len(calls) == 1  # unlocked, within its $0.25
    assert llm.complete("y", fallback="LOCAL", max_tokens=1_000_000).blocked  # est $0.50 > $0.25 quota


def test_vault_releases_to_first_group_a_revenue_only(settings):
    o = Orchestrator(settings)
    o.cfo.log_revenue("PRJ-04", 50)  # Group B revenue never unlocks the vault
    assert o.state.snapshot()["vault"]["locked"]
    o.cfo.log_revenue("PRJ-02", 39)
    d = o.state.snapshot()
    assert d["vault"]["locked"] is False and d["vault"]["released_to"] == "PRJ-02"
    assert d["projects"]["PRJ-02"]["quota_usd"] == pytest.approx(3.5)  # 2.00 + 1.50
    o.cfo.log_revenue("PRJ-01", 1500)
    d = o.state.snapshot()
    assert d["projects"]["PRJ-01"]["quota_usd"] == pytest.approx(2.5)  # second revenue does not re-release
    assert d["vault"]["released_to"] == "PRJ-02"


# ---------------------------------------------------------------- 2. circuit breaker
def test_breaker_blocks_call_over_project_subbudget(settings):
    o = Orchestrator(settings)
    o.state.set_project("PRJ-03", spent_usd=3.4999)  # $0.0001 left
    llm = o.pms["PRJ-03"].llm
    calls = fake_provider(llm)
    r = llm.complete("draft an audit", fallback="LOCAL TEMPLATE", max_tokens=800)
    assert calls == [] and r.text == "LOCAL TEMPLATE" and not r.live
    assert "sub-budget" in r.blocked
    p = o.state.project("PRJ-03")
    assert p["blocked_calls"] == 1 and p["spent_usd"] == pytest.approx(3.4999)  # nothing was spent
    assert o.state.snapshot()["blocked_calls"] == 1


def test_breaker_blocks_call_over_global_cap(settings):
    o = Orchestrator(settings)
    o.state.update(lambda d: d.__setitem__("seed_usd", 1.0))
    o.state.set_project("PRJ-03", spent_usd=0.9997)  # project has $2.50 left, global cap only $0.0003
    llm = o.pms["PRJ-03"].llm
    calls = fake_provider(llm)
    r = llm.complete("x", fallback="LOCAL")
    assert calls == [] and r.text == "LOCAL" and "global hard cap" in r.blocked
    assert not compute_summary(o.state.snapshot())["breaker_tripped"]
    o.state.set_project("PRJ-03", spent_usd=1.0)
    s = compute_summary(o.state.snapshot())
    assert s["breaker_tripped"] and s["breaker"] == "TRIPPED (Hard Cap Reached)"


def test_estimate_uses_worst_case_output_tokens(settings):
    o = Orchestrator(settings)
    llm = o.pms["PRJ-02"].llm  # $2.00 quota
    calls = fake_provider(llm)
    r = llm.complete("hi", fallback="LOCAL", max_tokens=5_000_000)  # est = 5M * $0.50/M = $2.50 > $2.00
    assert calls == [] and r.blocked
    assert llm.complete("hi", fallback="LOCAL", max_tokens=800).live  # a sane cap goes through


def test_group_b_is_local_until_group_a_revenue(settings):
    o = Orchestrator(settings)
    llm = o.pms["PRJ-04"].llm
    calls = fake_provider(llm)
    r = llm.complete("patch reasoning", fallback="LOCAL")
    assert calls == [] and "local-only" in r.blocked
    o.cfo.log_revenue("PRJ-03", 100)
    r = llm.complete("patch reasoning 2", fallback="LOCAL")
    assert len(calls) == 1 and r.live and not r.blocked


def test_parallel_reservations_never_overshoot(settings):
    o = Orchestrator(settings)
    ok = []
    ts = [threading.Thread(target=lambda: ok.append(o.cfo.reserve("PRJ-01", 0.1)[0])) for _ in range(60)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(ok) == 25  # $2.50 quota / $0.10 each, exactly
    o.cfo.release("PRJ-01", 0.1)
    assert o.cfo.reserve("PRJ-01", 0.1)[0] is True


def test_reservation_released_after_call_and_failures(settings):
    o = Orchestrator(settings)
    llm = o.pms["PRJ-01"].llm
    from llm import LLMError

    def boom(*a):
        raise LLMError("down")
    llm._anthropic = boom
    assert llm.complete("x", fallback="FB").text == "FB"
    assert o.cfo._reserved["PRJ-01"] == pytest.approx(0.0)
    fake_provider(llm)
    llm.complete("y")
    assert o.cfo._reserved["PRJ-01"] == pytest.approx(0.0)


def test_over_subbudget_project_still_runs_locally_and_audits_as_breaker(settings):
    o = Orchestrator(settings)
    o.state.set_project("PRJ-01", spent_usd=2.5)  # exactly exhausted, not overspent
    assert o.cfo.preflight("PRJ-01").approved
    llm = o.pms["PRJ-01"].llm
    fake_provider(llm)
    llm.complete("x", fallback="FB")  # blocked -> counted
    a = o.cfo.audit("PRJ-01")
    assert a.approved and a.status == "BREAKER"


# ---------------------------------------------------------------- 3. cache
def test_duplicate_prompt_is_free_and_persisted(settings):
    o = Orchestrator(settings)
    llm = o.pms["PRJ-03"].llm
    calls = fake_provider(llm, tin=1000, tout=500)
    r1 = llm.complete("same prompt", system="sys", max_tokens=300)
    spent = o.state.project("PRJ-03")["spent_usd"]
    assert r1.cost_usd == pytest.approx(0.00035) and spent == pytest.approx(0.00035)
    r2 = llm.complete("same prompt", system="sys", max_tokens=300)
    assert r2.cached and r2.cost_usd == 0.0 and r2.text == r1.text and len(calls) == 1
    p = o.state.project("PRJ-03")
    assert p["spent_usd"] == pytest.approx(spent) and p["cache_hits"] == 1
    assert o.state.snapshot()["cache_savings_usd"] == pytest.approx(0.00035)
    # a brand-new orchestrator/client reads the on-disk cache
    o2 = Orchestrator(settings)
    llm2 = o2.pms["PRJ-01"].llm
    calls2 = fake_provider(llm2)
    r3 = llm2.complete("same prompt", system="sys", max_tokens=300)
    assert r3.cached and calls2 == []
    assert json.loads(Path(settings.cache_path).read_text())


def test_cache_key_covers_model_system_and_prompt(settings):
    o = Orchestrator(settings)
    llm = o.pms["PRJ-03"].llm
    calls = fake_provider(llm)
    llm.complete("p", system="s")
    llm.complete("p", system="s2")      # different system
    llm.complete("p2", system="s")      # different prompt
    llm.complete("p", system="s", tier=2)  # different model
    assert len(calls) == 4
    assert LLMCache.key("a", "b", "c") != LLMCache.key("a", "b", "d") != LLMCache.key("x", "b", "c")


def test_cache_hit_is_free_even_when_breaker_tripped(settings):
    o = Orchestrator(settings)
    llm = o.pms["PRJ-03"].llm
    fake_provider(llm)
    llm.complete("warm", system="s")
    o.state.set_project("PRJ-03", spent_usd=3.5)  # sub-budget exhausted
    r = llm.complete("warm", system="s")
    assert r.cached and not r.blocked
    assert llm.complete("cold", system="s", fallback="FB").blocked


def test_offline_fallbacks_are_not_cached(settings, tmp_path):
    s = replace(settings, provider="offline")
    llm = LLMClient(s, cache=LLMCache(tmp_path / "c2.json"))
    llm.complete("x", fallback="FB")
    assert not (tmp_path / "c2.json").exists()


# ---------------------------------------------------------------- 4. router + exact burn
def test_router_tiers_and_cent_level_burn(settings):
    o = Orchestrator(settings)
    pm = o.pms["PRJ-03"]
    calls = fake_provider(pm.llm, tin=1000, tout=500)
    pm.llm.complete("PM draft", system="s")  # default tier = 1 (PM work)
    assert calls[-1]["model"] == HAIKU

    f = Path(settings.output_dir) / "r.md"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("# r")
    res = {"artifacts": {"r": str(f)}, "checks": [{"name": "c", "passed": True}], "summary": "good"}
    ceo_llm = o.pms["PRJ-01"].llm
    ceo_calls = fake_provider(ceo_llm, tin=1200, tout=100)
    assert o.ceo.review("PRJ-01", res, ceo_llm).approved
    assert ceo_calls[-1]["model"] == OPUS  # CEO quality gate -> flagship tier

    d = on_disk(settings)  # persisted, not just in memory
    assert d["projects"]["PRJ-03"]["spent_usd"] == pytest.approx((1000 * 0.10 + 500 * 0.50) / 1e6)      # $0.00035
    assert d["projects"]["PRJ-01"]["spent_usd"] == pytest.approx((1200 * 4.00 + 100 * 20.00) / 1e6)     # $0.0068
    ledger = [e for e in d["ledger"] if e["kind"] == "api"]
    assert {(e["model"], e["tier"]) for e in ledger} == {(HAIKU, 1), (OPUS, 2)}
    assert sum(e["usd"] for e in ledger) == pytest.approx(0.00035 + 0.0068)


def test_ceo_and_security_narrative_use_tier2_everything_else_tier1():
    import re
    src = {p: Path(p).read_text() for p in ["agents/ceo_agent.py", "projects/prj_04_zeroday_hunter/pipeline.py"]}
    assert all("tier=2" in s for s in src.values())
    others = [p for p in Path("projects").rglob("*.py") if "tests" not in p.parts and "prj_04" not in str(p)] + [Path("agents/pm_agents.py")]
    assert not any(re.search(r"tier\s*=\s*2", p.read_text()) for p in others)


def test_model_overrides_and_unknown_model_priced_conservatively(settings):
    s = replace(settings, model_t1="my-custom-model")
    llm = LLMClient(s, cache=LLMCache(Path(settings.cache_path)))
    assert llm.model_for("anthropic", 1) == "my-custom-model" and llm.model_for("anthropic", 2) == OPUS
    from llm import price_for
    assert price_for("anthropic", "my-custom-model", 1) == (0.10, 0.50) and price_for("ollama", "x") == (0.0, 0.0)
    plain = LLMClient(replace(settings, model_t1="", model_t2=""), cache=LLMCache(Path(settings.cache_path)))
    assert plain.model_for("openai", 1) == "gpt-4o-mini" and plain.model_for("openai", 2) == "gpt-4o"
    assert plain.model_for("gemini", 1) == "gemini-2.5-flash" and plain.model_for("gemini", 2) == "gemini-2.5-pro"


# ---------------------------------------------------------------- 5. token engineering
def test_system_prompt_compressed_under_300_tokens(settings):
    long_system = "You are a careful analyst. " * 200
    c = compress_system(long_system)
    assert est_tokens(c) <= 300 and c.startswith("You are a careful analyst.")
    o = Orchestrator(settings)
    llm = o.pms["PRJ-01"].llm
    calls = fake_provider(llm)
    llm.complete("hi", system=long_system)
    assert est_tokens(calls[0]["system"]) <= 300


def test_user_prompt_distilled_and_html_stripped(settings):
    page = "<html><head><style>.a{color:red}</style><script>var x=1;</script></head><body><h1>Title</h1>" + \
           "<p>filler text &amp; more</p>" * 400 + "</body></html>"
    d = distill(page, 500)
    assert "<" not in d and "var x" not in d and "color:red" not in d and "&amp;" not in d
    assert est_tokens(d) <= 500 + 8 and d.startswith("Title") and "..." in d
    assert strip_html("<b>a</b><!-- c -->b").split() == ["a", "b"]
    o = Orchestrator(settings)
    llm = o.pms["PRJ-02"].llm
    calls = fake_provider(llm)
    llm.complete(page)
    assert est_tokens(calls[0]["prompt"]) <= 508 and "<" not in calls[0]["prompt"]


# ---------------------------------------------------------------- 6. telemetry
def test_dashboard_shows_roi_telemetry(settings):
    from rich.console import Console
    o = Orchestrator(settings)
    c = Console(width=200, record=True)
    o.ceo.render_dashboard(c)
    t = c.export_text()
    for needle in ("Remaining Seed Capital", "$10.0000", "Cache Savings", "Est. Revenue Pipeline", "Circuit Breaker",
                   "ACTIVE ($10.00 remaining)", "Reserve Vault", "LOCKED $1.50"):
        assert needle in t, needle


def test_summary_pipeline_and_savings(settings):
    o = Orchestrator(settings)
    o.state.set_project("PRJ-03", units={"audits_ready": 500}, spent_usd=0.05)
    o.state.set_project("PRJ-01", units={"legacy_repos_audited": 2})
    o.state.set_project("PRJ-02", units={"extensions_packaged": 1})
    o.state.update(lambda d: d.__setitem__("cache_savings_usd", 0.012))
    s = o.cfo.summary()
    assert s["pipeline_usd"] == pytest.approx(500 * 3.0 + 2 * 100.0 + 390.0)
    assert s["remaining_seed_usd"] == pytest.approx(10 - 0.05) and s["burn_usd"] == pytest.approx(0.05)
    assert s["cache_savings_usd"] == pytest.approx(0.012) and s["roi_multiple"] == pytest.approx(s["pipeline_usd"] / 0.05)


def test_roi_values_override(monkeypatch):
    from config import roi_values
    monkeypatch.setenv("ROI_VALUES_JSON", '{"audits_ready": 1.5}')
    assert roi_values()["audits_ready"] == 1.5 and roi_values()["extensions_packaged"] == 390.0
    monkeypatch.setenv("ROI_VALUES_JSON", "not json")
    assert roi_values()["audits_ready"] == 3.0


def test_sprint_records_sellable_units_offline(tmp_path):
    s = replace(Settings.load(), provider="offline", budget_usd=10.0, state_path=tmp_path / "s.json",
                cache_path=tmp_path / "c.json", output_dir=tmp_path / "out", max_cycles=2)
    o = Orchestrator(s)
    o.run_sprint(["PRJ-03", "PRJ-02", "PRJ-01"])
    summ = o.cfo.summary()
    assert summ["units"]["PRJ-03"] == {"audits_ready": 1} and summ["units"]["PRJ-02"] == {"extensions_packaged": 1}
    assert summ["pipeline_usd"] == pytest.approx(3.0 + 390.0 + 100.0)
    assert summ["burn_usd"] == 0.0 and summ["breaker"].startswith("ACTIVE ($10.00")


def test_batch_audit_isolates_failures(tmp_path):
    from projects.prj_03_deal_closer import b2b_sniper as bs
    from projects.prj_03_deal_closer.pipeline import start_fixture_server
    srv, base = start_fixture_server()
    try:
        csv_path = tmp_path / "t.csv"
        csv_path.write_text(f"url,ceo,company\n{base}/bad,Dana,Northwind\n{base}/good,Priya,Contoso\nftp://nope,X,Y\n,,\n")
        targets = bs.load_targets(str(csv_path))
        assert len(targets) == 3  # blank url skipped
        llm = LLMClient(Settings(provider="offline"), cache=LLMCache(tmp_path / "c.json"))
        res = bs.run_batch(targets, llm, allow_private=True)
        assert [r["ready"] for r in res] == [True, True, False] and "error" in res[2]
    finally:
        srv.shutdown()
