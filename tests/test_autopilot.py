"""AI CEO auto-pilot: prospect pool, auto-seeding, the one-sequence chain, spend caps, sign-off, web + CLI."""
import json
import os
import re
from dataclasses import replace
from pathlib import Path

import pytest

import main as cli
from agents.ceo_agent import CEOAgent
from config import Settings, sender_name
from llm import LLMClient, LLMResult
from orchestrator import Orchestrator
from projects.prj_03_deal_closer import b2b_sniper as bs
from projects.prj_03_deal_closer import prospects
from state import AgencyState
from test_web_dashboard import Recorder, Web

FIXTURE = (Path(bs.__file__).parent / "fixtures" / "bad_site.html").read_text() + "<!--" + "x" * 3000 + "-->"


def mk(tmp_path, provider="offline", key=""):
    s = replace(Settings.load(), provider=provider, api_key=key, fallback_ollama=False, budget_usd=10.0, model_t1="", model_t2="",
                compute_rate_per_hour=0.0, state_path=tmp_path / "state.json", cache_path=tmp_path / "cache.json",
                output_dir=tmp_path / "out", targets_path=tmp_path / "targets.csv", max_cycles=2)
    AgencyState(s.state_path, s.budget_usd)
    return s


@pytest.fixture
def net(monkeypatch):
    """No real network: every prospect 'site' is the flawed fixture page (deterministic findings)."""
    fetched = []
    real_fetch = bs.fetch

    def fake_fetch(url, allow_private=False, timeout=15.0):
        if url.startswith("http://127.0.0.1"):  # PRJ-03's own local fixture sites stay real
            return real_fetch(url, allow_private=allow_private, timeout=timeout)
        fetched.append(url)
        n = len(FIXTURE.encode())
        return bs.FetchResult(url, 200, 0.3, 0.5, n, n, True, True, {}, FIXTURE)
    monkeypatch.setattr(bs, "fetch", fake_fetch)
    monkeypatch.setattr(bs, "check_url_safe", lambda *a, **k: None)
    return fetched


# ------------------------------------------------------------------ the curated pool
def test_pool_is_curated_valid_and_honest():
    pool = prospects.load_pool()
    assert 15 <= len(pool) <= 20
    assert len({prospects.norm_url(p["url"]) for p in pool}) == len(pool)
    for p in pool:
        assert p["url"].startswith("https://") and p["company"] and p["segment"] in {"saas", "agency"}
        prospects.clean_row(p["url"], p["greeting"], p["company"])  # passes the same validation as user input
        if p["greeting_verified"]:
            assert p["greeting_source"].startswith("https://") and p["greeting"] != "there"
        else:
            assert p["greeting"] == "there" and not p["greeting_source"]
    assert {p["segment"] for p in pool} == {"saas", "agency"} and sum(p["greeting_verified"] for p in pool) >= 5


def test_pool_loader_rejects_unsourced_names(tmp_path):
    bad = tmp_path / "pool.json"
    bad.write_text(json.dumps([{"company": "X", "url": "https://x.com", "greeting": "Bob", "greeting_verified": True, "greeting_source": None}]))
    with pytest.raises(ValueError):
        prospects.load_pool(bad)
    bad.write_text(json.dumps([{"company": "X", "url": "https://x.com", "greeting": "Bob", "greeting_verified": False}]))
    with pytest.raises(ValueError):
        prospects.load_pool(bad)


# ------------------------------------------------------------------ CEO target dispatch / auto-seeding
def test_ceo_seeds_missing_targets_csv_and_assigns_to_pm03(tmp_path):
    s = mk(tmp_path)
    o = Orchestrator(s)
    assert not s.targets_path.exists()
    r = o.ceo.dispatch_targets(s.targets_path, n=5)
    pool = prospects.load_pool()
    assert r["seeded"] and r["source"] == "pool" and [t["url"] for t in r["targets"]] == [p["url"] for p in pool[:5]]
    rows = prospects.read_targets(s.targets_path)
    assert len(rows) == 5 and s.targets_path.read_text().startswith("url,ceo,company")
    assert {t["ceo"] for t in rows} <= {"there"} | {p["greeting"] for p in pool if p["greeting_verified"]}
    assert o.state.project("PRJ-03")["targets_assigned"] == 5
    assert r["pool"] == len(pool) and r["remaining"] == len(pool)


def test_empty_file_is_reseeded_and_unaudited_rows_are_respected(tmp_path):
    s = mk(tmp_path)
    o = Orchestrator(s)
    s.targets_path.write_text("url,ceo,company\n")  # header only = empty
    assert o.ceo.dispatch_targets(s.targets_path)["seeded"]
    prospects.write_targets(s.targets_path, [{"url": "https://my-own-pick.com", "ceo": "Zed", "company": "Mine"}])
    r = o.ceo.dispatch_targets(s.targets_path)
    assert not r["seeded"] and r["source"] == "existing" and prospects.read_targets(s.targets_path)[0]["company"] == "Mine"


def test_audited_targets_are_never_reselected_and_batches_rotate(tmp_path):
    s = mk(tmp_path)
    o = Orchestrator(s)
    pool = prospects.load_pool()
    seen = []
    for _ in range(3):
        r = o.ceo.dispatch_targets(s.targets_path, n=5)
        urls = [t["url"] for t in r["targets"]]
        assert not set(urls) & set(seen), "an audited prospect was handed out again"
        seen += urls
        o.ceo.mark_audited([{"url": u, "ready": True} for u in urls])  # all rows audited -> next call rotates
    assert seen[:5] == [p["url"] for p in pool[:5]] and len(seen) == 15
    assert o.ceo.pool_status() == {"pool": len(pool), "audited_in_pool": 15, "remaining": len(pool) - 15}
    r = o.ceo.dispatch_targets(s.targets_path, n=5)  # only 3 left
    assert len(r["targets"]) == 3
    o.ceo.mark_audited([{"url": t["url"]} for t in r["targets"]])
    r = o.ceo.dispatch_targets(s.targets_path, n=5)  # exhausted: keeps the current rows, says so
    assert not r["seeded"] and "exhausted" in r["note"]
    (tmp_path / "x").mkdir()
    o2 = Orchestrator(mk(tmp_path / "x"))
    o2.ceo.mark_audited([{"url": p["url"]} for p in pool])
    with pytest.raises(RuntimeError, match="exhausted"):
        o2.ceo.dispatch_targets(Path(tmp_path / "x" / "none.csv"))


def test_rotate_replaces_unaudited_rows_with_the_next_batch(tmp_path):
    s = mk(tmp_path)
    o = Orchestrator(s)
    first = [t["url"] for t in o.ceo.dispatch_targets(s.targets_path)["targets"]]
    rotated = [t["url"] for t in o.ceo.dispatch_targets(s.targets_path, rotate=True)["targets"]]
    assert first == rotated  # nothing was audited yet, so "next un-audited" is the same batch
    o.ceo.mark_audited([{"url": u} for u in first])
    after = [t["url"] for t in o.ceo.dispatch_targets(s.targets_path, rotate=True)["targets"]]
    assert not set(after) & set(first) and after == [t["url"] for t in prospects.read_targets(s.targets_path)]


# ------------------------------------------------------------------ LLM discovery is validated, never trusted
class FakeLLM:
    def __init__(self, text):
        self.text, self.prompts = text, []

    def complete(self, prompt, system="", fallback="", max_tokens=0, tier=1, **k):
        self.prompts.append((prompt, tier))
        return LLMResult(self.text, "anthropic", "claude-haiku-5-5", live=True)


def test_discovery_keeps_only_valid_reachable_unknown_https_leads(tmp_path, monkeypatch):
    s = mk(tmp_path)
    o = Orchestrator(s)
    monkeypatch.setattr(CEOAgent, "verify_reachable", staticmethod(lambda u: "unreachable" not in u))
    pool_url = prospects.load_pool()[0]["url"]
    llm = FakeLLM(json.dumps([
        {"company": "Fresh Co", "url": "https://fresh-co.com"},
        {"company": "Plain http", "url": "http://insecure.com"},
        {"company": "Local", "url": "https://localhost"}, {"company": "IP", "url": "https://10.0.0.5/"},
        {"company": "JS", "url": "javascript:alert(1)"}, {"company": "Pool dup", "url": pool_url},
        {"company": "=SUM(A1)", "url": "https://formula.com"}, {"company": "Gone", "url": "https://unreachable.com"},
        {"company": "Fresh Two", "url": "https://fresh-two.io/"}, {"url": 5}, "junk"]))
    rows = o.ceo.discover_prospects(llm, 5, {prospects.norm_url(pool_url)})
    assert [r["company"] for r in rows] == ["Fresh Co", "Fresh Two"]
    assert all(r["ceo"] == "there" and r["url"].startswith("https://") for r in rows)
    assert llm.prompts[0][1] == 1  # tier-1 model
    assert o.ceo.discover_prospects(FakeLLM("not json at all"), 5, set()) == []
    assert prospects.parse_discovered("[" * 3, set(), 5) == []


def test_dispatch_with_discovery_mixes_pool_and_llm_and_never_names_people(tmp_path, monkeypatch):
    s = mk(tmp_path)
    o = Orchestrator(s)
    monkeypatch.setattr(CEOAgent, "verify_reachable", staticmethod(lambda u: True))
    llm = FakeLLM(json.dumps([{"company": "New A", "url": "https://new-a.com"}, {"company": "New B", "url": "https://new-b.com"}]))
    r = o.ceo.dispatch_targets(s.targets_path, n=5, discover=True, llm=llm)
    assert r["source"] == "pool+llm" and len(r["targets"]) == 5
    assert [t["company"] for t in r["targets"][-2:]] == ["New A", "New B"] and r["targets"][-1]["ceo"] == "there"
    assert o.ceo.dispatch_targets(s.targets_path, n=5, discover=True, llm=None)["source"] == "existing"  # no LLM -> pool only


# ------------------------------------------------------------------ sign-off
def test_sender_name_default_override_and_sanitising(monkeypatch):
    monkeypatch.delenv("SENDER_NAME", raising=False)
    assert sender_name() == "Mohamed"
    monkeypatch.setenv("SENDER_NAME", "  Sam Lee ")
    assert sender_name() == "Sam Lee"
    monkeypatch.setenv("SENDER_NAME", "[Your Name]<b>\n")  # placeholder-looking input is stripped
    assert sender_name() == "Your Nameb"
    monkeypatch.setenv("SENDER_NAME", "   ")
    assert sender_name() == "Mohamed"


def test_outreach_is_signed_with_the_configured_name(monkeypatch):
    f = [bs.Finding("seo", 3, "mobile", "No viewport", "there is no mobile viewport tag")]
    llm = FakeLLM("")
    monkeypatch.delenv("SENDER_NAME", raising=False)
    text, _ = bs.generate_outreach(llm, "https://x.test", "Dana", "X", f)
    assert text.rstrip().endswith("- Mohamed") and "Alex" not in text and "Mohamed" in llm.prompts[0][0]
    monkeypatch.setenv("SENDER_NAME", "Priya")
    text, _ = bs.generate_outreach(FakeLLM(""), "https://x.test", "Dana", "X", f)
    assert text.rstrip().endswith("- Priya")
    assert bs.generate_outreach(FakeLLM(""), "https://x.test", "Dana", "X", f, sender="Kim")[0].rstrip().endswith("- Kim")


# ------------------------------------------------------------------ the full chain (offline, then live with caps)
def test_autopilot_offline_from_a_clean_state_runs_the_whole_chain(tmp_path, net):
    s = mk(tmp_path)
    o = Orchestrator(s)
    seen_steps = []
    r = o.run_autopilot(on_step=lambda steps: seen_steps.append([(x["key"], x["status"]) for x in steps]))
    assert r["status"] == "complete" and [x["key"] for x in r["steps"]] == ["dispatch", "audit", "group_a", "sheet"]
    assert all(x["status"] == "done" for x in r["steps"]) and seen_steps[0] == [("dispatch", "running")]
    # step 1: CEO seeded targets.csv from the pool (it did not exist) and fetched exactly those sites
    rows = prospects.read_targets(s.targets_path)
    assert len(rows) == 5 and all(t["url"] in net for t in rows)
    # step 2: five validated messages signed Mohamed
    batch = json.loads((s.output_dir / "PRJ-03" / "outreach_batch.json").read_text())
    assert len(batch) == 5 and all(b["ready"] and b["outreach"].rstrip().endswith("Mohamed") for b in batch)
    assert all(b["outreach_words"] < 110 for b in batch)
    # step 3: PRJ-01 / PRJ-02 went through the CFO + CEO gates
    d = o.state.snapshot()
    assert d["projects"]["PRJ-01"]["ceo_status"] == d["projects"]["PRJ-02"]["ceo_status"] == "APPROVED"
    assert d["projects"]["PRJ-03"]["units"] == {"audits_ready": 5} and d["projects"]["PRJ-03"]["targets_assigned"] == 5
    # step 4: a non-empty sell sheet, signed Mohamed, with the 5 messages
    sheet = (s.output_dir / "READY_TO_SELL_NOW.md").read_text()
    assert len(sheet) > 2000 and sheet.count("Mohamed") >= 6 and "Alex" not in sheet and "5 of 5 targets" in sheet
    # all five targets are recorded as audited; free run
    assert set(d["prospects"]["audited"]) == {prospects.norm_url(t["url"]) for t in rows}
    assert r["llm"]["spent_usd"] == 0 and all(e.get("usd", 0) == 0 for e in d["ledger"])
    # a second run moves on to a new batch
    again = o.run_autopilot()
    assert again["status"] == "complete"
    assert not {t["url"] for t in prospects.read_targets(s.targets_path)} & {t["url"] for t in rows}


def fake_provider(monkeypatch, tin=1000, tout=500):
    calls = []

    def f(self, model, system, prompt, max_tokens):
        calls.append(model)
        return LLMResult("Hi there, the page head has render-blocking scripts. Would that be useful? - Mohamed", "anthropic", model, tin, tout, live=True)
    monkeypatch.setattr(LLMClient, "_anthropic", f)
    return calls


def test_autopilot_live_enforces_the_cfo_cap_and_still_completes(tmp_path, net, monkeypatch):
    calls = fake_provider(monkeypatch)  # haiku call = $0.00035, opus call = $0.014
    s = mk(tmp_path, "anthropic", "sk-ant-api03-fake-test-key-0000000000")
    o = Orchestrator(s)
    o.cfo.set_run_cap(0.05)
    r = o.run_autopilot(live=True)
    burn = o.cfo.summary()["burn_usd"]
    assert r["status"] == "complete" and 0 < burn <= 0.05 and r["llm"]["live_calls"] >= 6
    assert "claude-haiku-5-5" in calls and "claude-opus-5-5" in calls
    sheet = (s.output_dir / "READY_TO_SELL_NOW.md").read_text()
    assert len(sheet) > 2000 and "Alex" not in sheet
    # a tiny cap: the flagship calls are blocked, the chain still completes on templates, spend never exceeds the cap
    t2 = tmp_path / "tiny"
    t2.mkdir()
    s2 = mk(t2, "anthropic", "sk-ant-api03-fake-test-key-0000000000")
    o2 = Orchestrator(s2)
    o2.cfo.set_run_cap(0.002)
    before = len(calls)
    r2 = o2.run_autopilot(live=True)
    assert r2["status"] == "complete" and r2["llm"]["blocked"] >= 1 and o2.cfo.summary()["burn_usd"] <= 0.002
    assert "claude-opus-5-5" not in calls[before:]
    assert all(b["outreach"].rstrip().endswith("Mohamed") for b in json.loads((s2.output_dir / "PRJ-03" / "outreach_batch.json").read_text()))


def test_a_failed_step_is_recorded_and_later_steps_still_run(tmp_path, net, monkeypatch):
    s = mk(tmp_path)
    o = Orchestrator(s)
    monkeypatch.setattr(o.ceo, "dispatch_targets", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("pool exhausted")))
    r = o.run_autopilot()
    assert r["status"] == "partial" and r["failed_steps"][0] == "dispatch" and r["steps"][0]["detail"].startswith("RuntimeError: pool exhausted")
    assert [x["status"] for x in r["steps"]][2] == "done"  # PRJ-01 / PRJ-02 still ran


# ------------------------------------------------------------------ CLI
def env_paths(monkeypatch, tmp_path):
    for k, name in (("AGENCY_STATE_PATH", "state.json"), ("AGENCY_CACHE_PATH", "cache.json"), ("AGENCY_OUTPUT_DIR", "out"),
                    ("AGENCY_TARGETS_PATH", "targets.csv")):
        monkeypatch.setenv(k, str(tmp_path / name))


def test_cli_autopilot_end_to_end_offline(tmp_path, net, monkeypatch, capsys):
    env_paths(monkeypatch, tmp_path)
    assert cli.main(["--ceo-autopilot"]) == 0
    out = capsys.readouterr().out
    assert "offline, $0.00" in out and "Auto-pilot complete" in out and out.count("✓") == 4
    assert (tmp_path / "targets.csv").exists() and len((tmp_path / "out" / "READY_TO_SELL_NOW.md").read_text()) > 2000


def test_cli_flag_rules(tmp_path, monkeypatch):
    env_paths(monkeypatch, tmp_path)
    for argv in (["--discover-targets"], ["--rotate-targets"], ["--ceo-autopilot", "--discover-targets"]):
        with pytest.raises(SystemExit) as e:
            cli.main(argv)
        assert e.value.code == 2


def test_cli_live_autopilot_defaults_to_a_ten_cent_cap_and_honours_max_spend(tmp_path, monkeypatch):
    env_paths(monkeypatch, tmp_path)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-fake-test-key-0000000000")
    caps = []

    def fake_run(self, **kw):
        caps.append(round(self.cfo.run_ceiling, 6))
        return {"status": "complete", "failed_steps": [], "steps": [], "sell_sheet": "x", "llm": {"live_calls": 0, "cache_hits": 0, "blocked": 0, "errors": 0, "spent_usd": 0.0}}
    monkeypatch.setattr(Orchestrator, "run_autopilot", fake_run)
    assert cli.main(["--ceo-autopilot", "--live"]) == 0
    assert cli.main(["--ceo-autopilot", "--live", "--max-spend", "0.03"]) == 0
    assert caps == [0.10, 0.03]


def test_cli_live_without_key_falls_back_to_offline(tmp_path, net, monkeypatch, capsys):
    env_paths(monkeypatch, tmp_path)
    assert cli.main(["--ceo-autopilot", "--live"]) == 0
    assert "no API key" in capsys.readouterr().out


# ------------------------------------------------------------------ web UI + API
def test_ui_has_the_autopilot_and_rotate_controls(tmp_path):
    w = Web(mk(tmp_path))
    html = w.get("/").text
    assert "AI CEO: Run Full Auto-Pilot (Live - Capped at $0.10)" in html and "AI CEO: Auto-Pilot (Offline)" in html
    assert "Rotate / Load Next 5 Prospects" in html
    js = w.get("/static/app.js").text
    assert "/api/autopilot" in js and "/api/targets/rotate" in js


def test_autopilot_endpoint_guards_and_wiring(tmp_path):
    calls = []

    def ap(live, cap, discover, rotate, on_step=None):
        calls.append({"live": live, "cap": cap, "discover": discover, "rotate": rotate})
        if on_step:
            on_step([{"key": "dispatch", "label": "CEO", "status": "done", "detail": "5 targets"}])
        return {"status": "complete", "failed_steps": [], "steps": [], "llm": {}}
    key = "sk-ant-api03-fake-test-key-0000000000"
    keyless = Web(mk(tmp_path), executor=Recorder())
    keyless.app.autopilot = ap
    assert keyless.post("/api/autopilot", {"mode": "live", "confirm": True}).status_code == 409           # no key
    assert keyless.post("/api/autopilot", {"mode": "offline", "discover": True}).status_code == 422       # discovery needs live
    job = keyless.wait(keyless.post("/api/autopilot", {"mode": "offline"}))
    assert job["status"] == "done" and job["kind"] == "autopilot" and job["progress"][0]["key"] == "dispatch"
    assert calls == [{"live": False, "cap": None, "discover": False, "rotate": False}]

    t2 = tmp_path / "live"
    t2.mkdir()
    w = Web(mk(t2, "anthropic", key), executor=Recorder())
    w.app.autopilot = ap
    assert w.post("/api/autopilot", {"mode": "live"}).status_code == 400                                    # no confirm
    for bad in (0, -1, 1.5, "x"):
        assert w.post("/api/autopilot", {"mode": "live", "confirm": True, "max_spend": bad}).status_code == 422
    w.wait(w.post("/api/autopilot", {"mode": "live", "confirm": True}))
    w.wait(w.post("/api/autopilot", {"mode": "live", "confirm": True, "max_spend": 0.04, "discover": True, "rotate": True}))
    assert calls[1:] == [{"live": True, "cap": 0.10, "discover": False, "rotate": False},
                         {"live": True, "cap": 0.04, "discover": True, "rotate": True}]


def test_autopilot_through_the_web_runs_everything_and_updates_the_sell_sheet_tab(tmp_path, net):
    w = Web(mk(tmp_path), targets=tmp_path / "targets.csv")
    job = w.wait(w.post("/api/autopilot", {"mode": "offline"}), timeout=120)
    assert job["status"] == "done" and job["result"]["status"] == "complete"
    assert [p["status"] for p in job["progress"]] == ["done"] * 4
    sheet = w.get("/api/sell-sheet").json()
    assert sheet["exists"] and "Mohamed" in sheet["markdown"] and "Alex" not in sheet["markdown"] and sheet["html"].count("Copy message") >= 5
    t = w.get("/api/targets").json()
    assert len(t["targets"]) == 5 and t["pool"]["remaining"] == t["pool"]["pool"] - 5
    s = w.get("/api/state").json()
    assert s["summary"]["burn_usd"] == 0 and next(p for p in s["projects"] if p["id"] == "PRJ-03")["units"] == {"audits_ready": 5}


def test_rotate_endpoint_loads_the_next_batch_with_one_tap(tmp_path):
    w = Web(mk(tmp_path), targets=tmp_path / "targets.csv")
    r = w.post("/api/targets/rotate", {"count": 5})
    assert r.status_code == 200 and len(r.json()["targets"]) == 5 and r.json()["source"] == "pool"
    first = [t["url"] for t in r.json()["targets"]]
    assert [t["url"] for t in w.get("/api/targets").json()["targets"]] == first
    Orchestrator(w.settings).ceo.mark_audited([{"url": u} for u in first])
    second = [t["url"] for t in w.post("/api/targets/rotate", {}).json()["targets"]]
    assert len(second) == 5 and not set(first) & set(second)
    assert w.get("/api/targets").json()["pool"]["audited_in_pool"] == 5
    for bad in ({"count": 0}, {"count": 11}, {"count": 2.5}, {"count": "5"}):
        assert w.post("/api/targets/rotate", bad).status_code == 422


def test_rotate_discovery_is_a_guarded_paid_action(tmp_path, monkeypatch):
    keyless = Web(mk(tmp_path))
    assert keyless.post("/api/targets/rotate", {"discover": True, "confirm": True}).status_code == 409
    t2 = tmp_path / "k"
    t2.mkdir()
    key = "sk-ant-api03-fake-test-key-0000000000"
    w = Web(mk(t2, "anthropic", key), targets=t2 / "targets.csv")
    assert w.post("/api/targets/rotate", {"discover": True}).status_code == 400                             # no confirm
    assert w.post("/api/targets/rotate", {"discover": True, "confirm": True, "max_spend": 5}).status_code == 422
    monkeypatch.setattr(CEOAgent, "verify_reachable", staticmethod(lambda u: True))
    calls = []
    monkeypatch.setattr(LLMClient, "_anthropic", lambda self, m, s, p, t: calls.append(m) or LLMResult(
        json.dumps([{"company": "Brand New", "url": "https://brand-new.dev"}]), "anthropic", m, 400, 100, live=True))
    r = w.post("/api/targets/rotate", {"discover": True, "confirm": True, "max_spend": 0.02})
    assert r.status_code == 200 and r.json()["targets"][-1] == {"url": "https://brand-new.dev", "ceo": "there", "company": "Brand New"}
    assert calls == ["claude-haiku-5-5"] and r.json()["source"] == "pool+llm"
    assert w.get("/api/state").json()["summary"]["burn_usd"] <= 0.02


def test_rotate_is_refused_while_a_run_is_in_progress(tmp_path):
    import threading
    rec = Recorder()
    rec.gate = threading.Event()
    w = Web(mk(tmp_path), executor=rec, targets=tmp_path / "targets.csv")
    started = w.post("/api/run/PRJ-01", {"mode": "offline"})
    assert w.post("/api/targets/rotate", {}).status_code == 409
    assert w.post("/api/autopilot", {"mode": "offline"}).status_code == 409
    rec.gate.set()
    w.wait(started)
