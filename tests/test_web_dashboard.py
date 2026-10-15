"""Local web command center: security, accurate telemetry, safe runs, spend caps, artifacts, targets."""
import csv
import http.client
import json
import re
import socket
import threading
import time
import zipfile
from dataclasses import replace
from pathlib import Path

import pytest

import web_dashboard as wd
from config import Settings
from llm import LLMClient, LLMResult
from orchestrator import Orchestrator
from state import AgencyState
from web_markdown import render_markdown

SECRET = "sk-ant-api03-TESTSECRETVALUE1234567890abcdefghij"
BASE = "http://127.0.0.1:8080"


def mk_settings(tmp_path, provider="offline", key=""):
    s = replace(Settings.load(), provider=provider, api_key=key, fallback_ollama=False, budget_usd=10.0, model_t1="", model_t2="",
                compute_rate_per_hour=0.0, state_path=tmp_path / "state.json", cache_path=tmp_path / "cache.json",
                output_dir=tmp_path / "out", max_cycles=2)
    AgencyState(s.state_path, s.budget_usd)  # fresh state file
    return s


class Resp:
    def __init__(self, status, headers, body):
        self.status_code, self.content = status, body
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.text = body.decode("utf-8", "replace")

    def json(self):
        return json.loads(self.text)


class Client:
    """Calls the app's transport-independent handler directly (same code path the HTTP server uses)."""

    def __init__(self, app, host="127.0.0.1:8080"):
        self.app, self.host = app, host

    def request(self, method, path, headers=None, json_body=None):
        h = {"host": self.host, **{k.lower(): v for k, v in (headers or {}).items()}}
        body = b""
        if json_body is not None:
            body = json.dumps(json_body).encode()
            h["content-type"] = "application/json"
        return Resp(*self.app.handle(method, path, h, body))

    def get(self, path, headers=None):
        return self.request("GET", path, headers)

    def post(self, path, json=None, headers=None):
        return self.request("POST", path, headers, json)

    def delete(self, path, headers=None):
        return self.request("DELETE", path, headers)

    def options(self, path, headers=None):
        return self.request("OPTIONS", path, headers)


class Web:
    """Client + CSRF token, mimicking the page."""

    def __init__(self, settings, executor=None, targets=None):
        self.settings = settings
        self.targets = targets or settings.state_path.parent / "targets.csv"
        self.app = wd.create_app(settings, port=8080, targets_path=self.targets, executor=executor)
        self.c = Client(self.app)
        self.token = re.search(r'csrf-token" content="([^"]+)"', self.c.get("/").text).group(1)

    def get(self, path, **kw):
        return self.c.get(path, **kw)

    def post(self, path, json_=None, **kw):
        return self.c.post(path, json=json_ if json_ is not None else {}, headers={"X-CSRF-Token": self.token}, **kw)

    def delete(self, path):
        return self.c.delete(path, headers={"X-CSRF-Token": self.token})

    def wait(self, resp, timeout=90):
        assert resp.status_code == 202, resp.text
        jid = resp.json()["job"]["id"]
        end = time.time() + timeout
        while time.time() < end:
            job = self.get(f"/api/jobs/{jid}").json()["job"]
            if job["status"] != "running":
                return job
            time.sleep(0.1)
        raise AssertionError("job did not finish")


@pytest.fixture
def web(tmp_path):
    return Web(mk_settings(tmp_path))


class Recorder:
    """Fake executor: records what the server asked to run (no pipelines, no spend)."""

    def __init__(self):
        self.calls, self.gate = [], None

    def __call__(self, pids, live, max_spend, env=None):
        if self.gate:
            self.gate.wait(10)
        self.calls.append({"pids": pids, "live": live, "max_spend": max_spend, "env": env})
        return {"projects": {p: {"ceo_status": "APPROVED", "ceo_score": 100.0, "cfo_status": "HEALTHY", "blockers": []} for p in pids},
                "llm": {"live_calls": 0, "cache_hits": 0, "blocked": 0, "errors": 0, "spent_usd": 0.0}}


# ------------------------------------------------------------------ page, state, telemetry
def test_index_and_static_assets(web):
    r = web.get("/")
    assert r.status_code == 200 and "Agency Command Center" in r.text
    assert 'name="csrf-token"' in r.text and "{{CSRF_TOKEN}}" not in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "default-src 'none'" in csp and r.headers["x-frame-options"] == "DENY"
    assert "cdn" not in r.text.lower() and not re.search(r"""(src|href|action)=["']?(https?:)?//""", r.text)  # no external resources
    assert "<form" not in r.text and not re.search(r"<script(?![^>]*\bsrc=)", r.text)  # no forms, no inline scripts (CSP-clean)
    js = web.get("/static/app.js")
    assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    assert "eval(" not in js.text and "document.write" not in js.text
    assert web.get("/static/app.css").status_code == 200


def test_state_telemetry_matches_cfo_numbers(web):
    d = web.get("/api/state").json()
    s = d["summary"]
    assert (s["seed_usd"], s["remaining_seed_usd"], s["burn_usd"]) == (10.0, 10.0, 0.0)
    assert s["vault_locked"] is True and s["vault_amount"] == pytest.approx(1.5) and s["breaker"] == "ACTIVE ($10.00 remaining)"
    assert s["breaker_tripped"] is False and s["seed_remaining_pct"] == 100
    ps = {p["id"]: p for p in d["projects"]}
    assert list(ps) == ["PRJ-01", "PRJ-02", "PRJ-03", "PRJ-04", "PRJ-05"]
    assert {k: v["quota_usd"] for k, v in ps.items()} == pytest.approx({"PRJ-01": 2.5, "PRJ-02": 2.0, "PRJ-03": 3.5, "PRJ-04": 0.25, "PRJ-05": 0.25})
    assert ps["PRJ-03"]["group_label"] == "Group A: Cash Cow" and ps["PRJ-04"]["group_label"] == "Group B: Reinvested"
    assert d["live_available"] is False and d["limits"] == {"single_default": 0.05, "all_default": 0.10, "click_ceiling": 1.0}


def test_state_reflects_burn_cache_units_and_tripped_breaker(web):
    o = Orchestrator(web.settings)
    o.cfo.record_usage("PRJ-03", LLMResult("x", "anthropic", "claude-haiku-5-5", 1000, 500, 0.00035, live=True, tier=1))
    o.cfo.record_usage("PRJ-03", LLMResult("x", "anthropic", "claude-haiku-5-5", 0, 0, 0.0, live=True, cached=True, saved_usd=0.00035))
    o.state.set_project("PRJ-03", units={"audits_ready": 5}, ceo_status="APPROVED", ceo_score=100.0)
    s = web.get("/api/state").json()
    assert s["summary"]["burn_usd"] == pytest.approx(0.00035) and s["summary"]["remaining_seed_usd"] == pytest.approx(9.99965)
    assert s["summary"]["live_calls"] == 1 and s["summary"]["cached_calls"] == 1 and s["summary"]["cache_savings_usd"] == pytest.approx(0.00035)
    p3 = next(p for p in s["projects"] if p["id"] == "PRJ-03")
    assert p3["units"] == {"audits_ready": 5} and p3["status"] == "APPROVED" and p3["spent_pct"] == pytest.approx(0.01, abs=0.01)
    assert s["summary"]["pipeline_usd"] == pytest.approx(15.0)
    o.state.set_project("PRJ-03", spent_usd=3.5, cfo_status="BREAKER")
    o.state.update(lambda d: d.__setitem__("seed_usd", 3.5))
    s = web.get("/api/state").json()
    assert s["summary"]["breaker_tripped"] is True and "TRIPPED" in s["summary"]["breaker"]
    assert next(p for p in s["projects"] if p["id"] == "PRJ-03")["status"] == "BREAKER"


def test_ledger_endpoint_lists_exact_spend(web):
    o = Orchestrator(web.settings)
    o.cfo.record_usage("PRJ-01", LLMResult("x", "anthropic", "claude-opus-5-5", 1200, 100, 0.0068, live=True, tier=2))
    rows = web.get("/api/ledger?limit=5").json()["entries"]
    assert rows[0]["project"] == "PRJ-01" and rows[0]["model"] == "claude-opus-5-5" and rows[0]["tier"] == 2
    assert (rows[0]["tokens_in"], rows[0]["tokens_out"], rows[0]["usd"]) == (1200, 100, 0.0068)


# ------------------------------------------------------------------ zero secret leakage
def test_no_secret_leak_anywhere(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", SECRET)
    s = mk_settings(tmp_path, "anthropic", SECRET)
    (tmp_path / ".env").write_text(f"ANTHROPIC_API_KEY={SECRET}\n")
    w = Web(s)
    o = Orchestrator(replace(s, provider="offline"))
    # a provider error string that (hypothetically) echoed the key must still be scrubbed
    o.cfo.record_usage("PRJ-01", LLMResult("", "offline", "m", error=f"HTTP 401 invalid key {SECRET}"))
    out = s.output_dir
    (out / "prj_01").mkdir(parents=True)
    (out / "prj_01" / "client_audit_report.md").write_text(f"# Report\nleaked {SECRET} here")
    (out / "READY_TO_SELL_NOW.md").write_text(f"# Sheet\n```text\nkey={SECRET}\n```")
    for path in ["/", "/api/state", "/api/ledger?limit=1000", "/api/sell-sheet", "/api/launch-copy", "/api/audit-report", "/api/targets",
                 "/static/app.js", "/static/app.css"]:
        r = w.get(path)
        assert SECRET not in r.text and "TESTSECRETVALUE" not in r.text, path
    assert "[redacted]" in w.get("/api/ledger").text and "[redacted]" in w.get("/api/audit-report").text
    st = w.get("/api/state").text.lower()
    assert "api_key" not in st and "apikey" not in st and "sk-ant" not in st
    for p in ["/.env", "/static/../.env", "/static/%2e%2e/.env", "/api/.env"]:
        assert w.c.get(p).status_code in (404, 405) and SECRET not in w.c.get(p).text


# ------------------------------------------------------------------ request security
def test_rejects_foreign_host_origin_and_missing_csrf(web):
    assert web.c.get("/api/state", headers={"host": "evil.example"}).status_code == 403
    assert web.c.get("/api/state", headers={"host": "127.0.0.1:9999"}).status_code == 403
    assert web.c.get("/api/state", headers={"host": "localhost:8080"}).status_code == 200
    assert web.c.post("/api/run/PRJ-04", json={}).status_code == 403                                  # no token
    assert web.c.post("/api/run/PRJ-04", json={}, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    r = web.c.post("/api/run/PRJ-04", json={}, headers={"X-CSRF-Token": web.token, "Origin": "http://evil.example"})
    assert r.status_code == 403
    assert web.c.delete("/api/targets?url=x").status_code == 403
    assert web.c.options("/api/run/PRJ-04").status_code in (403, 405)  # no CORS preflight approval
    assert web.get("/api/state").headers["cache-control"] == "no-store"


def test_serve_binds_loopback_only_and_validates_port(monkeypatch):
    import inspect
    assert wd.HOST == "127.0.0.1"
    assert "host" not in inspect.signature(wd.serve).parameters and "host" not in inspect.signature(wd.make_server).parameters
    seen = {}

    class FakeSrv:
        def serve_forever(self):
            raise KeyboardInterrupt

        def server_close(self):
            seen["closed"] = True
    monkeypatch.setattr(wd, "make_server", lambda port: seen.update(port=port) or FakeSrv())
    assert wd.serve(8123) == 0 and seen == {"port": 8123, "closed": True}
    for bad in (80, 70000):
        with pytest.raises(SystemExit):
            wd.serve(bad)


def test_serve_reports_port_in_use(monkeypatch):
    blocker = socket.socket()
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    try:
        with pytest.raises(SystemExit) as e:
            wd.serve(blocker.getsockname()[1])
        assert "cannot bind" in str(e.value)
    finally:
        blocker.close()


def test_real_http_server_roundtrip(tmp_path):
    """Actual sockets: loopback binding, headers, CSRF over the wire, body-size limit, HEAD."""
    rec = Recorder()
    srv = wd.make_server(0, settings=mk_settings(tmp_path), targets_path=tmp_path / "t.csv", executor=rec)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        host, port = srv.server_address
        assert host == "127.0.0.1"

        def call(method, path, body=None, headers=None):
            conn = http.client.HTTPConnection(host, port, timeout=10)
            conn.request(method, path, body=body, headers=headers or {})
            r = conn.getresponse()
            data = r.read()
            conn.close()
            return r, data
        r, html = call("GET", "/")
        assert r.status == 200 and r.getheader("Content-Security-Policy") and r.getheader("X-Frame-Options") == "DENY"
        token = re.search(rb'csrf-token" content="([^"]+)"', html).group(1).decode()
        r, data = call("GET", "/api/state")
        assert r.status == 200 and json.loads(data)["summary"]["seed_usd"] == 10.0
        assert call("GET", "/static/app.js")[0].getheader("Content-Type").startswith("application/javascript")
        assert call("GET", "/", headers={"Host": "evil.example"})[0].status == 403
        assert call("POST", "/api/run/PRJ-04", body=b"{}", headers={"Content-Type": "application/json"})[0].status == 403
        ok_hdr = {"Content-Type": "application/json", "X-CSRF-Token": token}
        r, data = call("POST", "/api/run/PRJ-04", body=b'{"mode": "offline"}', headers=ok_hdr)
        assert r.status == 202 and json.loads(data)["job"]["status"] in {"running", "done"}
        assert call("POST", "/api/run/PRJ-04", body=b"{not json", headers=ok_hdr)[0].status == 422
        assert call("POST", "/api/run/PRJ-04", body=b"x" * (wd.MAX_BODY + 1), headers=ok_hdr)[0].status == 413
        r, data = call("HEAD", "/api/state")
        assert r.status == 200 and data == b""
        assert call("GET", "/nope")[0].status == 404 and call("PUT", "/api/state", headers=ok_hdr)[0].status == 405
    finally:
        srv.shutdown()
        srv.server_close()


def test_internal_errors_do_not_leak_details(tmp_path, monkeypatch):
    w = Web(mk_settings(tmp_path))
    monkeypatch.setattr(w.app, "state_payload", lambda: (_ for _ in ()).throw(RuntimeError("boom " + SECRET)))
    r = w.get("/api/state")
    assert r.status_code == 500 and r.json() == {"detail": "internal error"} and SECRET not in r.text


def test_cli_web_flag(monkeypatch):
    import main
    got = {}
    monkeypatch.setattr(wd, "serve", lambda port: got.setdefault("port", port) and 0)
    assert main.main(["--web"]) == 0 and got["port"] == 8080
    got.clear()
    assert main.main(["--web", "--port", "9191"]) == 0 and got["port"] == 9191
    with pytest.raises(SystemExit) as e:
        main.main(["--web", "--port", "80"])
    assert e.value.code == 2


# ------------------------------------------------------------------ running projects
def test_offline_run_updates_state_and_costs_nothing(web):
    job = web.wait(web.post("/api/run/prj-04", {"mode": "offline"}))  # id is case-insensitive
    assert job["status"] == "done", job
    assert job["result"]["projects"]["PRJ-04"]["ceo_status"] == "APPROVED" and job["result"]["llm"]["live_calls"] == 0
    d = web.get("/api/state").json()
    p4 = next(p for p in d["projects"] if p["id"] == "PRJ-04")
    assert p4["ceo_status"] == "APPROVED" and p4["ceo_score"] >= 95 and p4["status"] == "DRY-RUN" and p4["units"]["patches_ready"] >= 1
    assert d["summary"]["burn_usd"] == 0.0 and d["busy"] is False


def test_invalid_project_ids_are_rejected(web):
    for bad in ["PRJ-99", "nope", "PRJ-01;rm", "..%2F..%2Fetc"]:
        assert web.post(f"/api/run/{bad}", {"mode": "offline"}).status_code in (404, 405)
    assert web.post("/api/run/PRJ-99", {"mode": "live", "confirm": True, "max_spend": 0.05}).status_code == 404
    assert web.post("/api/revenue", {"project_id": "PRJ-99", "amount": 5, "confirm": True}).status_code == 404
    assert web.post("/api/run/PRJ-01", {"mode": "weird"}).status_code == 422


def test_only_one_run_at_a_time_and_mutations_blocked_while_running(tmp_path):
    rec = Recorder()
    rec.gate = threading.Event()
    w = Web(mk_settings(tmp_path), executor=rec)
    first = w.post("/api/run/PRJ-01", {"mode": "offline"})
    assert first.status_code == 202
    assert w.post("/api/run/PRJ-02", {"mode": "offline"}).status_code == 409
    assert w.post("/api/run-all", {"mode": "offline"}).status_code == 409
    assert w.post("/api/revenue", {"project_id": "PRJ-01", "amount": 5, "confirm": True}).status_code == 409
    assert w.post("/api/rebuild-sell-sheet").status_code == 409
    assert w.get("/api/state").json()["busy"] is True
    rec.gate.set()
    assert w.wait(first)["status"] == "done"
    assert w.post("/api/run/PRJ-02", {"mode": "offline"}).status_code == 202


def test_failed_job_is_reported_not_fatal(tmp_path):
    def boom(*a, **k):
        raise RuntimeError("pipeline exploded " + SECRET)
    w = Web(mk_settings(tmp_path), executor=boom)
    job = w.wait(w.post("/api/run/PRJ-01", {"mode": "offline"}))
    assert job["status"] == "failed" and "pipeline exploded" in job["error"] and SECRET not in w.get(f"/api/jobs/{job['id']}").text
    assert w.get("/api/state").status_code == 200


# ------------------------------------------------------------------ live (paid) guard rails
@pytest.fixture
def live(tmp_path):
    rec = Recorder()
    return Web(mk_settings(tmp_path, "anthropic", SECRET), executor=rec), rec


def test_live_requires_configured_key(web):
    r = web.post("/api/run/PRJ-03", {"mode": "live", "confirm": True, "max_spend": 0.05})
    assert r.status_code == 409 and "no API key" in r.json()["detail"] and SECRET not in r.text
    assert web.post("/api/run-all", {"mode": "live", "confirm": True}).status_code == 409


def test_live_requires_confirmation_and_valid_cap(live):
    w, rec = live
    assert w.post("/api/run/PRJ-03", {"mode": "live", "max_spend": 0.05}).status_code == 400                       # no confirm
    assert w.post("/api/run/PRJ-03", {"mode": "live", "confirm": False, "max_spend": 0.05}).status_code == 400
    for bad in (0, -1, 1.01, 50, 1e9):
        r = w.post("/api/run/PRJ-03", {"mode": "live", "confirm": True, "max_spend": bad})
        assert r.status_code == 422, bad
    assert w.post("/api/run/PRJ-03", {"mode": "live", "confirm": True, "max_spend": "abc"}).status_code == 422
    assert rec.calls == []  # nothing ran for any rejected request


def test_live_cap_defaults_and_pass_through(live):
    w, rec = live
    w.wait(w.post("/api/run/PRJ-03", {"mode": "live", "confirm": True}))
    w.wait(w.post("/api/run/PRJ-03", {"mode": "live", "confirm": True, "max_spend": 0.02}))
    w.wait(w.post("/api/run-all", {"mode": "live", "confirm": True}))
    w.wait(w.post("/api/run-all", {"mode": "live", "confirm": True, "max_spend": 1.0}))
    w.wait(w.post("/api/run/PRJ-03", {"mode": "offline", "max_spend": 0.5}))
    assert [(c["live"], c["max_spend"]) for c in rec.calls] == [(True, 0.05), (True, 0.02), (True, 0.10), (True, 1.0), (False, None)]
    assert rec.calls[2]["pids"] == ["PRJ-01", "PRJ-02", "PRJ-03", "PRJ-04", "PRJ-05"]


def fake_provider(monkeypatch, tin=1000, tout=500):
    calls = []

    def f(self, model, system, prompt, max_tokens):
        calls.append(model)
        return LLMResult("Hi there, the page head has render-blocking scripts. Would it help?", "anthropic", model, tin, tout, live=True)
    monkeypatch.setattr(LLMClient, "_anthropic", f)
    return calls


def test_live_run_end_to_end_enforces_max_spend_through_the_real_orchestrator(tmp_path, monkeypatch):
    calls = fake_provider(monkeypatch)  # haiku call = $0.00035, opus call = $0.014
    w = Web(mk_settings(tmp_path, "anthropic", SECRET))
    job = w.wait(w.post("/api/run/PRJ-03", {"mode": "live", "confirm": True, "max_spend": 0.05}))
    assert job["status"] == "done" and job["result"]["llm"]["live_calls"] >= 2 and job["result"]["llm"]["errors"] == 0
    burn = w.get("/api/state").json()["summary"]["burn_usd"]
    assert 0 < burn <= 0.05 and "claude-opus-5-5" in calls and "claude-haiku-5-5" in calls
    # a tiny cap lets the cheap tier through but blocks the flagship call (worst-case estimate > cap)
    before = len(calls)
    fresh = tmp_path / "second"
    fresh.mkdir()
    w2 = Web(mk_settings(fresh, "anthropic", SECRET))
    job2 = w2.wait(w2.post("/api/run/PRJ-03", {"mode": "live", "confirm": True, "max_spend": 0.005}))
    s2 = w2.get("/api/state").json()["summary"]
    assert job2["result"]["llm"]["blocked"] >= 1 and s2["burn_usd"] <= 0.005 and s2["blocked_calls"] >= 1
    assert "claude-opus-5-5" not in calls[before:]
    ledger = w2.get("/api/ledger").json()["entries"]
    assert any(e["kind"] == "blocked" and "--max-spend" in e["note"] for e in ledger)


def test_group_b_live_blocked_until_revenue_even_via_web(tmp_path, monkeypatch):
    calls = fake_provider(monkeypatch)
    w = Web(mk_settings(tmp_path, "anthropic", SECRET))
    job = w.wait(w.post("/api/run/PRJ-04", {"mode": "live", "confirm": True, "max_spend": 0.05}))
    assert job["status"] == "done" and calls == [] and job["result"]["llm"]["live_calls"] == 0


# ------------------------------------------------------------------ revenue
def test_revenue_requires_confirmation_and_unlocks_vault(web):
    assert web.post("/api/revenue", {"project_id": "PRJ-03", "amount": 39}).status_code == 400
    for bad in (0, -5, 10_000_001):
        assert web.post("/api/revenue", {"project_id": "PRJ-03", "amount": bad, "confirm": True}).status_code == 422
    r = web.post("/api/revenue", {"project_id": "prj-03", "amount": 39, "note": "first sale", "confirm": True})
    assert r.status_code == 200 and r.json()["logged"] == {"project_id": "PRJ-03", "amount": 39.0}
    s = web.get("/api/state").json()
    assert s["summary"]["vault_locked"] is False and s["summary"]["vault_released_to"] == "PRJ-03"
    assert next(p for p in s["projects"] if p["id"] == "PRJ-03")["quota_usd"] == pytest.approx(5.0)
    assert s["summary"]["ceiling_usd"] == 10.0  # revenue never raises the hard cap


# ------------------------------------------------------------------ targets manager
def test_targets_crud_validation_and_csv(web):
    assert web.get("/api/targets").json()["targets"] == []
    r = web.post("/api/targets", {"url": "example.com/", "ceo": "  Dana   Lee ", "company": "Example  Inc"})
    assert r.status_code == 201 and r.json()["targets"] == [{"url": "https://example.com/", "ceo": "Dana Lee", "company": "Example Inc"}]
    assert web.post("/api/targets", {"url": "https://EXAMPLE.com"}).status_code == 409                    # duplicate (normalised)
    for bad in ({"url": "javascript:alert(1)"}, {"url": "ftp://x.com"}, {"url": "https://user:pw@x.com"}, {"url": "localhost"},
                {"url": ""}, {"url": "https://ok.com", "ceo": "=HYPERLINK(1)"}, {"url": "https://ok2.com", "company": "@evil"},
                {"url": "https://ok3.com", "ceo": "x" * 61}):
        assert web.post("/api/targets", bad).status_code == 422, bad
    web.post("/api/targets", {"url": "https://b.com", "company": "B, Inc."})
    with web.targets.open(newline="") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["url", "ceo", "company"] and rows[2] == ["https://b.com", "there", "B, Inc."]
    assert web.delete("/api/targets?url=https://example.com").status_code == 200
    assert web.delete("/api/targets?url=https://nope.com").status_code == 404
    assert [t["url"] for t in web.get("/api/targets").json()["targets"]] == ["https://b.com"]


def test_targets_list_is_bounded(web):
    wd_max = wd.MAX_TARGETS
    wd.write_targets(web.targets, [{"url": f"https://s{i}.com", "ceo": "there", "company": ""} for i in range(wd_max)])
    assert web.post("/api/targets", {"url": "https://onemore.com"}).status_code == 422


def test_audit_targets_guard_rails_and_wiring(tmp_path):
    rec = Recorder()
    w = Web(mk_settings(tmp_path, "anthropic", SECRET), executor=rec)
    assert w.post("/api/targets/audit", {"confirm": True}).status_code == 422                       # empty list
    w.post("/api/targets", {"url": "https://a.com", "ceo": "Ann", "company": "A"})
    assert w.post("/api/targets/audit", {}).status_code == 400                                     # needs confirm
    assert w.post("/api/targets/audit", {"confirm": True, "max_spend": 5}).status_code == 422
    job = w.wait(w.post("/api/targets/audit", {"confirm": True}))
    assert rec.calls == [{"pids": ["PRJ-03"], "live": True, "max_spend": 0.10, "env": {"TARGETS_FILE": str(w.targets)}}]
    assert job["result"]["sell_sheet"].startswith("not rebuilt - missing")  # no PRJ-01/02 artifacts in this sandbox
    offline = Web(mk_settings(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path), executor=Recorder())
    offline.post("/api/targets", {"url": "https://a.com"})
    assert offline.post("/api/targets/audit", {"confirm": True}).status_code == 409                 # no key configured


# ------------------------------------------------------------------ artifacts, sell sheet, downloads
def test_artifact_endpoints_when_nothing_generated(web):
    for path in ("/api/sell-sheet", "/api/launch-copy", "/api/audit-report"):
        d = web.get(path).json()
        assert d["exists"] is False and "<p" in d["html"]
    assert web.get("/api/launch-copy").json()["zip"]["exists"] is False
    assert web.get("/api/download/extension").status_code == 404
    r = web.post("/api/rebuild-sell-sheet")
    assert r.status_code == 409 and "missing" in r.json()["detail"]


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    """Real PRJ-01 + PRJ-02 offline artifacts, plus a hand-written PRJ-03 batch, then a real sell-sheet rebuild."""
    tmp = tmp_path_factory.mktemp("built")
    w = Web(mk_settings(tmp))
    for pid in ("PRJ-01", "PRJ-02"):
        assert w.wait(w.post(f"/api/run/{pid}", {"mode": "offline"}))["status"] == "done"
    f = {"detail": "10 render-blocking scripts in the page head.", "keyword": "blocking scripts", "area": "speed", "severity": 2, "short": "10 scripts"}
    batch = [{"url": "https://acme.test/", "company": "Acme", "ceo": "there", "ready": True, "scores": {"overall": 80}, "outreach_words": 40,
              "outreach": "Hi there,\n\nYour page head has 10 render-blocking scripts <script>alert(1)</script>.\n\nWorth a look?\n\nAlex",
              "outreach_findings": [f], "findings": [f]}]
    (w.settings.output_dir / "PRJ-03").mkdir(parents=True, exist_ok=True)
    (w.settings.output_dir / "PRJ-03" / "outreach_batch.json").write_text(json.dumps(batch))
    r = w.post("/api/rebuild-sell-sheet")
    assert r.status_code == 200, r.text
    return w


def test_rebuild_sell_sheet_and_serving(built):
    w = built
    assert (w.settings.output_dir / "READY_TO_SELL_NOW.md").exists() and (w.settings.output_dir / "prj_02" / "LAUNCH_COPY.md").exists()
    d = w.get("/api/sell-sheet").json()
    assert d["exists"] and "READY TO SELL NOW" in d["markdown"] and "<h1>" in d["html"]
    assert 'class="copy-btn"' in d["html"] and "Copy message" in d["html"]            # one-click copy for each message
    assert "<script>alert(1)</script>" not in d["html"] and "&lt;script&gt;" in d["html"]  # scraped text can't inject HTML
    assert "Hi there," in d["markdown"] and w.get("/api/state").json()["artifacts"]["sell_sheet"] is True


def test_launch_copy_audit_report_and_zip_download(built):
    w = built
    lc = w.get("/api/launch-copy").json()
    assert lc["exists"] and "Offline CRM Clipper" in lc["markdown"] and "$39" in lc["markdown"] and lc["zip"]["exists"] and lc["zip"]["size"] > 1000
    assert "Legacy Modernization Audit" in w.get("/api/audit-report").json()["markdown"]
    r = w.get("/api/download/extension")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert "crm_clipper_extension.zip" in r.headers["content-disposition"]
    import io
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert "manifest.json" in names and "db.js" in names                                  # real, publishable package
    assert w.get("/api/state").json()["artifacts"]["extension_zip"] is True


# ------------------------------------------------------------------ markdown renderer
def test_markdown_is_escape_first_and_safe():
    html = render_markdown('# T <script>x</script>\n\n[bad](javascript:alert(1)) [ok](https://a.com/?q=1&r=2) <img src=x onerror=alert(1)>\n\n'
                           '| a | b |\n|---|---|\n| <b>1</b> | `<i>2</i>` |\n')
    assert "<script" not in html and "onerror=" not in html.replace("&lt;img src=x onerror=alert(1)&gt;", "")
    assert 'href="javascript' not in html and 'href="https://a.com/?q=1&amp;r=2"' in html and 'rel="noopener noreferrer"' in html
    assert "<table>" in html and "&lt;b&gt;1&lt;/b&gt;" in html and "<code>&lt;i&gt;2&lt;/i&gt;</code>" in html


def test_markdown_structures_and_copy_buttons():
    html = render_markdown("## H\n\n- one\n  - nested\n- [ ] todo\n- [x] done\n\n1. a\n2. b\n\n> quote\n\n---\n\n```text\nHello <b>\nworld\n```\n\n```python\nx = 1\n```\n")
    assert "<h2>H</h2>" in html and "<li>one<ul><li>nested</li></ul></li>" in html and "☐ todo" in html and "☑ done" in html
    assert "<ol><li>a</li><li>b</li></ol>" in html and "<blockquote>quote</blockquote>" in html and "<hr>" in html
    assert 'data-copy="code">Copy message</button>' in html and 'data-copy="code">Copy</button>' in html
    assert "Hello &lt;b&gt;\nworld" in html
    assert render_markdown("```text\nunclosed").count("<pre>") == 1  # an unclosed fence cannot break the page


# ------------------------------------------------------------------ environment problems are explained, not mysterious
def test_missing_pytest_is_reported_clearly(tmp_path, monkeypatch):
    import importlib.util
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec", lambda name, *a, **k: None if name == "pytest" else real(name, *a, **k))
    w = Web(mk_settings(tmp_path))
    warns = w.get("/api/state").json()["warnings"]
    assert warns and "pip install pytest" in warns[0]


def test_no_warnings_when_environment_is_healthy(web):
    assert web.get("/api/state").json()["warnings"] == []


def test_run_pytest_names_the_missing_module(tmp_path, monkeypatch):
    from projects.common import run_pytest
    fake = tmp_path / "fakepath"
    fake.mkdir()
    (fake / "pytest.py").write_text("raise ModuleNotFoundError(\"No module named 'pytest'\")\n")
    monkeypatch.setenv("PYTHONPATH", str(fake))
    passed, total, detail = run_pytest(tmp_path, cwd=tmp_path)
    assert (passed, total) == (0, 0) and "pip install pytest" in detail
