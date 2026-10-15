"""Local web command center for the agency (FastAPI, bound to 127.0.0.1 only).

    python main.py --web [--port 8080]      ->  http://127.0.0.1:8080

Security model (this server can spend real money, so it is locked down even though it is local-only):
  * binds strictly to 127.0.0.1 - there is no way to pass another host;
  * Host header must be 127.0.0.1/localhost:<port> (blocks DNS-rebinding) and any Origin must match;
  * every state-changing request needs a per-process CSRF token that only the served page can read;
  * live (paid) runs additionally require `confirm: true` and a per-click `max_spend` (server-side ceiling),
    on top of the CFO's sub-budgets and the $10 hard cap;
  * secrets are never read into responses: API keys / key-shaped strings are scrubbed from every payload and no
    endpoint serves .env or arbitrary paths (artifacts are served from a fixed allowlist);
  * markdown is rendered server-side by an escape-first renderer; the page ships its own CSS/JS (no CDN) under a strict CSP.
"""
from __future__ import annotations

import csv
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from agents.cfo_agent import compute_summary
from config import KEY_VARS, ROOT, Settings
from orchestrator import Orchestrator
from state import PROJECT_META, AgencyState
from web_markdown import render_markdown

HOST = "127.0.0.1"  # not configurable, by design
DEFAULT_PORT = 8080
SINGLE_DEFAULT = 0.05   # default per-click cap for one project (USD)
ALL_DEFAULT = 0.10      # default cap for a live sprint / target audit (USD)
CLICK_CEILING = 1.00    # no single click may authorise more than this, whatever the client sends
WEB_DIR = ROOT / "web"
MAX_TARGETS = 200

_KEY_PATTERNS = [re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"), re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
                 re.compile(r"AIza[0-9A-Za-z_\-]{20,}")]


# ----------------------------------------------------------------------------------- secrets
def make_scrubber(settings: Settings) -> Callable[[Any], Any]:
    """Redact the configured key(s) and anything key-shaped from any JSON-like structure or string."""
    literals = {v for v in [settings.api_key, *(os.getenv(k, "") for k in KEY_VARS)] if v and len(v) >= 8}

    def scrub(obj: Any) -> Any:
        if isinstance(obj, str):
            for lit in literals:
                obj = obj.replace(lit, "[redacted]")
            for pat in _KEY_PATTERNS:
                obj = pat.sub("[redacted]", obj)
            return obj
        if isinstance(obj, dict):
            return {k: scrub(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [scrub(v) for v in obj]
        return obj
    return scrub


# ----------------------------------------------------------------------------------- jobs
class Busy(RuntimeError):
    pass


@dataclass
class Job:
    id: str
    kind: str
    label: str
    mode: str
    max_spend: float | None
    status: str = "running"
    started: float = field(default_factory=time.time)
    finished: float | None = None
    result: dict | None = None
    error: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label, "mode": self.mode, "max_spend": self.max_spend,
                "status": self.status, "started": self.started, "finished": self.finished,
                "elapsed": round((self.finished or time.time()) - self.started, 2), "result": self.result, "error": self.error}


class JobManager:
    """One mutating operation at a time: the state file has a single writer, so runs, revenue logging and sell-sheet
    rebuilds are mutually exclusive."""

    def __init__(self) -> None:
        self._op = threading.Lock()
        self._guard = threading.Lock()
        self.jobs: dict[str, Job] = {}
        self.current: Job | None = None

    @contextmanager
    def exclusive(self):
        if not self._op.acquire(blocking=False):
            raise Busy("another operation is running")
        try:
            yield
        finally:
            self._op.release()

    def submit(self, kind: str, label: str, mode: str, max_spend: float | None, fn: Callable[[], dict]) -> Job:
        if not self._op.acquire(blocking=False):
            raise Busy("another run is in progress")
        job = Job(uuid.uuid4().hex[:12], kind, label, mode, max_spend)
        with self._guard:
            self.jobs[job.id] = job
            self.current = job
            for old in list(self.jobs)[:-25]:
                del self.jobs[old]

        def work() -> None:
            try:
                job.result = fn()
                job.status = "done"
            except Exception as exc:  # surfaced to the UI; never crashes the server
                job.status, job.error = "failed", f"{type(exc).__name__}: {exc}"
            finally:
                job.finished = time.time()
                self._op.release()
        threading.Thread(target=work, daemon=True, name=f"job-{job.id}").start()
        return job

    def running(self) -> Job | None:
        return self.current if self.current and self.current.status == "running" else None


# ----------------------------------------------------------------------------------- request bodies
class RunBody(BaseModel):
    mode: Literal["offline", "live"] = "offline"
    max_spend: float | None = None
    confirm: bool = False


class RevenueBody(BaseModel):
    project_id: str
    amount: float
    note: str = ""
    confirm: bool = False


class TargetBody(BaseModel):
    url: str
    ceo: str = "there"
    company: str = ""


class AuditBody(BaseModel):
    max_spend: float | None = None
    confirm: bool = False
    rebuild: bool = True


# ----------------------------------------------------------------------------------- targets.csv
_FORMULA = re.compile(r"^[=+\-@\t\r]")


def clean_target(t: TargetBody) -> dict:
    url = t.url.strip()
    if url and "://" not in url:
        url = "https://" + url
    p = urllib.parse.urlparse(url)
    if p.scheme not in {"http", "https"} or not p.hostname or "." not in p.hostname:
        raise HTTPException(422, "url must be a public http(s) address, e.g. https://example.com")
    if p.username or p.password:
        raise HTTPException(422, "credentials in URLs are not allowed")
    if len(url) > 300:
        raise HTTPException(422, "url too long")
    ceo = " ".join(t.ceo.split()) or "there"
    company = " ".join(t.company.split())
    for name, v, limit in (("ceo", ceo, 60), ("company", company, 80)):
        if len(v) > limit:
            raise HTTPException(422, f"{name} too long (max {limit})")
        if _FORMULA.match(v):
            raise HTTPException(422, f"{name} must not start with = + - @ (spreadsheet formula injection)")
    return {"url": url, "ceo": ceo, "company": company}


def norm_url(u: str) -> str:
    return u.strip().lower().rstrip("/")


def read_targets(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return [{"url": (r.get("url") or "").strip(), "ceo": (r.get("ceo") or "there").strip(),
                 "company": (r.get("company") or "").strip()} for r in csv.DictReader(fh) if (r.get("url") or "").strip()]


def write_targets(path: Path, rows: list[dict]) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "ceo", "company"])
        for r in rows:
            w.writerow([r["url"], r["ceo"], r["company"]])
    os.replace(tmp, path)


# ----------------------------------------------------------------------------------- app
def summarize_ledger(entries: list[dict]) -> dict:
    api = [e for e in entries if e["kind"] == "api" and e.get("provider") != "offline"]
    return {"live_calls": len(api), "cache_hits": sum(1 for e in entries if e["kind"] == "cache_hit"),
            "blocked": sum(1 for e in entries if e["kind"] == "blocked"), "errors": sum(1 for e in entries if e.get("error")),
            "spent_usd": round(sum(e.get("usd", 0.0) for e in api), 6)}


def create_app(settings: Settings | None = None, port: int = DEFAULT_PORT, targets_path: Path | None = None,
               executor: Callable[..., dict] | None = None) -> FastAPI:
    settings = settings or Settings.load()
    targets_path = Path(targets_path or ROOT / "targets.csv")
    scrub = make_scrubber(settings)
    jobs = JobManager()
    csrf = secrets.token_urlsafe(32)
    allowed_hosts = {f"{HOST}:{port}", f"localhost:{port}"}
    allowed_origins = {f"http://{h}" for h in allowed_hosts}
    live_available = settings.provider != "offline"
    targets_lock = threading.Lock()
    app = FastAPI(title="Agency Command Center", docs_url=None, redoc_url=None, openapi_url=None)

    # -- security middleware ---------------------------------------------------------------
    @app.middleware("http")
    async def guard(request: Request, call_next):
        if request.headers.get("host", "") not in allowed_hosts:
            return JSONResponse({"detail": "forbidden host"}, status_code=403)
        if request.method not in {"GET", "HEAD"}:
            origin = request.headers.get("origin")
            if origin and origin not in allowed_origins:
                return JSONResponse({"detail": "forbidden origin"}, status_code=403)
            if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), csrf):
                return JSONResponse({"detail": "missing or invalid CSRF token"}, status_code=403)
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                                   "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def ok(data: Any, status: int = 200) -> JSONResponse:
        return JSONResponse(scrub(data), status_code=status)

    # -- data access (read-only; never touches .env) ---------------------------------------
    def snapshot() -> dict:
        p = settings.state_path
        if p.exists():
            try:
                d = json.loads(p.read_text())
                if d.get("version") and d.get("projects"):
                    return d
            except (OSError, json.JSONDecodeError):
                pass
        return AgencyState(p, settings.budget_usd).snapshot()  # first run: creates fresh state

    def cache_entries() -> int:
        try:
            return len(json.loads(settings.cache_path.read_text()))
        except (OSError, json.JSONDecodeError):
            return 0

    def out_file(*rel: str) -> Path | None:
        for r in rel:
            p = settings.output_dir / r
            if p.is_file():
                return p
        return None

    def state_payload() -> dict:
        snap = snapshot()
        summ = compute_summary(snap)
        ledger = snap.get("ledger", [])
        v = snap.get("vault", {})
        ls = summarize_ledger(ledger)
        projects = []
        for pid, p in snap["projects"].items():
            status = p["cfo_status"] if p["cfo_status"] in {"DRY-RUN", "BREAKER", "OVER BUDGET"} else p["ceo_status"]
            projects.append({
                "id": pid, "name": p["name"], "group": p["group"],
                "group_label": "Group A: Cash Cow" if p["group"] == "A" else "Group B: Reinvested",
                "pm": p["pm"], "spent_usd": p["spent_usd"], "quota_usd": p["quota_usd"],
                "spent_pct": round(100 * p["spent_usd"] / p["quota_usd"], 2) if p["quota_usd"] else 0,
                "ceo_score": p["ceo_score"], "ceo_status": p["ceo_status"], "cfo_status": p["cfo_status"], "status": status,
                "mode": p["mode"], "stage": p["stage"], "progress": p["progress"], "units": p.get("units", {}),
                "blockers": p["blockers"][:3], "blocked_calls": p.get("blocked_calls", 0), "cache_hits": p.get("cache_hits", 0),
                "cache_saved_usd": p.get("cache_saved_usd", 0.0), "revenue_usd": p["revenue_usd"]})
        job = jobs.current
        return {
            "generated_at": time.time(),
            "summary": {**summ, "seed_remaining_pct": round(100 * summ["remaining_seed_usd"] / summ["seed_usd"], 2) if summ["seed_usd"] else 0,
                        "vault_locked": bool(v.get("locked", True)), "vault_amount": v.get("amount", 0.0),
                        "vault_released_to": v.get("released_to"), "cache_entries": cache_entries(),
                        "llm_errors": snap.get("llm_errors", 0), "live_calls": ls["live_calls"],
                        "cached_calls": summ["cache_hits"]},
            "projects": projects, "live_available": live_available,
            "limits": {"single_default": SINGLE_DEFAULT, "all_default": ALL_DEFAULT, "click_ceiling": CLICK_CEILING},
            "job": job.to_dict() if job else None, "busy": jobs.running() is not None,
            "artifacts": {"sell_sheet": out_file("READY_TO_SELL_NOW.md") is not None,
                          "extension_zip": out_file("prj_02/crm_clipper_extension.zip", "PRJ-02/crm_clipper_extension.zip") is not None},
        }

    # -- execution -------------------------------------------------------------------------
    def default_executor(pids: list[str], live: bool, max_spend: float | None, env: dict | None = None) -> dict:
        s = settings if live else replace(settings, provider="offline")
        saved = {k: os.environ.get(k) for k in (env or {})}
        os.environ.update(env or {})
        try:
            orch = Orchestrator(s)
            if live and max_spend is not None:
                orch.cfo.set_run_cap(max_spend)
            start = len(orch.state.snapshot()["ledger"])
            orch.run_sprint(pids)
            snap = orch.state.snapshot()
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        return {"projects": {pid: {"ceo_status": snap["projects"][pid]["ceo_status"], "ceo_score": snap["projects"][pid]["ceo_score"],
                                   "cfo_status": snap["projects"][pid]["cfo_status"], "blockers": snap["projects"][pid]["blockers"][:3]}
                             for pid in pids},
                "llm": summarize_ledger(snap["ledger"][start:])}

    run = executor or default_executor

    def project_or_404(pid: str) -> str:
        pid = pid.upper()
        if pid not in PROJECT_META:
            raise HTTPException(404, f"unknown project '{pid[:20]}'")
        return pid

    def live_guard(mode: str, confirm: bool, max_spend: float | None, default: float) -> float | None:
        """Server-side enforcement of the paid-run rules (the UI prompt is a convenience, not the control)."""
        if mode != "live":
            return None
        if not live_available:
            raise HTTPException(409, "Live mode unavailable: no API key is configured (set it in .env and restart)")
        if not confirm:
            raise HTTPException(400, "Live runs spend real money: resend with confirm=true after confirming with the user")
        spend = default if max_spend is None else max_spend
        if not (0 < spend <= CLICK_CEILING):
            raise HTTPException(422, f"max_spend must be > 0 and <= ${CLICK_CEILING:.2f} per click")
        return round(spend, 4)

    def submit(kind: str, label: str, mode: str, cap: float | None, fn: Callable[[], dict]) -> JSONResponse:
        try:
            job = jobs.submit(kind, label, mode, cap, fn)
        except Busy:
            raise HTTPException(409, "A run is already in progress - wait for it to finish")
        return ok({"job": job.to_dict()}, 202)

    # -- routes ----------------------------------------------------------------------------
    @app.get("/", response_class=HTMLResponse)
    def index():
        return HTMLResponse((WEB_DIR / "index.html").read_text().replace("{{CSRF_TOKEN}}", csrf))

    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

    @app.get("/api/state")
    def api_state():
        return ok(state_payload())

    @app.get("/api/ledger")
    def api_ledger(limit: int = 200):
        limit = max(1, min(limit, 1000))
        entries = [e for e in snapshot().get("ledger", []) if e.get("kind") in {"api", "cache_hit", "blocked", "vault_release", "reinvest"}]
        rows = [{"t": e["t"], "project": e.get("project", "-"), "kind": e["kind"], "provider": e.get("provider", ""),
                 "model": e.get("model", ""), "tier": e.get("tier"), "tokens_in": e.get("tokens_in", 0),
                 "tokens_out": e.get("tokens_out", 0), "usd": e.get("usd", 0.0), "saved_usd": e.get("saved_usd", 0.0),
                 "note": e.get("error") or e.get("reason") or ""} for e in reversed(entries[-limit:])]
        return ok({"entries": rows, "total": len(entries)})

    @app.get("/api/jobs/{job_id}")
    def api_job(job_id: str):
        job = jobs.jobs.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        return ok({"job": job.to_dict()})

    @app.post("/api/run/{project_id}")
    def api_run(project_id: str, body: RunBody):
        pid = project_or_404(project_id)
        cap = live_guard(body.mode, body.confirm, body.max_spend, SINGLE_DEFAULT)
        return submit("run", f"{pid} ({body.mode})", body.mode, cap, lambda: run([pid], body.mode == "live", cap))

    @app.post("/api/run-all")
    def api_run_all(body: RunBody):
        cap = live_guard(body.mode, body.confirm, body.max_spend, ALL_DEFAULT)
        pids = list(PROJECT_META)
        return submit("run-all", f"all projects ({body.mode})", body.mode, cap, lambda: run(pids, body.mode == "live", cap))

    @app.post("/api/revenue")
    def api_revenue(body: RevenueBody):
        pid = project_or_404(body.project_id)
        if not body.confirm:
            raise HTTPException(400, "Revenue unlocks the reserve vault: resend with confirm=true once it is verified")
        if not (0 < body.amount <= 10_000_000):
            raise HTTPException(422, "amount must be > 0 and <= 10,000,000")
        try:
            with jobs.exclusive():
                orch = Orchestrator(replace(settings, provider="offline"))
                orch.cfo.log_revenue(pid, round(body.amount, 2), body.note[:200])
        except Busy:
            raise HTTPException(409, "A run is in progress - wait for it to finish")
        return ok({"logged": {"project_id": pid, "amount": round(body.amount, 2)}, "state": state_payload()})

    @app.post("/api/rebuild-sell-sheet")
    def api_rebuild():
        from tools.build_ready_to_sell import MissingArtifacts, build
        try:
            with jobs.exclusive():
                result = build(settings)
        except Busy:
            raise HTTPException(409, "A run is in progress - wait for it to finish")
        except MissingArtifacts as exc:
            raise HTTPException(409, f"Cannot build the sell sheet yet - {exc}")
        return ok({"path": "output/READY_TO_SELL_NOW.md", "outreach_ready": result["outreach_ready"]})

    def doc(rel: list[str], missing_hint: str) -> JSONResponse:
        p = out_file(*rel)
        if not p:
            return ok({"exists": False, "html": f"<p class='muted'>{missing_hint}</p>", "markdown": ""})
        text = scrub(p.read_text(errors="replace"))
        return ok({"exists": True, "markdown": text, "html": render_markdown(text), "updated": p.stat().st_mtime})

    @app.get("/api/sell-sheet")
    def api_sell_sheet():
        return doc(["READY_TO_SELL_NOW.md"], "No sell sheet yet - run the projects, then click <b>Rebuild Master Sell Sheet</b>.")

    @app.get("/api/launch-copy")
    def api_launch_copy():
        z = out_file("prj_02/crm_clipper_extension.zip", "PRJ-02/crm_clipper_extension.zip")
        r = json.loads(doc(["prj_02/LAUNCH_COPY.md", "PRJ-02/LAUNCH_COPY.md"], "Run PRJ-02 to generate the launch kit.").body)
        r["zip"] = {"exists": bool(z), "size": z.stat().st_size if z else 0, "name": "crm_clipper_extension.zip"}
        return ok(r)

    @app.get("/api/audit-report")
    def api_audit_report():
        return doc(["prj_01/client_audit_report.md", "PRJ-01/client_audit_report.md"], "Run PRJ-01 to generate the audit report.")

    @app.get("/api/download/extension")
    def api_download_extension():
        z = out_file("prj_02/crm_clipper_extension.zip", "PRJ-02/crm_clipper_extension.zip")
        if not z:
            raise HTTPException(404, "extension zip not built yet - run PRJ-02")
        return FileResponse(z, media_type="application/zip", filename="crm_clipper_extension.zip")

    @app.get("/api/targets")
    def api_targets():
        with targets_lock:
            return ok({"targets": read_targets(targets_path), "max": MAX_TARGETS})

    @app.post("/api/targets")
    def api_add_target(body: TargetBody):
        row = clean_target(body)
        with targets_lock:
            rows = read_targets(targets_path)
            if len(rows) >= MAX_TARGETS:
                raise HTTPException(422, f"target list is full ({MAX_TARGETS})")
            if any(norm_url(r["url"]) == norm_url(row["url"]) for r in rows):
                raise HTTPException(409, "that URL is already in the list")
            rows.append(row)
            write_targets(targets_path, rows)
        return ok({"targets": rows}, 201)

    @app.delete("/api/targets")
    def api_delete_target(url: str):
        with targets_lock:
            rows = read_targets(targets_path)
            keep = [r for r in rows if norm_url(r["url"]) != norm_url(url)]
            if len(keep) == len(rows):
                raise HTTPException(404, "no such target")
            write_targets(targets_path, keep)
        return ok({"targets": keep})

    @app.post("/api/targets/audit")
    def api_audit_targets(body: AuditBody):
        with targets_lock:
            rows = read_targets(targets_path)
        if not rows:
            raise HTTPException(422, "add at least one target first")
        cap = live_guard("live", body.confirm, body.max_spend, ALL_DEFAULT)

        def work() -> dict:
            result = run(["PRJ-03"], True, cap, {"TARGETS_FILE": str(targets_path)})
            if body.rebuild:
                from tools.build_ready_to_sell import MissingArtifacts, build
                try:
                    build(settings)
                    result["sell_sheet"] = "rebuilt"
                except MissingArtifacts as exc:
                    result["sell_sheet"] = f"not rebuilt - {exc}"
            return result
        return submit("audit-targets", f"audit {len(rows)} targets (live)", "live", cap, work)

    return app


def serve(port: int = DEFAULT_PORT) -> int:
    """Start the dashboard. The host is fixed to 127.0.0.1."""
    if not (1024 <= port <= 65535):
        raise SystemExit("--port must be between 1024 and 65535")
    import uvicorn
    app = create_app(port=port)
    print(f"Agency Command Center: http://{HOST}:{port}   (localhost only - Ctrl+C to stop)")
    try:
        uvicorn.run(app, host=HOST, port=port, log_level="warning")
    except OSError as exc:
        raise SystemExit(f"cannot bind {HOST}:{port}: {exc}")
    return 0
