"""Local web command center for the agency - standard library only (no FastAPI/pydantic, so it installs anywhere,
including Termux/Android where pydantic-core cannot be built).

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
import importlib.util
import inspect
import json
import os
import re
import secrets
import sys
import threading
import time
import traceback
import urllib.parse
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from agents.cfo_agent import compute_summary
from config import KEY_VARS, ROOT, Settings
from orchestrator import Orchestrator
from projects.prj_03_deal_closer import prospects
from state import PROJECT_META, AgencyState
from web_markdown import render_markdown

HOST = "127.0.0.1"  # not configurable, by design
DEFAULT_PORT = 8080
SINGLE_DEFAULT = 0.05   # default per-click cap for one project (USD)
ALL_DEFAULT = 0.10      # default cap for a live sprint / target audit (USD)
CLICK_CEILING = 1.00    # no single click may authorise more than this, whatever the client sends
WEB_DIR = ROOT / "web"
MAX_BODY = 64 * 1024
CONTENT_TYPES = {".js": "application/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}

_KEY_PATTERNS = [re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"), re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),
                 re.compile(r"AIza[0-9A-Za-z_\-]{20,}")]


class HttpError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


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
    progress: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"id": self.id, "kind": self.kind, "label": self.label, "mode": self.mode, "max_spend": self.max_spend,
                "status": self.status, "started": self.started, "finished": self.finished,
                "elapsed": round((self.finished or time.time()) - self.started, 2), "result": self.result, "error": self.error,
                "progress": self.progress}


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

    def submit(self, kind: str, label: str, mode: str, max_spend: float | None, fn: Callable[..., dict]) -> Job:
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
                job.result = fn(job) if len(inspect.signature(fn).parameters) else fn()
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


# ----------------------------------------------------------------------------------- request validation
def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _field(d: dict, name: str, kind: str, default: Any = None, required: bool = False) -> Any:
    """Typed field access: strict types (no coercion) so a malformed client can never smuggle a value past a guard."""
    if name not in d or d[name] is None:
        if required:
            raise HttpError(422, f"'{name}' is required")
        return default
    v = d[name]
    ok = {"str": isinstance(v, str), "bool": isinstance(v, bool), "num": _is_num(v)}[kind]
    if not ok:
        raise HttpError(422, f"'{name}' must be a {'number' if kind == 'num' else kind}")
    return v


@dataclass
class TargetBody:
    url: str
    ceo: str = "there"
    company: str = ""


# ----------------------------------------------------------------------------------- targets.csv (shared with the AI CEO)
MAX_TARGETS = prospects.MAX_TARGETS
norm_url, read_targets, write_targets = prospects.norm_url, prospects.read_targets, prospects.write_targets


def clean_target(t: "TargetBody") -> dict:
    try:
        return prospects.clean_row(t.url, t.ceo, t.company)
    except ValueError as exc:
        raise HttpError(422, str(exc))


def summarize_ledger(entries: list[dict]) -> dict:
    api = [e for e in entries if e["kind"] == "api" and e.get("provider") != "offline"]
    return {"live_calls": len(api), "cache_hits": sum(1 for e in entries if e["kind"] == "cache_hit"),
            "blocked": sum(1 for e in entries if e["kind"] == "blocked"), "errors": sum(1 for e in entries if e.get("error")),
            "spent_usd": round(sum(e.get("usd", 0.0) for e in api), 6)}


# ----------------------------------------------------------------------------------- app
class Req:
    def __init__(self, method: str, path: str, query: dict, headers: dict, body: bytes):
        self.method, self.path, self.query, self.headers, self.body = method, path, query, headers, body

    def json(self) -> dict:
        if not self.body:
            return {}
        try:
            d = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HttpError(422, "request body must be valid JSON")
        if not isinstance(d, dict):
            raise HttpError(422, "request body must be a JSON object")
        return d


class App:
    """Transport-independent application: `handle()` maps (method, path, headers, body) -> (status, headers, bytes)."""

    def __init__(self, settings: Settings, port: int, targets_path: Path, executor: Callable[..., dict] | None,
                 autopilot: Callable[..., dict] | None = None):
        self.settings = settings
        self.targets_path = Path(targets_path)
        self.scrub = make_scrubber(settings)
        self.jobs = JobManager()
        self.csrf = secrets.token_urlsafe(32)
        self.allowed_hosts = {f"{HOST}:{port}", f"localhost:{port}"}
        self.allowed_origins = {f"http://{h}" for h in self.allowed_hosts}
        self.live_available = settings.provider != "offline"
        self.targets_lock = threading.Lock()
        self.run = executor or self.default_executor
        self.autopilot = autopilot or self.default_autopilot
        self.routes = [
            ("GET", r"^/$", self.index), ("GET", r"^/static/([A-Za-z0-9._-]+)$", self.static),
            ("GET", r"^/api/state$", self.api_state), ("GET", r"^/api/ledger$", self.api_ledger),
            ("GET", r"^/api/jobs/([A-Za-z0-9]+)$", self.api_job),
            ("POST", r"^/api/run/([^/]+)$", self.api_run), ("POST", r"^/api/run-all$", self.api_run_all),
            ("POST", r"^/api/revenue$", self.api_revenue), ("POST", r"^/api/rebuild-sell-sheet$", self.api_rebuild),
            ("GET", r"^/api/sell-sheet$", self.api_sell_sheet), ("GET", r"^/api/launch-copy$", self.api_launch_copy),
            ("GET", r"^/api/audit-report$", self.api_audit_report), ("GET", r"^/api/download/extension$", self.api_download),
            ("GET", r"^/api/targets$", self.api_targets), ("POST", r"^/api/targets$", self.api_add_target),
            ("DELETE", r"^/api/targets$", self.api_delete_target), ("POST", r"^/api/targets/audit$", self.api_audit_targets),
            ("POST", r"^/api/targets/rotate$", self.api_rotate_targets), ("POST", r"^/api/autopilot$", self.api_autopilot)]

    # -- http plumbing ---------------------------------------------------------------------
    def handle(self, method: str, raw_path: str, headers: dict[str, str], body: bytes = b"") -> tuple[int, dict, bytes]:
        headers = {k.lower(): v for k, v in headers.items()}
        method = method.upper()
        try:
            if headers.get("host", "") not in self.allowed_hosts:
                raise HttpError(403, "forbidden host")
            if method not in {"GET", "HEAD"}:
                origin = headers.get("origin")
                if origin and origin not in self.allowed_origins:
                    raise HttpError(403, "forbidden origin")
                if not secrets.compare_digest(headers.get("x-csrf-token", ""), self.csrf):
                    raise HttpError(403, "missing or invalid CSRF token")
            parts = urllib.parse.urlsplit(raw_path)
            path = urllib.parse.unquote(parts.path)
            req = Req(method, path, dict(urllib.parse.parse_qsl(parts.query)), headers, body)
            allowed: list[str] = []
            for m, pattern, fn in self.routes:
                hit = re.match(pattern, path)
                if not hit:
                    continue
                if m == method or (method == "HEAD" and m == "GET"):
                    status, ctype, payload, extra = fn(req, *hit.groups())
                    return self._finish(status, ctype, payload, extra)
                allowed.append(m)
            if allowed:
                raise HttpError(405, "method not allowed")
            raise HttpError(404, "not found")
        except HttpError as exc:
            return self._finish(exc.status, "application/json", json.dumps({"detail": exc.detail}).encode(), {})
        except Exception:  # never leak internals (or secrets embedded in them) to the client
            traceback.print_exc(file=sys.stderr)
            return self._finish(500, "application/json", b'{"detail": "internal error"}', {})

    @staticmethod
    def _finish(status: int, ctype: str, payload: bytes, extra: dict) -> tuple[int, dict, bytes]:
        hdr = {"Content-Type": ctype, "Content-Security-Policy": (
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
            "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store", **extra}
        return status, hdr, payload

    def ok(self, data: Any, status: int = 200):
        return status, "application/json", json.dumps(self.scrub(data)).encode(), {}

    # -- data access (read-only; never touches .env) ---------------------------------------
    def snapshot(self) -> dict:
        p = self.settings.state_path
        if p.exists():
            try:
                d = json.loads(p.read_text())
                if d.get("version") and d.get("projects"):
                    return d
            except (OSError, json.JSONDecodeError):
                pass
        return AgencyState(p, self.settings.budget_usd).snapshot()  # first run: creates fresh state

    def cache_entries(self) -> int:
        try:
            return len(json.loads(self.settings.cache_path.read_text()))
        except (OSError, json.JSONDecodeError):
            return 0

    def out_file(self, *rel: str) -> Path | None:
        for r in rel:
            p = self.settings.output_dir / r
            if p.is_file():
                return p
        return None

    def state_payload(self) -> dict:
        snap = self.snapshot()
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
        job = self.jobs.current
        return {
            "generated_at": time.time(),
            "summary": {**summ, "seed_remaining_pct": round(100 * summ["remaining_seed_usd"] / summ["seed_usd"], 2) if summ["seed_usd"] else 0,
                        "vault_locked": bool(v.get("locked", True)), "vault_amount": v.get("amount", 0.0),
                        "vault_released_to": v.get("released_to"), "cache_entries": self.cache_entries(),
                        "llm_errors": snap.get("llm_errors", 0), "live_calls": ls["live_calls"],
                        "cached_calls": summ["cache_hits"]},
            "projects": projects, "live_available": self.live_available, "warnings": self.warnings(),
            "limits": {"single_default": SINGLE_DEFAULT, "all_default": ALL_DEFAULT, "click_ceiling": CLICK_CEILING},
            "job": job.to_dict() if job else None, "busy": self.jobs.running() is not None,
            "artifacts": {"sell_sheet": self.out_file("READY_TO_SELL_NOW.md") is not None,
                          "extension_zip": self.out_file("prj_02/crm_clipper_extension.zip", "PRJ-02/crm_clipper_extension.zip") is not None},
        }

    @staticmethod
    def warnings() -> list[str]:
        """Environment problems that would make every run fail - shown as a banner instead of a mystery REJECTED."""
        out = []
        if importlib.util.find_spec("pytest") is None:
            out.append("pytest is not installed, so every project will be REJECTED (they verify their own output with it). "
                       "Fix: run  pip install pytest  in the terminal, then reload.")
        return out

    # -- execution -------------------------------------------------------------------------
    def default_executor(self, pids: list[str], live: bool, max_spend: float | None, env: dict | None = None) -> dict:
        s = self.settings if live else replace(self.settings, provider="offline")
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

    def default_autopilot(self, live: bool, max_spend: float | None, discover: bool, rotate: bool, on_step=None) -> dict:
        s = self.settings if live else replace(self.settings, provider="offline")
        orch = Orchestrator(s)
        if live and max_spend is not None:
            orch.cfo.set_run_cap(max_spend)
        return orch.run_autopilot(self.targets_path, live=live, discover=discover, rotate=rotate, on_step=on_step)

    @staticmethod
    def project_or_404(pid: str) -> str:
        pid = pid.upper()
        if pid not in PROJECT_META:
            raise HttpError(404, f"unknown project '{pid[:20]}'")
        return pid

    def live_guard(self, mode: str, confirm: bool, max_spend: float | None, default: float) -> float | None:
        """Server-side enforcement of the paid-run rules (the UI prompt is a convenience, not the control)."""
        if mode != "live":
            return None
        if not self.live_available:
            raise HttpError(409, "Live mode unavailable: no API key is configured (set it in .env and restart)")
        if not confirm:
            raise HttpError(400, "Live runs spend real money: resend with confirm=true after confirming with the user")
        spend = default if max_spend is None else max_spend
        if not (0 < spend <= CLICK_CEILING):
            raise HttpError(422, f"max_spend must be > 0 and <= ${CLICK_CEILING:.2f} per click")
        return round(spend, 4)

    def submit(self, kind: str, label: str, mode: str, cap: float | None, fn: Callable[[], dict]):
        try:
            job = self.jobs.submit(kind, label, mode, cap, fn)
        except Busy:
            raise HttpError(409, "A run is already in progress - wait for it to finish")
        return self.ok({"job": job.to_dict()}, 202)

    @staticmethod
    def run_body(d: dict) -> tuple[str, float | None, bool]:
        mode = _field(d, "mode", "str", "offline")
        if mode not in {"offline", "live"}:
            raise HttpError(422, "'mode' must be 'offline' or 'live'")
        return mode, _field(d, "max_spend", "num"), _field(d, "confirm", "bool", False)

    # -- routes ----------------------------------------------------------------------------
    def index(self, req: Req):
        page = (WEB_DIR / "index.html").read_text().replace("{{CSRF_TOKEN}}", self.csrf)
        return 200, "text/html; charset=utf-8", page.encode(), {}

    def static(self, req: Req, name: str):
        p = WEB_DIR / "static" / name
        if p.suffix not in CONTENT_TYPES or not p.is_file():
            raise HttpError(404, "not found")
        return 200, CONTENT_TYPES[p.suffix], p.read_bytes(), {}

    def api_state(self, req: Req):
        return self.ok(self.state_payload())

    def api_ledger(self, req: Req):
        try:
            limit = max(1, min(int(req.query.get("limit", 200)), 1000))
        except ValueError:
            raise HttpError(422, "limit must be an integer")
        entries = [e for e in self.snapshot().get("ledger", []) if e.get("kind") in {"api", "cache_hit", "blocked", "vault_release", "reinvest"}]
        rows = [{"t": e["t"], "project": e.get("project", "-"), "kind": e["kind"], "provider": e.get("provider", ""),
                 "model": e.get("model", ""), "tier": e.get("tier"), "tokens_in": e.get("tokens_in", 0),
                 "tokens_out": e.get("tokens_out", 0), "usd": e.get("usd", 0.0), "saved_usd": e.get("saved_usd", 0.0),
                 "note": e.get("error") or e.get("reason") or ""} for e in reversed(entries[-limit:])]
        return self.ok({"entries": rows, "total": len(entries)})

    def api_job(self, req: Req, job_id: str):
        job = self.jobs.jobs.get(job_id)
        if not job:
            raise HttpError(404, "unknown job")
        return self.ok({"job": job.to_dict()})

    def api_run(self, req: Req, project_id: str):
        mode, max_spend, confirm = self.run_body(req.json())
        pid = self.project_or_404(project_id)
        cap = self.live_guard(mode, confirm, max_spend, SINGLE_DEFAULT)
        return self.submit("run", f"{pid} ({mode})", mode, cap, lambda: self.run([pid], mode == "live", cap))

    def api_run_all(self, req: Req):
        mode, max_spend, confirm = self.run_body(req.json())
        cap = self.live_guard(mode, confirm, max_spend, ALL_DEFAULT)
        pids = list(PROJECT_META)
        return self.submit("run-all", f"all projects ({mode})", mode, cap, lambda: self.run(pids, mode == "live", cap))

    def api_revenue(self, req: Req):
        d = req.json()
        pid_raw = _field(d, "project_id", "str", required=True)
        amount = _field(d, "amount", "num", required=True)
        note = _field(d, "note", "str", "")
        confirm = _field(d, "confirm", "bool", False)
        pid = self.project_or_404(pid_raw)
        if not confirm:
            raise HttpError(400, "Revenue unlocks the reserve vault: resend with confirm=true once it is verified")
        if not (0 < amount <= 10_000_000):
            raise HttpError(422, "amount must be > 0 and <= 10,000,000")
        try:
            with self.jobs.exclusive():
                orch = Orchestrator(replace(self.settings, provider="offline"))
                orch.cfo.log_revenue(pid, round(amount, 2), note[:200])
        except Busy:
            raise HttpError(409, "A run is in progress - wait for it to finish")
        return self.ok({"logged": {"project_id": pid, "amount": round(amount, 2)}, "state": self.state_payload()})

    def api_rebuild(self, req: Req):
        from tools.build_ready_to_sell import MissingArtifacts, build
        try:
            with self.jobs.exclusive():
                result = build(self.settings)
        except Busy:
            raise HttpError(409, "A run is in progress - wait for it to finish")
        except MissingArtifacts as exc:
            raise HttpError(409, f"Cannot build the sell sheet yet - {exc}")
        return self.ok({"path": "output/READY_TO_SELL_NOW.md", "outreach_ready": result["outreach_ready"]})

    def doc(self, rel: list[str], missing_hint: str) -> dict:
        p = self.out_file(*rel)
        if not p:
            return {"exists": False, "html": f"<p class='muted'>{missing_hint}</p>", "markdown": ""}
        text = self.scrub(p.read_text(errors="replace"))
        return {"exists": True, "markdown": text, "html": render_markdown(text), "updated": p.stat().st_mtime}

    def api_sell_sheet(self, req: Req):
        return self.ok(self.doc(["READY_TO_SELL_NOW.md"], "No sell sheet yet - run the projects, then click <b>Rebuild Master Sell Sheet</b>."))

    def api_launch_copy(self, req: Req):
        z = self.out_file("prj_02/crm_clipper_extension.zip", "PRJ-02/crm_clipper_extension.zip")
        r = self.doc(["prj_02/LAUNCH_COPY.md", "PRJ-02/LAUNCH_COPY.md"], "Run PRJ-02 to generate the launch kit.")
        r["zip"] = {"exists": bool(z), "size": z.stat().st_size if z else 0, "name": "crm_clipper_extension.zip"}
        return self.ok(r)

    def api_audit_report(self, req: Req):
        return self.ok(self.doc(["prj_01/client_audit_report.md", "PRJ-01/client_audit_report.md"], "Run PRJ-01 to generate the audit report."))

    def api_download(self, req: Req):
        z = self.out_file("prj_02/crm_clipper_extension.zip", "PRJ-02/crm_clipper_extension.zip")
        if not z:
            raise HttpError(404, "extension zip not built yet - run PRJ-02")
        return 200, "application/zip", z.read_bytes(), {"Content-Disposition": 'attachment; filename="crm_clipper_extension.zip"'}

    def pool_info(self) -> dict:
        audited = set(self.snapshot().get("prospects", {}).get("audited", {}))
        return prospects.pool_status(prospects.load_pool(), audited)

    def api_targets(self, req: Req):
        with self.targets_lock:
            return self.ok({"targets": read_targets(self.targets_path), "max": MAX_TARGETS, "pool": self.pool_info()})

    def api_autopilot(self, req: Req):
        d = req.json()
        mode, max_spend, confirm = self.run_body(d)
        discover, rotate = _field(d, "discover", "bool", False), _field(d, "rotate", "bool", False)
        if discover and mode != "live":
            raise HttpError(422, "discovery asks the AI for new prospects, so it needs live mode")
        cap = self.live_guard(mode, confirm, max_spend, ALL_DEFAULT)
        live = mode == "live"

        def work(job: Job) -> dict:
            return self.autopilot(live, cap, discover, rotate, lambda steps: setattr(job, "progress", [dict(x) for x in steps]))
        return self.submit("autopilot", f"AI CEO auto-pilot ({mode})", mode, cap, work)

    def api_rotate_targets(self, req: Req):
        d = req.json()
        count = _field(d, "count", "num", 5)
        discover = _field(d, "discover", "bool", False)
        if not (1 <= count <= 10 and float(count).is_integer()):
            raise HttpError(422, "count must be a whole number from 1 to 10")
        cap = self.live_guard("live", _field(d, "confirm", "bool", False), _field(d, "max_spend", "num"), 0.02) if discover else None
        try:
            with self.jobs.exclusive(), self.targets_lock:
                orch = Orchestrator(self.settings if discover else replace(self.settings, provider="offline"))
                if cap is not None:
                    orch.cfo.set_run_cap(cap)
                res = orch.ceo.dispatch_targets(self.targets_path, n=int(count), rotate=True, discover=discover,
                                                llm=orch.pms["PRJ-03"].llm if discover else None)
        except Busy:
            raise HttpError(409, "A run is in progress - wait for it to finish")
        except RuntimeError as exc:
            raise HttpError(409, str(exc))
        return self.ok({"targets": res["targets"], "note": res["note"], "source": res["source"],
                        "pool": {k: res[k] for k in ("pool", "audited_in_pool", "remaining")}})

    def api_add_target(self, req: Req):
        d = req.json()
        row = clean_target(TargetBody(url=_field(d, "url", "str", required=True), ceo=_field(d, "ceo", "str", "there"),
                                      company=_field(d, "company", "str", "")))
        with self.targets_lock:
            rows = read_targets(self.targets_path)
            if len(rows) >= MAX_TARGETS:
                raise HttpError(422, f"target list is full ({MAX_TARGETS})")
            if any(norm_url(r["url"]) == norm_url(row["url"]) for r in rows):
                raise HttpError(409, "that URL is already in the list")
            rows.append(row)
            write_targets(self.targets_path, rows)
        return self.ok({"targets": rows}, 201)

    def api_delete_target(self, req: Req):
        url = req.query.get("url", "")
        with self.targets_lock:
            rows = read_targets(self.targets_path)
            keep = [r for r in rows if norm_url(r["url"]) != norm_url(url)]
            if len(keep) == len(rows):
                raise HttpError(404, "no such target")
            write_targets(self.targets_path, keep)
        return self.ok({"targets": keep})

    def api_audit_targets(self, req: Req):
        d = req.json()
        max_spend, confirm, rebuild = _field(d, "max_spend", "num"), _field(d, "confirm", "bool", False), _field(d, "rebuild", "bool", True)
        with self.targets_lock:
            rows = read_targets(self.targets_path)
        if not rows:
            raise HttpError(422, "add at least one target first")
        cap = self.live_guard("live", confirm, max_spend, ALL_DEFAULT)

        def work() -> dict:
            result = self.run(["PRJ-03"], True, cap, {"TARGETS_FILE": str(self.targets_path)})
            if rebuild:
                from tools.build_ready_to_sell import MissingArtifacts, build
                try:
                    build(self.settings)
                    result["sell_sheet"] = "rebuilt"
                except MissingArtifacts as exc:
                    result["sell_sheet"] = f"not rebuilt - {exc}"
            return result
        return self.submit("audit-targets", f"audit {len(rows)} targets (live)", "live", cap, work)


def create_app(settings: Settings | None = None, port: int = DEFAULT_PORT, targets_path: Path | None = None,
               executor: Callable[..., dict] | None = None, autopilot: Callable[..., dict] | None = None) -> App:
    settings = settings or Settings.load()
    return App(settings, port, Path(targets_path or settings.targets_path), executor, autopilot)


# ----------------------------------------------------------------------------------- http server
class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "AgencyUI"
    sys_version = ""

    def _dispatch(self) -> None:
        try:
            length = int(self.headers.get("content-length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY:
            status, hdr, payload = App._finish(413, "application/json", b'{"detail": "request body too large"}', {})
            self.close_connection = True
        else:
            body = self.rfile.read(length) if length else b""
            status, hdr, payload = self.server.app.handle(self.command, self.path, dict(self.headers.items()), body)  # type: ignore[attr-defined]
        self.send_response(status)
        for k, v in hdr.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = do_POST = do_DELETE = do_HEAD = do_OPTIONS = do_PUT = do_PATCH = _dispatch

    def log_message(self, *args: Any) -> None:  # quiet: request lines could contain query strings
        pass


def make_server(port: int = DEFAULT_PORT, **app_kwargs: Any) -> ThreadingHTTPServer:
    """Bind a server to 127.0.0.1 (port 0 = ephemeral). The host is fixed; there is no parameter for it."""
    srv = ThreadingHTTPServer((HOST, port), _Handler)
    srv.daemon_threads = True
    srv.app = create_app(port=srv.server_address[1], **app_kwargs)  # type: ignore[attr-defined]
    return srv


def serve(port: int = DEFAULT_PORT) -> int:
    """Start the dashboard. The host is fixed to 127.0.0.1."""
    if not (1024 <= port <= 65535):
        raise SystemExit("--port must be between 1024 and 65535")
    try:
        srv = make_server(port)
    except OSError as exc:
        raise SystemExit(f"cannot bind {HOST}:{port}: {exc}")
    print(f"Agency Command Center: http://{HOST}:{port}   (localhost only - Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        srv.server_close()
    return 0
