"""The AI COO daemon: runs the agency on a schedule and keeps the owner in the loop over Telegram.

Autonomy levels (the owner never has to be at the phone for the first two):
  * $0 work (offline templates, or the free lane)  -> runs by itself every DAEMON_CYCLE_HOURS
  * anything that could spend real money           -> only after the owner taps "Approve" on a proposal (hard cap per cycle,
                                                      plus a daily cap that also covers the COO's own briefings)
  * sending a message to a prospect                -> never automatic: on approval the messages are delivered to the owner's
                                                      chat for review and manual sending
A "No" never stops the agency: it runs the $0 version of the same cycle instead. Everything the daemon decides is a fixed rule;
model output is only ever text in a briefing.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import signal
import sys
import time
import traceback
from dataclasses import replace
from pathlib import Path

from agents.coo_agent import COOAgent, clean, local_midnight, spent_since
from agents.growth_agent import GrowthAgent
from ops.lock import RunLock
from ops.telegram import Telegram, TelegramError
from orchestrator import Orchestrator
from state import PROJECT_META, AgencyState

LOCK_NAME = "agency.lock"
HELP = ("AI COO commands\n"
        "/status  quick facts (no cost)\n"
        "/report  full briefing with analysis\n"
        "/run  run a cycle now ($0 ones start at once; paid ones ask you first)\n"
        "/decisions  what is waiting for your answer\n"
        "/sent N  add N to messages you sent\n"
        "/replies N  add N to replies received\n"
        "/revenue PRJ-02 39 note  log verified revenue (asks you to confirm)\n"
        "/pause  /resume  stop or restart the schedule")


def in_quiet(spec: str, now: float) -> bool:
    try:
        a, b = (int(x) for x in spec.split("-"))
    except (ValueError, AttributeError):
        return False
    h = time.localtime(now).tm_hour
    return (a <= h < b) if a <= b else (h >= a or h < b)


def batch_id(items: list[dict]) -> str:
    return hashlib.sha1("|".join(sorted(i["url"] for i in items)).encode()).hexdigest()[:10]


class Daemon:
    def __init__(self, settings, tg: Telegram | None = None, clock=time.time, orch_factory=Orchestrator, log=print):
        self.s, self.tg, self.clock, self.orch_factory, self.log = settings, tg, clock, orch_factory, log
        self.coo = COOAgent(settings)
        self.lock = RunLock(Path(settings.state_path).parent / LOCK_NAME)
        self.stop = False
        self._hb = 0.0

    # -- state -----------------------------------------------------------------------------
    def store(self) -> AgencyState:
        """A fresh view of the state file. The daemon is single-threaded and holds the run lock while an orchestrator writes,
        so no two live AgencyState objects ever write concurrently."""
        return AgencyState(self.s.state_path, self.s.budget_usd)

    def ops(self) -> dict:
        return self.store().snapshot().get("ops", {})

    def ops_update(self, fn) -> None:
        def f(d):
            fn(d.setdefault("ops", {}))
        self.store().update(f)

    # -- messaging -------------------------------------------------------------------------
    def send(self, text: str, buttons=None, interactive: bool = False) -> int | None:
        self.log(text.splitlines()[0][:120] if text else "")
        if not self.tg:
            return None
        silent = (not interactive) and in_quiet(self.s.daemon_quiet_hours, self.clock())
        try:
            return self.tg.send(text, buttons=buttons, silent=silent)
        except TelegramError as exc:
            self.log(f"telegram send failed: {exc}")
            return None

    # -- planning --------------------------------------------------------------------------
    def daily_left(self) -> float:
        snap = self.store().snapshot()
        return round(self.s.daemon_daily_cap_usd - spent_since(snap, local_midnight(self.clock())), 6)

    def plan_cycle(self) -> tuple[str, str]:
        """('offline' | 'free' | 'paid', why). 'paid' is the only kind that needs the owner's approval."""
        if self.s.provider == "offline":
            return "offline", "no API key configured: deterministic templates ($0)"
        if self.s.provider == "free":
            return "free", "free-tier providers only ($0)"
        pol = GrowthAgent(self.store(), self.s, readonly=True).assess()
        if pol["mode"] == "free":
            return "free", f"PM-06 free lane: {pol['reason']}"
        if self.daily_left() <= 0.002:
            return "free", f"today's ${self.s.daemon_daily_cap_usd:.2f} spending cap is used up"
        return "paid", "paid model quality available within the caps"

    def cooling(self, ptype: str) -> bool:
        return self.ops().get("reject_until", {}).get(ptype, 0) > self.clock()

    def pending(self, ptype: str | None = None) -> list[dict]:
        return [p for p in self.ops().get("proposals", {}).values()
                if p["status"] == "pending" and (ptype is None or p["type"] == ptype)]

    def propose(self, ptype: str, text: str, payload: dict, yes: str, no: str) -> str:
        pid = secrets.token_hex(4)
        mid = self.send(text, buttons=[[(yes, f"p:{pid}:y"), (no, f"p:{pid}:n")]])

        def f(o):
            o.setdefault("proposals", {})[pid] = {"id": pid, "type": ptype, "t": self.clock(), "status": "pending",
                                                  "message_id": mid, "text": text[:600], "payload": payload}
            for old in sorted(o["proposals"], key=lambda k: o["proposals"][k]["t"])[:-30]:
                del o["proposals"][old]  # bounded history
        self.ops_update(f)
        return pid

    def expire(self) -> None:
        ttl, now, gone = self.s.daemon_proposal_ttl_hours * 3600, self.clock(), []

        def f(o):
            for p in o.get("proposals", {}).values():
                if p["status"] == "pending" and now - p["t"] > ttl:
                    p["status"] = "expired"
                    gone.append(dict(p))
                    if p["type"] == "cycle_paid":  # silence counts as "not now": $0 cycles continue, ask again later
                        o.setdefault("reject_until", {})[p["type"]] = now + self.s.daemon_reject_cooldown_hours * 3600
        self.ops_update(f)
        for p in gone:
            if self.tg:
                self.tg.clear_buttons(p.get("message_id"))

    # -- cycle -----------------------------------------------------------------------------
    def run_cycle(self, kind: str, cap: float = 0.0) -> dict | None:
        if not self.lock.acquire():
            self.log("another agency run holds the lock; cycle postponed")
            return None
        t0 = self.clock()
        try:
            s = replace(self.s, provider="offline") if kind == "offline" else self.s
            orch = self.orch_factory(s)
            orch.cfo.set_run_cap(cap if kind == "paid" else 0.0)  # $0 kinds can never spend, whatever the router decides
            result = orch.run_autopilot(live=kind != "offline")
        finally:
            self.lock.release()
        ready, audited = [], 0
        if any(x["key"] == "audit" and x["status"] == "done" for x in result["steps"]):
            f = Path(self.s.output_dir) / "PRJ-03" / "outreach_batch.json"
            try:
                batch = json.loads(f.read_text())
            except (OSError, ValueError):
                batch = []
            audited = len(batch)
            ready = [{"company": clean(r.get("company") or r["url"], 60), "url": r["url"], "ceo": clean(r.get("ceo", "there"), 40),
                      "message": r["outreach"].strip()} for r in batch if r.get("ready") and r.get("outreach")]
        cycle = {**result, "kind": kind, "seconds": self.clock() - t0, "ready": ready, "audited": audited}
        failed = bool(result["failed_steps"])
        now, mx = self.clock(), self.s.daemon_max_failures

        def f(o):
            o["last_cycle_t"], o["cycles"] = now, o.get("cycles", 0) + 1
            o["failures"] = o.get("failures", 0) + 1 if failed else 0
            if o["failures"] >= mx:
                o["paused"] = True
        self.ops_update(f)
        return cycle

    def after_cycle(self, cycle: dict, title: str = "Cycle briefing") -> None:
        self.briefing(cycle, title=title)
        ops = self.ops()
        if ops.get("paused"):
            self.send(f"⛔ Paused after {ops.get('failures')} failed cycles in a row. Check the briefing above, then send /resume.")
        ready = cycle["ready"]
        if ready and batch_id(ready) not in ops.get("released", []) and not any(
                p["payload"].get("batch") == batch_id(ready) for p in self.pending("release_batch")):
            lines = [f"📨 {len(ready)} outreach message(s) passed validation:"] + [f"  {i}. {r['company']}" for i, r in enumerate(ready, 1)]
            lines.append("\nTap Release and I will send you each message here to review and send yourself. I never contact anyone.")
            self.propose("release_batch", "\n".join(lines), {"batch": batch_id(ready), "items": ready},
                         "✅ Release to me", "⏭ Skip")

    def maybe_cycle(self) -> None:
        ops = self.ops()
        if ops.get("paused") or self.clock() - ops.get("last_cycle_t", 0) < self.s.daemon_cycle_hours * 3600:
            return
        kind, why = self.plan_cycle()
        if kind == "paid":
            if self.pending("cycle_paid"):
                return  # waiting for the owner's answer
            if not self.tg:
                self.log("paid cycle needs approval but Telegram is not configured: running the $0 version instead")
                kind = "free"
            elif self.cooling("cycle_paid"):
                kind = "free"
            else:
                last = ops.get("last_cycle_spent")
                self.propose("cycle_paid",
                             f"🤖 Ready to run the next auto-pilot cycle with paid models.\nCap: ${min(self.s.daemon_live_cap_usd, self.daily_left()):.2f} "
                             f"(today's remaining allowance ${self.daily_left():.2f})." + (f" Last paid cycle cost ${last:.4f}." if last else "")
                             + "\nIf you say No, I run the $0 version instead.",
                             {}, "✅ Approve", "❌ No, use $0 mode")
                return
        cycle = self.run_cycle(kind)
        if cycle:
            self.after_cycle(cycle)

    # -- briefing --------------------------------------------------------------------------
    def analyst_llm(self):
        if self.s.provider == "offline":
            return None
        orch = self.orch_factory(self.s)
        orch.cfo.set_run_cap(min(0.005, max(0.0, self.daily_left())))  # a briefing costs at most half a cent
        return orch.pms["PRJ-03"].llm

    def briefing(self, cycle: dict | None = None, title: str = "Agency briefing", analysis: bool = True,
                 interactive: bool = False, send: bool = True) -> str:
        snap = self.store().snapshot()
        f = self.coo.facts(snap, cycle, self.clock())
        ana = None
        if analysis:
            try:
                ana = self.coo.analysis(f, self.analyst_llm())
            except Exception:  # the analyst is optional: never lose the briefing over it
                traceback.print_exc(file=sys.stderr)
                ana = (self.coo.rule_analysis(f), "rules")
        text = self.coo.render(f, ana, title)
        if cycle is not None or analysis:
            self.ops_update(lambda o: o.update(last_briefing={"t": self.clock(), "text": text}))
        if send:
            self.send(text, interactive=interactive)
        return text

    # -- telegram input --------------------------------------------------------------------
    def poll(self, timeout: int = 20) -> None:
        if not self.tg:
            return
        offset = self.ops().get("tg_offset", 0)
        for u in self.tg.updates(offset, timeout):
            self.ops_update(lambda o, n=u["update_id"] + 1: o.update(tg_offset=n))  # at-most-once: saved BEFORE acting
            if not self.tg.is_owner(u):
                self.log("ignored an update from an unpaired chat")
                continue
            try:
                if u.get("callback_query"):
                    self.on_callback(u["callback_query"])
                else:
                    self.on_text((u.get("message") or {}).get("text", ""))
            except TelegramError:
                raise
            except Exception:
                traceback.print_exc(file=sys.stderr)
                self.send("⚠️ I hit an internal error handling that. Nothing was changed; check the daemon log.", interactive=True)

    def on_callback(self, cb: dict) -> None:
        try:
            tag, pid, ans = (cb.get("data") or "").split(":")
        except ValueError:
            return self.tg.answer(cb["id"], "unknown button")
        props = self.ops().get("proposals", {})
        p = props.get(pid)
        if tag != "p" or ans not in {"y", "n"} or not p or p["status"] != "pending":
            return self.tg.answer(cb["id"], "That decision is no longer open.")
        self.tg.answer(cb["id"], "Approved" if ans == "y" else "Declined")
        self.tg.clear_buttons(p.get("message_id"))
        status = "approved" if ans == "y" else "rejected"
        self.ops_update(lambda o: o["proposals"][pid].update(status=status, answered=self.clock()))
        self.execute(p, ans == "y")

    def execute(self, p: dict, yes: bool) -> None:
        t = p["type"]
        if t == "cycle_paid":
            if not yes:
                self.ops_update(lambda o: o.setdefault("reject_until", {}).__setitem__(
                    "cycle_paid", self.clock() + self.s.daemon_reject_cooldown_hours * 3600))
                self.send("👍 No spend. Running the $0 version now.", interactive=True)
                cycle = self.run_cycle("free" if self.s.provider != "offline" else "offline")
            else:
                cap = round(min(self.s.daemon_live_cap_usd, self.daily_left()), 4)
                if cap <= 0.002:
                    self.send("Today's spending cap is already used, so I'm running the $0 version.", interactive=True)
                    cycle = self.run_cycle("free")
                else:
                    self.send(f"⏳ Running the paid cycle (hard cap ${cap:.2f})…", interactive=True)
                    cycle = self.run_cycle("paid", cap)
                    if cycle:
                        self.ops_update(lambda o: o.update(last_cycle_spent=cycle["llm"]["spent_usd"]))
            if cycle:
                self.after_cycle(cycle)
        elif t == "release_batch":
            if not yes:
                self.send("⏭ Skipped. The messages stay in the sell sheet.", interactive=True)
                return
            items = p["payload"]["items"]
            for i, r in enumerate(items, 1):
                hello = r["ceo"] + ("  (not verified: check the name before sending)" if r["ceo"].lower() == "there" else "")
                self.send(f"✉️ Message {i}/{len(items)} · {r['company']}\nTo: {r['url']}\nGreeting: {hello}\n\n{r['message']}", interactive=True)
            self.send("Reminder: add your postal address and an opt-out line; CAN-SPAM / GDPR rules apply to cold email. "
                      "After sending, tell me with /sent N, and /replies N when answers arrive.", interactive=True)

            def f(o):
                o.setdefault("released", []).append(p["payload"]["batch"])
                o["released"] = o["released"][-50:]
                fn = o.setdefault("funnel", {})
                fn["released"] = fn.get("released", 0) + len(items)
            self.ops_update(f)
        elif t == "revenue":
            if not yes:
                return self.send("Cancelled. Nothing was logged.", interactive=True)
            pl = p["payload"]
            orch = self.orch_factory(replace(self.s, provider="offline"))
            if not self.lock.acquire():
                return self.send("A cycle is running; send the /revenue command again in a minute.", interactive=True)
            try:
                orch.cfo.log_revenue(pl["project"], pl["amount"], pl.get("note", ""))
            finally:
                self.lock.release()
            self.send(f"💵 Logged ${pl['amount']:.2f} for {pl['project']}.", interactive=True)

    def on_text(self, text: str) -> None:
        parts = (text or "").strip().split()
        cmd = parts[0].split("@")[0].lower() if parts else ""
        arg = parts[1:]
        reply = lambda m: self.send(m, interactive=True)  # noqa: E731
        if cmd in {"/start", "/help"} or not cmd.startswith("/"):
            reply(HELP)
        elif cmd == "/status":
            self.briefing(analysis=False, title="Status", interactive=True)
        elif cmd == "/report":
            self.briefing(title="Report", interactive=True)
        elif cmd == "/decisions":
            pend = self.pending()
            reply("\n\n".join(f"• {p['text']}" for p in pend) if pend else "Nothing is waiting for you.")
        elif cmd == "/pause":
            self.ops_update(lambda o: o.update(paused=True))
            reply("⏸ Paused. No new cycles until /resume.")
        elif cmd == "/resume":
            self.ops_update(lambda o: o.update(paused=False, failures=0))
            reply("▶️ Resumed.")
        elif cmd == "/run":
            kind, why = self.plan_cycle()
            if kind == "paid":
                if self.pending("cycle_paid"):
                    return reply("A paid cycle is already waiting for your answer above.")
                if self.cooling("cycle_paid"):
                    self.ops_update(lambda o: o.setdefault("reject_until", {}).pop("cycle_paid", None))
                self.ops_update(lambda o: o.update(last_cycle_t=0))  # make it due now
                return self.maybe_cycle()
            reply(f"⏳ Running a {kind.upper()} cycle ($0): {why}")
            cycle = self.run_cycle(kind)
            if cycle:
                self.after_cycle(cycle)
        elif cmd in {"/sent", "/replies"}:
            try:
                n = int(arg[0])
                assert 1 <= n <= 500
            except (IndexError, ValueError, AssertionError):
                return reply(f"Usage: {cmd} N  (1-500)")
            key = "sent" if cmd == "/sent" else "replies"
            self.ops_update(lambda o: o.setdefault("funnel", {}).__setitem__(key, o.setdefault("funnel", {}).get(key, 0) + n))
            fn = self.ops().get("funnel", {})
            reply(f"Noted. Sent {fn.get('sent', 0)}, replies {fn.get('replies', 0)}.")
        elif cmd == "/revenue":
            try:
                pid, amount = arg[0].upper(), round(float(arg[1]), 2)
                assert pid in PROJECT_META and 0 < amount <= 1_000_000
            except (IndexError, ValueError, AssertionError):
                return reply("Usage: /revenue PRJ-02 39 optional note   (only money that has actually arrived)")
            note = clean(" ".join(arg[2:]), 120)
            self.propose("revenue", f"💵 Log ${amount:.2f} of VERIFIED revenue for {pid}" + (f" ({note})" if note else "")
                         + "?\nThe first Group A revenue unlocks the reserve vault.", {"project": pid, "amount": amount, "note": note},
                         "✅ Yes, it arrived", "❌ Cancel")

    # -- loop ------------------------------------------------------------------------------
    def tick(self, poll: int = 0) -> None:
        now = self.clock()
        if now - self._hb > 60:
            self._hb = now
            self.ops_update(lambda o: o.update(heartbeat=now, telegram=bool(self.tg), cycle_hours=self.s.daemon_cycle_hours))
        self.poll(poll)
        self.expire()
        self.maybe_cycle()

    def run_forever(self) -> int:
        single = RunLock(Path(self.s.state_path).parent / "daemon.lock")
        if not single.acquire():
            self.log("another daemon is already running")
            return 1
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: setattr(self, "stop", True))
        self.send(f"🟢 AI COO online. Cycle every {self.s.daemon_cycle_hours:g}h · daily cap ${self.s.daemon_daily_cap_usd:.2f} · "
                  "send /help for commands.")
        while not self.stop:
            try:
                self.tick(poll=20 if self.tg else 0)
                if not self.tg:
                    time.sleep(30)
            except TelegramError as exc:
                self.log(f"telegram: {exc}; retrying in 15s")
                time.sleep(15)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                time.sleep(30)
        self.send("🔴 AI COO stopped.")
        single.release()
        return 0
