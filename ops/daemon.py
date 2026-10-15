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
import re
import secrets
import signal
import sys
import time
import traceback
import urllib.parse
from dataclasses import replace
from pathlib import Path

from agents.coo_agent import COOAgent, clean, local_midnight, spent_since
from agents.growth_agent import GrowthAgent
from config import sender_name
from ops import sales
from ops.lock import RunLock
from ops.telegram import Telegram, TelegramError
from projects.prj_03_deal_closer import prospects
from orchestrator import Orchestrator
from state import PROJECT_META, AgencyState

LOCK_NAME = "agency.lock"
HELP = ("AI COO commands\n"
        "/status  quick facts (no cost)\n"
        "/report  full briefing with analysis\n"
        "/run  run a cycle now ($0 ones start at once; paid ones ask you first)\n"
        "/decisions  what is waiting for your answer\n"
        "/leads  every lead and its status\n"
        "/sent all | /sent Acme  mark messages you sent (starts follow-up reminders)\n"
        "/replied Acme  they answered: I send the reply kit (audit, price, payment link, draft)\n"
        "/quote Acme 120  redo the kit with your own price\n"
        "/won Acme 149  they paid: logs the revenue after you confirm\n"
        "/report Acme  the written report to deliver after payment\n"
        "/lost Acme  /optout Acme  stop contacting (optout is permanent)\n"
        "/addlead https://site.com Company  add a prospect for the next cycle\n"
        "/sent N  /replies N  (plain counters)\n"
        "/revenue PRJ-02 39 note  log other verified revenue (asks you to confirm)\n"
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
    def __init__(self, settings, tg: Telegram | None = None, clock=time.time, orch_factory=Orchestrator, log=print, fetch=None):
        self.s, self.tg, self.clock, self.orch_factory, self.log = settings, tg, clock, orch_factory, log
        if fetch is None:
            from projects.prj_03_deal_closer import b2b_sniper as bs
            fetch = bs.fetch
        self.fetch = fetch  # public-page fetcher (SSRF-guarded in production); injected in tests
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
            optout = set(self.ops().get("optout", []))
            ready = [{"company": clean(r.get("company") or r["url"], 60), "url": r["url"], "ceo": clean(r.get("ceo", "there"), 40),
                      "message": r["outreach"].strip(),
                      "findings": [{k: clean(f.get(k, ""), 160) for k in ("area", "keyword", "detail", "short")} | {"severity": int(f.get("severity", 1))}
                                   for f in (r.get("findings") or [])[:12]],
                      "score": (r.get("scores") or {}).get("overall"), "html_kb": (r.get("performance") or {}).get("html_kb"),
                      "images": (r.get("page") or {}).get("images"), "lang": ((r.get("page") or {}).get("lang") or "")[:2].lower() or ""}
                     for r in batch if r.get("ready") and r.get("outreach")
                     and sales._base_host(r["url"]) not in optout]
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
            self.release(p["payload"]["items"], p["payload"]["batch"])
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
            if pl.get("lead"):
                self.ops_update(lambda o: o.get("leads", {}).get(pl["lead"], {}).update(status="won", won_usd=pl["amount"], next_followup=None))
            self.send(f"💵 Logged ${pl['amount']:.2f} for {pl['project']}.", interactive=True)

    # -- sales: leads, release, reply kit, follow-ups --------------------------------------
    def leads(self) -> dict:
        return self.ops().get("leads", {})

    def lead_set(self, key: str, **fields) -> None:
        self.ops_update(lambda o: o["leads"][key].update(fields))

    def funnel_add(self, field: str, n: int = 1) -> None:
        self.ops_update(lambda o: o.setdefault("funnel", {}).__setitem__(field, o.setdefault("funnel", {}).get(field, 0) + n))

    def find(self, name: str) -> str | None:
        """One lead by company/domain text, or None after telling the owner why."""
        leads = self.leads()
        key, hits = sales.match_lead(leads, name)
        if key:
            return key
        if not name.strip():
            self.send("Which lead? Add the company name, e.g. /replied Acme   (see /leads).", interactive=True)
        elif hits:
            self.send("More than one lead matches: " + ", ".join(leads[k]["company"] or leads[k]["url"] for k in hits[:6]) + ". Be more specific.", interactive=True)
        else:
            self.send(f"No lead matches '{clean(name, 40)}'. See /leads.", interactive=True)
        return None

    def contact_line(self, lead: dict) -> str:
        c = lead.get("contacts") or {}
        if c.get("emails"):
            return ", ".join(c["emails"])
        if c.get("form"):
            return f"contact form {c['form']}"
        return "no public contact found: use the site's contact page, LinkedIn or a phone call"

    def translate(self, text: str, lang: str, llm) -> str | None:
        """AI translation of a validated message, accepted only if numbers and the signature survive. Always shown as unverified."""
        if llm is None or lang in {"", "en"}:
            return None
        res = llm.complete(f"Translate this business email into the language with ISO 639-1 code '{lang}'. Keep every fact, number and the "
                           f"signature name exactly as is, use Western digits, add nothing. Output only the translation.\n\n{text}",
                           system="You are a careful professional translator.", fallback="", max_tokens=500)
        out = (res.text or "").strip()
        if not (res.live and not res.error and out):
            return None
        if not set(re.findall(r"\d+", text)) <= set(re.findall(r"\d+", out)) or sender_name() not in out:
            return None
        return out

    def release(self, items: list[dict], batch: str) -> None:
        sender, address = sender_name(), self.s.sender_address
        optout = set(self.ops().get("optout", []))
        items = [r for r in items if sales._base_host(r["url"]) not in optout]
        llm = None
        if any(r.get("lang") not in {"", "en", None} for r in items):
            try:
                llm = self.analyst_llm()
            except Exception:
                traceback.print_exc(file=sys.stderr)
        for i, r in enumerate(items, 1):
            try:
                contacts = sales.discover_contacts(r["url"], self.fetch, r.get("lang", ""))
            except Exception:
                contacts = {"emails": [], "form": None, "lang": r.get("lang") or "en"}
            lead = sales.new_lead(r, self.clock()) | {"contacts": contacts, "lang": contacts["lang"]}
            hello = r["ceo"] + ("  (not verified: check the name before sending)" if r["ceo"].lower() == "there" else "")
            self.send(f"✉️ Message {i}/{len(items)} · {r['company']}\nTo: {self.contact_line(lead)}\n"
                      f"Suggested subject: {sales.suggested_subject(r['company'])}\nGreeting: {hello}\n\n"
                      f"{r['message']}{sales.compliance_footer(sender, address)}", interactive=True)
            if lead["lang"] not in {"", "en"}:
                tr = self.translate(r["message"], lead["lang"], llm)
                self.send(f"🌐 The site is in '{lead['lang']}'. " + (f"AI translation (unverified: have a native speaker check it):\n\n{tr}" if tr else
                          "No translation available right now (offline or over budget): send the English version or translate it yourself."),
                          interactive=True)
            key = prospects.norm_url(r["url"])
            self.ops_update(lambda o, k=key, l=lead: o.setdefault("leads", {}).setdefault(k, l))
        warn = "" if address else "\n⚠️ SENDER_ADDRESS is not set in .env: add your postal address, it is a legal requirement in many countries."
        self.send("Add a real contact email you found for each company (I only list role addresses published on their own site and never guess). "
                  "After sending, tell me: /sent all (or /sent Acme). When someone answers: /replied Acme. CAN-SPAM / GDPR rules apply to cold email."
                  + warn, interactive=True)

        def f(o):
            o.setdefault("released", []).append(batch)
            o["released"] = o["released"][-50:]
            fn = o.setdefault("funnel", {})
            fn["released"] = fn.get("released", 0) + len(items)
        self.ops_update(f)

    def cmd_leads(self) -> None:
        leads = self.leads()
        if not leads:
            return self.send("No leads yet. They appear here after you release a batch.", interactive=True)
        order = {"replied": 0, "quoted": 1, "sent": 2, "released": 3, "won": 4, "lost": 5, "optout": 6}
        rows = sorted(leads.values(), key=lambda l: (order.get(l["status"], 9), -l["t"]))[:40]
        lines = []
        for l in rows:
            extra = ""
            if l["status"] == "sent" and l.get("next_followup"):
                extra = f" · follow-up {time.strftime('%d %b', time.localtime(l['next_followup']))}"
            if l["status"] == "won":
                extra = f" · ${l.get('won_usd', 0):g}"
            lines.append(f"• {l['company'] or l['url']} — {l['status']}{extra}")
        self.send(f"👥 Leads ({len(leads)})\n" + "\n".join(lines), interactive=True)

    def cmd_sent(self, name: str) -> None:
        now = self.clock()
        if name.strip().lower() == "all":
            keys = [k for k, l in self.leads().items() if l["status"] == "released"]
            if not keys:
                return self.send("No unsent leads (nothing is in 'released' state).", interactive=True)
        else:
            k = self.find(name)
            if not k:
                return
            if self.leads()[k]["status"] != "released":
                return self.send(f"{self.leads()[k]['company']} is already '{self.leads()[k]['status']}'.", interactive=True)
            keys = [k]
        first = self.s.followup_days[0] * sales.DAY

        def f(o):
            for k in keys:
                o["leads"][k].update(status="sent", t_sent=now, next_followup=now + first, followups=0)
        self.ops_update(f)
        self.funnel_add("sent", len(keys))
        self.send(f"📤 Marked {len(keys)} lead(s) as sent. I'll draft a follow-up for each after {self.s.followup_days[0]:g} days of silence "
                  "(at most two). When someone replies: /replied Company.", interactive=True)

    def lead_quote(self, lead: dict, override: float | None = None) -> dict:
        return sales.quote({"findings": lead.get("findings"), "performance": {"html_kb": lead.get("html_kb")}},
                           self.s.price_report, self.s.price_hourly, self.s.price_cap, override)

    def send_kit(self, key: str, override: float | None = None) -> None:
        lead = self.leads()[key]
        q = self.lead_quote(lead, override)
        la = sales.paypal_link(self.s.paypal_me, q["report"])
        lb = None if q["custom"] else sales.paypal_link(self.s.paypal_me, q["fix"])
        top = sorted(lead.get("findings") or [], key=lambda f: -int(f.get("severity", 1)))[:5]
        lines = [f"💬 Reply kit · {lead['company'] or lead['url']}", f"{lead['url']} · score {lead.get('score', '?')}/100 · {q['issues']} issues",
                 "Top findings:"] + [f"  {i}. [{f.get('area', '')}] {f.get('detail', '')}" for i, f in enumerate(top, 1)]
        lines += ["", f"💰 Price (change it: /quote {lead['company'].split()[0] if lead['company'] else 'name'} 120)",
                  f"  Report only: ${q['report']:g}",
                  ("  Report + fixes: custom (≈%.1f h): agree scope first" % q["hours"]) if q["custom"] else
                  f"  Report + top {len(q['fixes'])} fixes: ${q['fix']:g} (≈{q['hours']:g} h at ${self.s.price_hourly:g}/h)"]
        lines += [f"  ⚠️ {n}" for n in q["notes"]]
        if not la:
            lines.append("  ⚠️ PAYPAL_ME is not set (or invalid) in .env, so the draft has no payment link yet.")
        lines += ["", f"📮 Contact: {self.contact_line(lead)}", "", "📝 Draft reply (edit before sending):", "—" * 10,
                  sales.reply_draft(lead, q, sender_name(), la, lb, self.s.delivery_days), "—" * 10]
        self.send("\n".join(lines), interactive=True)
        self.ops_update(lambda o: o["leads"][key].update(quote=q, t_quoted=self.clock(),
                                                          **({} if o["leads"][key]["status"] in {"won", "optout", "lost"} else {"status": "quoted"})))

    def cmd_replied(self, name: str) -> None:
        key = self.find(name)
        if not key:
            return
        lead = self.leads()[key]
        if lead["status"] in {"optout", "lost"}:
            return self.send(f"{lead['company']} is marked '{lead['status']}'. Not contacting them again.", interactive=True)
        if lead["status"] in {"released", "sent"}:
            self.lead_set(key, status="replied", t_replied=self.clock(), next_followup=None)
            self.funnel_add("replies")
        self.send_kit(key)

    def cmd_quote(self, name: str, amount: float | None) -> None:
        key = self.find(name)
        if key:
            self.send_kit(key, amount)

    def cmd_won(self, arg: list[str]) -> None:
        name, amount = sales.split_name_amount(arg)
        if amount is None or not 0 < amount <= 100_000:
            return self.send("Usage: /won Acme 149   (the amount that actually arrived in your PayPal)", interactive=True)
        key = self.find(name)
        if not key:
            return
        lead = self.leads()[key]
        self.propose("revenue", f"💵 Log ${amount:.2f} of VERIFIED revenue from {lead['company'] or lead['url']}?\n"
                     "Only confirm after the money shows in your PayPal.",
                     {"project": "PRJ-03", "amount": round(amount, 2), "note": clean(f"{lead['company']} audit service", 120), "lead": key},
                     "✅ Yes, it arrived", "❌ Cancel")

    def cmd_close(self, name: str, how: str) -> None:
        key = self.find(name)
        if not key:
            return
        lead = self.leads()[key]
        host = sales._base_host(lead["url"])

        def f(o):
            o["leads"][key].update(status=how, next_followup=None)
            if how == "optout" and host not in o.setdefault("optout", []):
                o["optout"].append(host)
        self.ops_update(f)
        self.send(f"Done: {lead['company'] or lead['url']} is '{how}'. " + ("It is on the do-not-contact list for good." if how == "optout" else
                  "No more follow-ups."), interactive=True)

    def cmd_client_report(self, name: str) -> None:
        key = self.find(name)
        if not key:
            return
        lead = self.leads()[key]
        md = sales.client_report(lead, sender_name())
        slug = re.sub(r"[^a-z0-9]+", "-", (lead["company"] or sales._base_host(lead["url"])).lower()).strip("-")[:50] or "client"
        out = Path(self.s.output_dir) / "PRJ-03" / "clients"
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{slug}.md").write_text(md)
        self.send(f"📄 Client report for {lead['company'] or lead['url']} (saved to output/PRJ-03/clients/{slug}.md). Review it, then send it "
                  "after payment:\n\n" + md, interactive=True)

    def cmd_addlead(self, arg: list[str]) -> None:
        if not arg:
            return self.send("Usage: /addlead https://site.com Company name", interactive=True)
        try:
            row = prospects.clean_row(arg[0], "there", " ".join(arg[1:]))
        except ValueError as exc:
            return self.send(f"Not added: {exc}", interactive=True)
        if not prospects._public_host(urllib.parse.urlparse(row["url"]).hostname or ""):
            return self.send("Not added: only public websites can be audited (no IP addresses or local hosts).", interactive=True)
        path = Path(self.s.targets_path)
        rows = prospects.read_targets(path)
        audited = set(self.store().snapshot().get("prospects", {}).get("audited", {}))
        known = {prospects.norm_url(r["url"]) for r in rows} | audited
        if prospects.norm_url(row["url"]) in known:
            return self.send("That site is already queued or was already audited.", interactive=True)
        if sum(prospects.norm_url(r["url"]) not in audited for r in rows) >= 10:
            return self.send("The queue already holds 10 un-audited targets. Wait for the next cycle (/run) first.", interactive=True)
        prospects.write_targets(path, rows + [row])
        self.send(f"➕ Added {row['company'] or row['url']}. It will be audited in the next cycle (or send /run).", interactive=True)

    def due_followups(self) -> None:
        if not self.tg:
            return  # nowhere to deliver the draft: leave it due rather than mark it done
        now, optout, sent = self.clock(), set(self.ops().get("optout", [])), 0
        for key, l in list(self.leads().items()):
            if sent >= 5 or l["status"] != "sent" or not l.get("next_followup") or l["next_followup"] > now or l.get("followups", 0) >= 2:
                continue
            if sales._base_host(l["url"]) in optout:
                self.lead_set(key, status="optout", next_followup=None)
                continue
            n = l.get("followups", 0) + 1
            days = int((now - l.get("t_sent", now)) / sales.DAY)
            mid = self.send(f"⏰ Follow-up {n}/2 due · {l['company'] or l['url']} (sent {days} days ago)\nTo: {self.contact_line(l)}\n\n"
                            + sales.followup_draft(l, n, sender_name()) + "\n" + sales.footer_tail(self.s.sender_address)
                            + "\n\nWhen they answer: /replied " + (l["company"].split()[0] if l["company"] else "name") + "   ·   not interested: /lost")
            if mid is None:
                continue  # Telegram hiccup: it stays due and is retried on the next tick
            gap = self.s.followup_days[1] * sales.DAY
            self.lead_set(key, followups=n, next_followup=(now + gap) if n < 2 else None)
            sent += 1

    def on_text(self, text: str) -> None:
        parts = (text or "").strip().split()
        cmd = parts[0].split("@")[0].lower() if parts else ""
        arg = parts[1:]
        reply = lambda m: self.send(m, interactive=True)  # noqa: E731
        if cmd in {"/start", "/help"} or not cmd.startswith("/"):
            reply(HELP)
        elif cmd == "/status":
            self.briefing(analysis=False, title="Status", interactive=True)
        elif cmd == "/report" and not arg:
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
        elif cmd == "/report" and arg:
            self.cmd_client_report(" ".join(arg))
        elif cmd == "/leads":
            self.cmd_leads()
        elif cmd == "/sent" and arg and not arg[0].isdigit():
            self.cmd_sent(" ".join(arg))
        elif cmd in {"/sent", "/replies"}:
            try:
                n = int(arg[0])
                assert 1 <= n <= 500
            except (IndexError, ValueError, AssertionError):
                return reply(f"Usage: {cmd} N  (1-500)" + ("  or  /sent all  or  /sent Acme" if cmd == "/sent" else ""))
            key = "sent" if cmd == "/sent" else "replies"
            self.ops_update(lambda o: o.setdefault("funnel", {}).__setitem__(key, o.setdefault("funnel", {}).get(key, 0) + n))
            fn = self.ops().get("funnel", {})
            reply(f"Noted. Sent {fn.get('sent', 0)}, replies {fn.get('replies', 0)}.")
        elif cmd == "/replied":
            self.cmd_replied(" ".join(arg))
        elif cmd == "/quote":
            name, amount = sales.split_name_amount(arg)
            if amount is not None and not 5 <= amount <= 5000:
                return reply("The price must be between $5 and $5000.")
            self.cmd_quote(name or " ".join(arg), amount)
        elif cmd == "/won":
            self.cmd_won(arg)
        elif cmd in {"/lost", "/optout"}:
            self.cmd_close(" ".join(arg), cmd[1:])
        elif cmd == "/addlead":
            self.cmd_addlead(arg)
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
        self.due_followups()
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
