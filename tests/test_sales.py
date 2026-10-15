"""Phase 8: payment links, quotes, reply kit, follow-ups, contact discovery, lead tracking. No network, no sending, no spend."""
import re
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from agents.coo_agent import COOAgent
from config import Settings
from llm import LLMResult
from ops import sales
from state import AgencyState
from tests.test_daemon import FakeAPI, OWNER, clock, ops, setup  # noqa: F401  (clock is a fixture)
from tests.test_web_dashboard import Web

ROOT = Path(__file__).resolve().parents[1]
PP = "paypal.me/demo-seller"
DAY = 86400.0

FINDINGS = [
    {"area": "seo", "severity": 3, "keyword": "mobile", "detail": "Missing viewport meta tag; page is not mobile-friendly.", "short": "there is no mobile viewport tag"},
    {"area": "conversion", "severity": 3, "keyword": "call to action", "detail": "No clear call-to-action found.", "short": "no clear call-to-action"},
    {"area": "funnel", "severity": 3, "keyword": "form", "detail": "Lead form has 9 fields.", "short": "your lead form asks for 9 fields"},
    {"area": "speed", "severity": 2, "keyword": "server", "detail": "Server took ~1.2s to respond.", "short": "server response takes ~1.2s"},
    {"area": "trust", "severity": 2, "keyword": "social proof", "detail": "No testimonials detected.", "short": "there is no visible social proof"},
    {"area": "seo", "severity": 2, "keyword": "title", "detail": "Weak page title: 'Home'.", "short": "your page title is just 'Home'"},
    {"area": "seo", "severity": 1, "keyword": "alt", "detail": "7 images have no alt attribute.", "short": "7 images have no alt text"},
]


def item(i=0, company=None, url=None, lang="en", findings=None):
    return {"url": url or f"https://co{i}.example.com", "company": company or f"Acme {i}", "ceo": "there",
            "message": f"Hi there, message {i}.\n\nMohamed", "findings": FINDINGS if findings is None else findings,
            "score": 64, "html_kb": 120.0, "images": 12, "lang": lang}


def seed(d, *items, status="released", **extra):
    for it in items:
        lead = sales.new_lead(it, d.clock()) | {"status": status} | extra
        d.ops_update(lambda o, k=it["url"].lower(), l=lead: o.setdefault("leads", {}).__setitem__(k, l))


def texts_since(api, n):
    return api.texts()[n:]


# ------------------------------------------------------------------ payment links
def test_paypal_handle_and_link_variants():
    for v in (PP, "https://www.paypal.me/demo-seller", "http://paypal.me/demo-seller/10USD", "demo-seller", " PayPal.me/demo-seller/?x=1 "):
        assert sales.paypal_handle(v) == "demo-seller", v
    assert sales.paypal_link(PP, 49) == "https://paypal.me/demo-seller/49USD"
    assert sales.paypal_link(PP, 120.5) == "https://paypal.me/demo-seller/120.50USD"
    for bad in ("", "paypal.me/", "https://evil.example/demo-seller", "a b", "x" * 61, "paypal.me/na me", "javascript:alert(1)"):
        assert sales.paypal_link(bad, 10) is None, bad
    assert sales.paypal_link(PP, 0) is None and sales.paypal_link(PP, -5) is None and sales.paypal_link(PP, 1e9) is None


def test_settings_read_sales_env(monkeypatch):
    monkeypatch.setenv("PAYPAL_ME", PP)
    monkeypatch.setenv("SENDER_ADDRESS", "1 Main St\r\nCairo, Egypt")
    monkeypatch.setenv("PRICE_REPORT_USD", "59")
    monkeypatch.setenv("FOLLOWUP_FIRST_DAYS", "2")
    s = Settings.load()
    assert s.paypal_me == PP and s.sender_address == "1 Main St, Cairo, Egypt" and s.price_report == 59.0 and s.followup_days == (2.0, 4.0)
    assert s.price_hourly == 30.0 and s.price_cap == 600.0 and s.delivery_days == 3


# ------------------------------------------------------------------ pricing
def test_quote_is_deterministic_and_explainable():
    q = sales.quote({"findings": FINDINGS, "performance": {"html_kb": 120}})
    assert q["fixes"] == ["mobile", "call to action", "form", "server", "social proof"]   # top 5 by severity, then effort
    assert q["hours"] == 6.0 and q["report"] == 49.0 and q["fix"] == 230.0 and not q["custom"] and q["issues"] == 7
    assert sales.quote({"findings": FINDINGS, "performance": {"html_kb": 500}})["fix"] == 245.0    # heavy page: +0.5 h
    assert sales.quote({"findings": FINDINGS}, report=59, hourly=40)["fix"] == 300.0
    small = sales.quote({"findings": [FINDINGS[-1]]})
    assert small["fix"] == 69.0 and small["hours"] == 0.5                                         # never less than report + $20


def test_quote_cap_override_and_empty():
    big = sales.quote({"findings": FINDINGS}, cap=100)
    assert big["custom"] and big["fix"] == 100 and any("above the $100 cap" in n for n in big["notes"])
    o = sales.quote({"findings": FINDINGS}, cap=100, override=120)
    assert not o["custom"] and o["fix"] == 120.0 and "price set manually" in o["notes"]
    e = sales.quote({"findings": []})
    assert e["issues"] == 0 and e["hours"] == 0 and any("nothing to sell" in n for n in e["notes"])


def test_every_auditor_finding_has_a_fix_recipe():
    src = (ROOT / "projects" / "prj_03_deal_closer" / "b2b_sniper.py").read_text()
    keywords = set(re.findall(r'Finding\("[a-z]+", \d, "([^"]+)"', src))
    assert len(keywords) >= 14 and keywords <= set(sales.FIXES), keywords - set(sales.FIXES)
    for hrs, title, how in sales.FIXES.values():
        assert hrs > 0 and title and len(how) > 30


def test_client_report_is_complete_and_honest():
    lead = sales.new_lead(item())
    md = sales.client_report(lead, "Mohamed")
    assert md.startswith("# Website diagnostic report: Acme 0") and "Overall score: **64/100**" in md and "issues found: **7**" in md
    assert md.index("Missing viewport") < md.index("7 images have no alt")                        # most severe first
    assert md.count("**How to fix:**") == 7 and "width=device-width" in md and "Limits: this is an automated check of one page" in md
    assert "@" not in md.replace("alt=", "")  # no contact details leak into a client deliverable
    assert "No issues were detected" in sales.client_report(sales.new_lead(item(findings=[])), "M")


# ------------------------------------------------------------------ drafts
def test_reply_draft_variants_and_followups():
    lead = sales.new_lead(item() | {"ceo": "Dana"})
    q = sales.quote({"findings": FINDINGS})
    la, lb = sales.paypal_link(PP, q["report"]), sales.paypal_link(PP, q["fix"])
    d = sales.reply_draft(lead, q, "Mohamed", la, lb, 3)
    assert d.startswith("Hi Dana,") and "(${:g})".format(q["report"]) in d and f"top 5 fixes (${q['fix']:g})" in d
    assert la in d and lb in d and "within 3 business days of payment" in d and d.rstrip().endswith("Mohamed")
    custom = sales.reply_draft(lead, sales.quote({"findings": FINDINGS}, cap=100), "Mohamed", la, None, 3)
    assert "depends on scope" in custom and "Report + fixes: https" not in custom
    nolink = sales.reply_draft(lead, q, "Mohamed", None, None, 3)
    assert "Secure payment" not in nolink
    f1, f2 = sales.followup_draft(lead, 1, "Mohamed"), sales.followup_draft(lead, 2, "Mohamed")
    assert "there is no mobile viewport tag" in f1 and "Last note from me" in f2 and f1 != f2 and "Hi Dana" in f1
    assert "reply" in sales.compliance_footer("Mohamed", "1 Main St").lower() and "1 Main St" in sales.compliance_footer("M", "1 Main St")
    assert sales.footer_tail("").startswith("If this is not relevant")


# ------------------------------------------------------------------ contact discovery (public role addresses only)
def page(body="", lang="en"):
    return SimpleNamespace(status=200, html=f"<html lang='{lang}'><body>{body}</body></html>")


def test_extract_emails_role_based_same_domain_only():
    html = ("<a href='mailto:info@acme.com'>x</a> jane.doe@acme.com sales@acme.com noreply@acme.com info@other.com "
            "support@mail.acme.com hello@acme.com.evil.io logo@2x.png INFO@ACME.COM")
    assert sales.extract_emails(html, "acme.com") == ["info@acme.com", "sales@acme.com", "support@mail.acme.com"]
    assert sales.extract_emails("a@b.c info@x.com", "acme.com") == []


def test_discover_contacts_walks_few_pages_and_never_guesses():
    seen = []

    def fetch(url, timeout=10.0, **kw):
        seen.append(url)
        if url.endswith("/contact"):
            return page("Write to <a href='mailto:hello@acme.com'>us</a>", lang="ar")
        return page("no mail here")
    c = sales.discover_contacts("https://www.acme.com/", fetch)
    assert c == {"emails": ["hello@acme.com"], "form": None, "lang": "en"} and len(seen) == 2          # stops once an address is found
    assert sales.discover_contacts("https://acme.com", fetch, page_lang="ar-EG")["lang"] == "ar"       # the audited page's language wins

    seen.clear()
    def formonly(url, timeout=10.0, **kw):
        seen.append(url)
        return page("<form action='/send'><input></form>" if url.endswith("/contact-us") else "x")
    c = sales.discover_contacts("https://acme.com", formonly)
    assert c["emails"] == [] and c["form"] == "https://acme.com/contact-us" and len(seen) <= 4

    def broken(url, timeout=10.0, **kw):
        raise OSError("blocked")
    assert sales.discover_contacts("https://acme.com", broken) == {"emails": [], "form": None, "lang": "en"}
    err = lambda url, timeout=10.0, **kw: SimpleNamespace(status=404, html="info@acme.com")  # noqa: E731
    assert sales.discover_contacts("https://acme.com", err)["emails"] == []


def test_match_lead_and_amount_parsing():
    leads = {"a": {"url": "https://www.acme.com", "company": "Acme Corp"}, "b": {"url": "https://acme-labs.io", "company": "Acme Labs"},
             "c": {"url": "https://zeta.com", "company": ""}}
    assert sales.match_lead(leads, "zeta")[0] == "c" and sales.match_lead(leads, "acme corp")[0] == "a"
    assert sales.match_lead(leads, "acme")[0] is None and len(sales.match_lead(leads, "acme")[1]) == 2
    assert sales.match_lead(leads, "nope") == (None, []) and sales.match_lead(leads, "acme.com")[0] == "a"
    assert sales.split_name_amount(["Acme", "Corp", "$149"]) == ("Acme Corp", 149.0)
    assert sales.split_name_amount(["Acme"]) == ("Acme", None) and sales.split_name_amount([]) == ("", None)


# ------------------------------------------------------------------ release: contacts, footer, translation
def test_release_adds_contacts_footer_subject_and_creates_leads(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock, sender_address="1 Main St, Cairo")
    d.fetch = lambda url, timeout=10.0, **kw: page("<a href='mailto:info@co0.example.com'>mail</a>") if "co0" in url else page("none")
    d.release([item(0), item(1)], "b1")
    msgs = api.texts()
    assert "To: info@co0.example.com" in msgs[0] and "Suggested subject: Quick note about Acme 0's website" in msgs[0]
    assert "1 Main St, Cairo" in msgs[0] and 'reply "no thanks"' in msgs[0] and "message 0" in msgs[0]
    assert "no public contact found" in msgs[1]
    assert "/sent all" in msgs[-1] and "SENDER_ADDRESS" not in msgs[-1]
    leads = d.leads()
    assert len(leads) == 2 and all(l["status"] == "released" and l["findings"] for l in leads.values())
    assert leads["https://co0.example.com"]["contacts"]["emails"] == ["info@co0.example.com"]
    d2, api2, _ = setup(tmp_path / "x", clock)
    d2.release([item(0)], "b2")
    assert "SENDER_ADDRESS is not set" in api2.texts()[-1]                                      # the legal footer needs your address


def test_release_skips_opted_out_domains(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock)
    d.ops_update(lambda o: o.update(optout=["co1.example.com"]))
    d.release([item(0), item(1)], "b1")
    assert sum(t.startswith("✉️") for t in api.texts()) == 1 and len(d.leads()) == 1


def test_non_english_sites_get_a_guarded_unverified_translation(tmp_path, clock):
    d, api, fab = setup(tmp_path, clock, provider="anthropic")
    good = "مرحبا، رسالة 0.\n\nMohamed"
    d.fetch = lambda url, timeout=10.0, **kw: page("x", lang="ar")
    fab.llm = SimpleNamespace(complete=lambda *a, **k: LLMResult(good, "anthropic", "m", live=True))
    d.release([item(0, lang="ar")], "b1")
    tr = [t for t in api.texts() if t.startswith("🌐")][0]
    assert "AI translation (unverified" in tr and good in tr
    for bad in ("مرحبا، رسالة 7.\n\nMohamed", "مرحبا، رسالة 0.\n\nشخص آخر", ""):                   # lost number / lost signature / empty
        d3, api3, fab3 = setup(tmp_path / f"t{len(bad)}", clock, provider="anthropic")
        d3.fetch = d.fetch
        fab3.llm = SimpleNamespace(complete=lambda *a, bad=bad, **k: LLMResult(bad, "anthropic", "m", live=bool(bad)))
        d3.release([item(0, lang="ar")], "b1")
        assert "No translation available" in [t for t in api3.texts() if t.startswith("🌐")][0]
    d4, api4, _ = setup(tmp_path / "off", clock)                                                  # offline: no model -> honest note
    d4.fetch = d.fetch
    d4.release([item(0, lang="fr")], "b1")
    assert "No translation available" in [t for t in api4.texts() if t.startswith("🌐")][0]


# ------------------------------------------------------------------ lead lifecycle through Telegram
def test_sent_all_and_single_start_the_follow_up_clock(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock)
    seed(d, item(0, "Acme Corp"), item(1, "Beta Labs"))
    api.say("/sent Acme")
    d.poll(0)
    leads = d.leads()
    assert leads["https://co0.example.com"]["status"] == "sent" and leads["https://co1.example.com"]["status"] == "released"
    assert leads["https://co0.example.com"]["next_followup"] == pytest.approx(clock[0] + 3 * DAY)
    api.say("/sent all")
    api.say("/sent Acme")                                                                         # already sent
    d.poll(0)
    assert all(l["status"] == "sent" for l in d.leads().values()) and ops(d)["funnel"]["sent"] == 2
    assert "already 'sent'" in api.texts()[-1]
    api.say("/sent all")
    d.poll(0)
    assert "No unsent leads" in api.texts()[-1]
    api.say("/sent nobody")
    d.poll(0)
    assert "No lead matches 'nobody'" in api.texts()[-1]


def test_ambiguous_and_missing_names_are_explained(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock)
    seed(d, item(0, "Acme Corp"), item(1, "Acme Labs"))
    api.say("/replied Acme")
    api.say("/replied")
    d.poll(0)
    assert "More than one lead matches: Acme Corp, Acme Labs" in api.texts()[0] and "Which lead?" in api.texts()[1]
    assert all(l["status"] == "released" for l in d.leads().values())


def test_follow_ups_are_drafted_at_day_3_and_day_7_and_never_a_third_time(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock, sender_address="1 Main St")
    seed(d, item(0, "Acme Corp"), status="sent", t_sent=clock[0], next_followup=clock[0] + 3 * DAY)
    t0 = clock[0]
    clock[0] = t0 + 2 * DAY
    d.tick()
    assert not any("Follow-up" in t for t in api.texts())
    clock[0] = t0 + 3 * DAY + 60
    d.tick()
    d.tick()
    fu = [t for t in api.texts() if "Follow-up" in t]
    assert len(fu) == 1 and "Follow-up 1/2 due · Acme Corp" in fu[0] and "there is no mobile viewport tag" in fu[0]
    assert "1 Main St" in fu[0] and 'reply "no thanks"' in fu[0] and "/replied Acme" in fu[0]
    clock[0] = t0 + 6 * DAY
    d.tick()
    assert len([t for t in api.texts() if "Follow-up" in t]) == 1
    clock[0] = t0 + 7 * DAY + 120
    d.tick()
    fu = [t for t in api.texts() if "Follow-up" in t]
    assert len(fu) == 2 and "Follow-up 2/2" in fu[1] and "Last note from me" in fu[1]
    clock[0] = t0 + 60 * DAY
    d.tick()
    assert len([t for t in api.texts() if "Follow-up" in t]) == 2 and next(iter(d.leads().values()))["next_followup"] is None


def test_follow_ups_wait_when_telegram_is_down_or_missing(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock)
    seed(d, item(0, "Acme Corp"), status="sent", t_sent=clock[0] - 4 * DAY, next_followup=clock[0] - 60)
    d.send = lambda *a, **k: None                                                                  # delivery failed
    d.due_followups()
    lead = next(iter(d.leads().values()))
    assert lead["followups"] == 0 and lead["next_followup"] is not None                            # still due: retried next tick
    d2, api2, _ = setup(tmp_path / "n", clock, tg=False)
    seed(d2, item(0, "Acme Corp"), status="sent", t_sent=clock[0] - 4 * DAY, next_followup=clock[0] - 60)
    d2.due_followups()
    assert next(iter(d2.leads().values()))["followups"] == 0


def test_replied_cancels_follow_ups_counts_once_and_sends_the_kit(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock, paypal_me=PP)
    seed(d, item(0, "Acme Corp") | {"ceo": "Dana"}, status="sent", next_followup=clock[0] + DAY)
    api.say("/replied Acme")
    d.poll(0)
    kit = api.texts()[-1]
    assert kit.startswith("💬 Reply kit · Acme Corp") and "score 64/100 · 7 issues" in kit and "[seo] Missing viewport" in kit
    assert "Report only: $49" in kit and "Report + top 5 fixes: $230 (≈6 h at $30/h)" in kit
    assert "https://paypal.me/demo-seller/49USD" in kit and "https://paypal.me/demo-seller/230USD" in kit
    assert "Hi there," in kit or "Hi Dana," in kit
    lead = next(iter(d.leads().values()))
    assert lead["status"] == "quoted" and lead["next_followup"] is None and lead["quote"]["fix"] == 230.0
    assert ops(d)["funnel"]["replies"] == 1
    api.say("/replied Acme")                                                                       # again: kit again, no double count
    d.poll(0)
    assert ops(d)["funnel"]["replies"] == 1
    clock[0] += 30 * DAY
    d.due_followups()
    assert not any("Follow-up" in t for t in api.texts())


def test_quote_override_bounds_and_missing_paypal(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock, paypal_me=PP)
    seed(d, item(0, "Acme Corp"))
    api.say("/quote Acme Corp 120")
    d.poll(0)
    assert "Report + top 5 fixes: $120" in api.texts()[-1] and "https://paypal.me/demo-seller/120USD" in api.texts()[-1]
    for bad in ("/quote Acme 3", "/quote Acme 9000"):
        api.say(bad)
    d.poll(0)
    assert api.texts()[-1] == "The price must be between $5 and $5000." and api.texts()[-2] == api.texts()[-1]
    d2, api2, _ = setup(tmp_path / "np", clock, paypal_me="")
    seed(d2, item(0, "Acme Corp"))
    api2.say("/quote Acme")
    d2.poll(0)
    assert "PAYPAL_ME is not set" in api2.texts()[-1] and "paypal.me/" not in api2.texts()[-1]
    d3, api3, _ = setup(tmp_path / "bad", clock, paypal_me="https://evil.example/x")
    seed(d3, item(0, "Acme Corp"))
    api3.say("/quote Acme")
    d3.poll(0)
    assert "PAYPAL_ME is not set" in api3.texts()[-1]                                              # an invalid handle never becomes a link


def test_custom_priced_sites_are_flagged_not_linked(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock, paypal_me=PP, price_cap=100.0)
    seed(d, item(0, "Acme Corp"))
    api.say("/quote Acme")
    d.poll(0)
    kit = api.texts()[-1]
    assert "custom" in kit and "agree scope first" in kit and "/49USD" in kit and "/230USD" not in kit and "/100USD" not in kit


def test_won_needs_amount_and_confirmation_then_logs_revenue(tmp_path, clock):
    from orchestrator import Orchestrator
    d, api, _ = setup(tmp_path, clock, paypal_me=PP)
    d.orch_factory = Orchestrator                                                                  # real CFO: the revenue must really be booked
    seed(d, item(0, "Acme Corp"), status="quoted")
    for cmd in ("/won Acme", "/won Acme 0", "/won Acme abc"):
        api.say(cmd)
    d.poll(0)
    assert sum("Usage: /won" in t for t in api.texts()) == 3
    assert not AgencyState(d.s.state_path, 10).snapshot()["revenue"]
    api.say("/won Acme 149")
    d.poll(0)
    assert "Log $149.00 of VERIFIED revenue from Acme Corp" in api.texts()[-1]
    assert next(iter(d.leads().values()))["status"] == "quoted"                                    # nothing changes before the tap
    api.tap(api.last_pid(), "y")
    d.poll(0)
    snap = AgencyState(d.s.state_path, 10).snapshot()
    lead = next(iter(snap["ops"]["leads"].values()))
    assert snap["revenue"][0]["usd"] == 149.0 and snap["revenue"][0]["project"] == "PRJ-03" and snap["vault"]["locked"] is False
    assert lead["status"] == "won" and lead["won_usd"] == 149.0


def test_lost_and_optout_stop_everything_and_optout_is_permanent(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock)
    seed(d, item(0, "Acme Corp"), item(1, "Beta Labs"), status="sent", t_sent=clock[0], next_followup=clock[0] - 1)
    api.say("/optout Acme")
    api.say("/lost Beta")
    d.poll(0)
    leads = d.leads()
    assert leads["https://co0.example.com"]["status"] == "optout" and leads["https://co1.example.com"]["status"] == "lost"
    assert ops(d)["optout"] == ["co0.example.com"] and "for good" in api.texts()[0]
    d.due_followups()
    assert not any("Follow-up" in t for t in api.texts())
    api.say("/replied Acme")
    d.poll(0)
    assert "Not contacting them again" in api.texts()[-1] and "Reply kit" not in api.texts()[-1]


def test_cycle_drops_opted_out_domains(tmp_path, clock):
    d, api, fab = setup(tmp_path, clock)
    d.ops_update(lambda o: o.update(optout=["a1.example.com"]))     # the fake audit produces a0 and a1
    cycle = d.run_cycle("offline")
    assert [r["url"] for r in cycle["ready"]] == ["https://a0.example.com"]


def test_cycle_items_carry_the_audit_findings_for_later_quotes(tmp_path, clock):
    d, api, fab = setup(tmp_path, clock)
    out = Path(d.s.output_dir) / "PRJ-03"
    orig = fab.__call__

    def with_findings(s):
        o = orig(s)
        run = o.run_autopilot

        def go(**kw):
            r = run(**kw)
            (out / "outreach_batch.json").write_text(__import__("json").dumps([{
                "url": "https://real.example.com", "company": "Real\nCo", "ceo": "there", "ready": True, "outreach": "Hi there.\n\nMohamed",
                "findings": FINDINGS, "scores": {"overall": 64}, "performance": {"html_kb": 120.0}, "page": {"images": 12, "lang": "ar-EG"}}]))
            return r
        o.run_autopilot = go
        return o
    d.orch_factory = with_findings
    ready = d.run_cycle("offline")["ready"]
    assert len(ready) == 1 and ready[0]["company"] == "Real Co" and ready[0]["score"] == 64 and ready[0]["lang"] == "ar"
    assert ready[0]["html_kb"] == 120.0 and [f["keyword"] for f in ready[0]["findings"]][:3] == ["mobile", "call to action", "form"]
    assert sales.quote({"findings": ready[0]["findings"], "performance": {"html_kb": ready[0]["html_kb"]}})["fix"] == 230.0


def test_client_report_command_saves_and_sends(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock)
    seed(d, item(0, "Acme Corp"))
    api.say("/report Acme")
    d.poll(0)
    path = Path(d.s.output_dir) / "PRJ-03" / "clients" / "acme-corp.md"
    assert path.exists() and "Website diagnostic report: Acme Corp" in path.read_text()
    assert "Review it, then send it after payment" in "".join(api.texts()) and "Website diagnostic report" in "".join(api.texts())
    api.say("/report")
    d.poll(0)
    assert api.texts()[-1].startswith("📊 Report ·")                                               # a bare /report is still the briefing


def test_addlead_validates_dedupes_and_caps_the_queue(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock)
    api.say("/addlead https://newco.example.com New Co")
    api.say("/addlead newco.example.com")
    api.say("/addlead javascript:alert(1)")
    api.say("/addlead http://127.0.0.1/x")
    api.say("/addlead")
    d.poll(0)
    out = api.texts()
    assert "Added New Co" in out[0] and "already queued" in out[1] and "Not added" in out[2] and "Usage: /addlead" in out[4]
    from projects.prj_03_deal_closer import prospects
    rows = prospects.read_targets(Path(d.s.targets_path))
    assert [r["company"] for r in rows] == ["New Co"]
    for i in range(12):
        api.say(f"/addlead https://co{i}.example.com")
    d.poll(0)
    assert "10 un-audited targets" in api.texts()[-1] and len(prospects.read_targets(Path(d.s.targets_path))) == 10


def test_leads_listing_is_sorted_by_urgency(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock)
    api.say("/leads")
    d.poll(0)
    assert "No leads yet" in api.texts()[-1]
    seed(d, item(0, "Alpha"), status="released")
    seed(d, item(1, "Beta"), status="replied")
    seed(d, item(2, "Gamma"), status="won", won_usd=149)
    seed(d, item(3, "Delta"), status="sent", next_followup=clock[0] + DAY)
    api.say("/leads")
    d.poll(0)
    lst = api.texts()[-1]
    assert lst.startswith("👥 Leads (4)") and lst.index("Beta") < lst.index("Delta") < lst.index("Alpha") < lst.index("Gamma")
    assert "Gamma — won · $149" in lst and "Delta — sent · follow-up" in lst


# ------------------------------------------------------------------ COO sees the sales funnel
def test_coo_facts_and_risks_cover_the_sales_funnel(tmp_path):
    from tests.test_autopilot import mk
    s = mk(tmp_path)
    snap = AgencyState(s.state_path, 10).snapshot()
    now = time.time()
    snap["ops"] = {"leads": {
        "a": {"url": "https://a.com", "company": "A", "status": "replied", "t": now},
        "b": {"url": "https://b.com", "company": "B", "status": "quoted", "t": now, "t_quoted": now - 4 * DAY},
        "c": {"url": "https://c.com", "company": "C", "status": "sent", "t": now, "next_followup": now - 5},
        "d": {"url": "https://d.com", "company": "D", "status": "won", "t": now, "won_usd": 149.0}}}
    coo = COOAgent(s)
    f = coo.facts(snap, None, now)
    assert f["leads"] == {"counts": {"replied": 1, "quoted": 1, "sent": 1, "won": 1}, "total": 4, "due_followups": 1,
                          "stale_quotes": 1, "won_usd": 149.0}
    r = " ".join(f["risks"])
    assert "1 quote(s) sent 3+ days ago" in r and "1 follow-up(s) are due" in r
    text = coo.render(f, coo.analysis(f))
    assert "👥 Leads: sent 1 · replied 1 · quoted 1 · won 1 · won $149" in text


def test_web_ops_lists_leads_without_contact_details(tmp_path, clock):
    d, api, _ = setup(tmp_path, clock, paypal_me=PP)
    seed(d, item(0, "Acme Corp"), status="quoted", quote={"fix": 230.0}, contacts={"emails": ["info@co0.example.com"]})
    w = Web(d.s)
    r = w.get("/api/ops")
    j = r.json()
    assert j["paypal"] is True and j["leads"][0]["company"] == "Acme Corp" and j["leads"][0]["quote"] == 230.0
    assert "info@co0.example.com" not in r.text and "paypal.me" not in r.text                  # no emails, no payment handle in the mirror
    assert 'id="coo-leads"' in w.get("/").text and "coo-leads" in w.get("/static/app.js").text


def test_sales_guide_covers_setup_pricing_compliance_and_limits():
    g = (ROOT / "docs" / "SALES.md").read_text()
    for must in ("PAYPAL_ME", "SENDER_ADDRESS", "/replied", "/won", "PRICE_HOURLY_USD", "never sends", "GDPR", "CAN-SPAM",
                 "role addresses", "AI translation", "no guarantee"):
        assert must in g, must
