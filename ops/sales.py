"""Sales toolkit for the AI COO: payment links, transparent quotes, reply/follow-up drafts, client report, contact discovery.

Everything here is deterministic and offline-testable. The agency never sends anything: these functions only prepare text that
the owner reviews and sends.

Quote model (shown to the owner, who can override the price with /quote):
  report only        = PRICE_REPORT (default $49): the full written report with a fix recipe for every finding
  report + fixes     = PRICE_REPORT + estimated hours for the top 5 fixes x PRICE_HOURLY, rounded to $5, never above PRICE_CAP;
                       above the cap the job is flagged "custom" (needs a conversation, not a link)
Hours come from a fixed table per finding type plus a small overhead for very heavy pages: a transparent estimate, not a promise.
"""
from __future__ import annotations

import re
import time
import urllib.parse

# ---------------------------------------------------------------------------------------------- payment links
_HANDLE = re.compile(r"^[A-Za-z0-9._-]{1,60}$")


def paypal_handle(value: str) -> str | None:
    """'paypal.me/name', 'https://www.paypal.me/name/10USD' or 'name' -> 'name'; anything else -> None."""
    v = (value or "").strip()
    if not v:
        return None
    if "paypal.me" in v.lower():
        v = re.sub(r"^(https?://)?(www\.)?paypal\.me/", "", v, flags=re.I).split("/")[0].split("?")[0]
    return v if _HANDLE.match(v) else None


def paypal_link(handle_or_url: str, amount: float) -> str | None:
    h = paypal_handle(handle_or_url)
    if not h or not (0 < amount <= 100_000):
        return None
    amt = f"{int(amount)}" if float(amount).is_integer() else f"{amount:.2f}"
    return f"https://paypal.me/{h}/{amt}USD"


# ---------------------------------------------------------------------------------------------- fix recipes
# keyword (Finding.keyword from the auditor) -> (estimated hours, title, how to fix)
FIXES: dict[str, tuple[float, str, str]] = {
    "server": (2.0, "Slow server response", "Turn on page/object caching or put a CDN in front of the site, check for slow database queries or "
               "underpowered hosting, and re-measure. Target: first byte in under 0.8 s."),
    "load": (1.0, "Slow HTML download", "Compress responses, cache pages and serve them through a CDN so the HTML arrives well under 3 s."),
    "compression": (0.5, "HTML served uncompressed", "Enable gzip or brotli. nginx: `gzip on; gzip_types text/html text/css application/javascript;` "
                    "Apache: enable mod_deflate. Most hosts and CDNs have a one-click toggle."),
    "blocking scripts": (1.0, "Render-blocking scripts", "Add `defer` (or `async`) to scripts in <head> that are not needed for first paint and move "
                         "non-critical ones to the end of <body>. Test forms and menus afterwards."),
    "mobile": (1.0, "No mobile viewport", 'Add to <head>: `<meta name="viewport" content="width=device-width, initial-scale=1">`, then check the '
               "layout on a real phone and fix anything that overflows."),
    "meta description": (0.25, "No meta description", 'Add to <head>: `<meta name="description" content="One sentence, 120-155 characters, '
                         'saying what you offer and for whom.">` on every important page.'),
    "meta description length": (0.25, "Meta description too long", "Rewrite it to 120-155 characters so search results show it whole, "
                                "leading with the benefit."),
    "title": (0.25, "Weak page title", "Write a unique 30-60 character title per page: what the page offers plus the brand name."),
    "h1": (0.25, "Heading structure", "Use exactly one <h1> stating the page's main promise; turn the others into <h2>/<h3>."),
    "alt": (0.5, "Images without alt text", 'Add short descriptive alt text to every meaningful image (use alt="" for purely decorative ones).'),
    "call to action": (1.0, "Weak or missing call to action", "Put one primary button above the fold that names a specific outcome "
                       "(e.g. 'Get my free quote') and repeat it after each key section."),
    "form": (1.0, "Long lead form", "Cut the form to the fields you truly need (name, email, one question) and collect the rest in a "
             "follow-up step."),
    "social proof": (1.0, "No visible social proof", "Add 2-3 real testimonials with names, a customer count or a short case study near the "
                     "main call to action. Use only genuine ones."),
    "contact": (0.25, "No obvious contact path", "Show a phone number, email address or Contact link in the header and footer."),
    "https": (1.0, "Not served over HTTPS", "Install a TLS certificate (many hosts offer free Let's Encrypt), redirect http to https and fix "
              "mixed-content warnings."),
    "structured data": (0.5, "No structured data", "Add JSON-LD (Organization / LocalBusiness / Product) in <head> and validate it with "
                        "Google's Rich Results Test."),
}
DEFAULT_FIX = (0.5, "Improvement", "See the diagnostic detail above.")
TOP_FIXES = 5


def fix_for(keyword: str) -> tuple[float, str, str]:
    return FIXES.get(keyword, DEFAULT_FIX)


def quote(result: dict, report: float = 49.0, hourly: float = 30.0, cap: float = 600.0, override: float | None = None) -> dict:
    """Price an engagement from an audit result (the auditor's `findings`, `performance`, `page`). Pure and deterministic."""
    fs = sorted(result.get("findings") or [], key=lambda f: (-int(f.get("severity", 1)), -fix_for(f.get("keyword", ""))[0]))
    top = fs[:TOP_FIXES]
    hours = sum(fix_for(f.get("keyword", ""))[0] for f in top)
    kb = float((result.get("performance") or {}).get("html_kb") or 0)
    if kb > 400:
        hours += 0.5  # heavy pages take longer to test
    notes = []
    raw = report + hours * hourly
    fix = max(report + 20.0, round(raw / 5.0) * 5.0)
    custom = fix > cap
    if custom:
        notes.append(f"Estimated ${fix:.0f} is above the ${cap:.0f} cap: discuss scope before sending a link.")
        fix = cap
    if override is not None:
        fix, custom = round(float(override), 2), False
        notes.append("price set manually")
    if not fs:
        notes.append("No findings: nothing to sell here.")
    return {"report": round(report, 2), "fix": fix, "hours": round(hours, 2), "custom": custom,
            "fixes": [f.get("keyword", "") for f in top], "issues": len(fs), "notes": notes}


# ---------------------------------------------------------------------------------------------- text drafts
def footer_tail(address: str) -> str:
    """Postal address + opt-out line: legal basics for cold email in many markets."""
    lines = [address] if address else []
    lines.append('If this is not relevant, reply "no thanks" and I will not write again.')
    return "\n".join(lines)


def compliance_footer(sender: str, address: str) -> str:
    """Appended to cold messages at release time (kept out of the validated body)."""
    return "\n\n--\n" + sender + "\n" + footer_tail(address)


def suggested_subject(company: str) -> str:
    return f"Quick note about {company}'s website"


def reply_draft(lead: dict, q: dict, sender: str, link_report: str | None, link_fix: str | None, delivery_days: int = 3) -> str:
    hello = lead.get("ceo") if lead.get("ceo") and lead["ceo"].lower() != "there" else "there"
    n = len(q["fixes"])
    lines = [f"Hi {hello},", "", "Thanks for getting back to me. Here is how I can help with the points I mentioned for "
             f"{lead.get('company') or lead['url']}:", "",
             f"1) Full report (${q['report']:g}): every issue I found, why it matters, and step-by-step fixes you or your developer can apply."]
    if q["custom"]:
        lines.append("2) Report + done-for-you fixes: this one depends on scope, so let's talk through it first and I'll send an exact price.")
    elif n:
        lines.append(f"2) Report + I implement the top {n} fixes (${q['fix']:g}): you give me access, I make the changes and send a before/after check.")
    lines += ["", f"Delivery: within {delivery_days} business days of payment. I start when payment arrives."]
    pay = [f"Report: {link_report}" if link_report else "", f"Report + fixes: {link_fix}" if link_fix and not q["custom"] else ""]
    pay = [p for p in pay if p]
    if pay:
        lines += ["", "Secure payment (PayPal):"] + pay
    lines += ["", "Happy to answer any questions first.", "", sender]
    return "\n".join(lines)


def followup_draft(lead: dict, n: int, sender: str) -> str:
    hello = lead.get("ceo") if lead.get("ceo") and lead["ceo"].lower() != "there" else "there"
    top = (lead.get("findings") or [{}])[0]
    point = top.get("short") or top.get("detail") or "a few quick wins on your website"
    if n == 1:
        body = (f"Hi {hello},\n\nA quick follow-up on my note about {lead.get('company') or lead['url']}: {point.rstrip('.')}. "
                "If it's useful I can send the short list of fixes. If not, no problem at all.\n\n" + sender)
    else:
        body = (f"Hi {hello},\n\nLast note from me on this: if improving {lead.get('company') or lead['url']}'s site isn't a priority "
                "right now, ignore this and I won't write again. If it is, just reply and I'll send the details.\n\n" + sender)
    return body


def client_report(lead: dict, sender: str) -> str:
    """The deliverable for the report tier: a markdown report built from the stored audit findings (owner reviews before sending)."""
    fs = sorted(lead.get("findings") or [], key=lambda f: (-int(f.get("severity", 1)), f.get("area", "")))
    name = lead.get("company") or lead["url"]
    out = [f"# Website diagnostic report: {name}", "", f"Site: {lead['url']}  ",
           f"Overall score: **{lead.get('score', '?')}/100** · issues found: **{len(fs)}**", "",
           "Each item below was measured automatically from your public homepage. Severity 3 = fix first.", ""]
    for i, f in enumerate(fs, 1):
        hrs, title, how = fix_for(f.get("keyword", ""))
        out += [f"## {i}. {title}  (severity {f.get('severity', '?')}, {f.get('area', '')})", "", f"**Finding:** {f.get('detail', '')}", "",
                f"**How to fix:** {how}", "", f"_Typical effort: about {hrs:g} h._", ""]
    if not fs:
        out.append("No issues were detected in this automated check.")
    out += ["---", "Limits: this is an automated check of one page (the homepage) at one moment. Speed numbers vary by location and time; "
            "re-test after changes.", "", sender]
    return "\n".join(out)


# ---------------------------------------------------------------------------------------------- leads
ROLE_LOCALS = {"info", "hello", "contact", "sales", "support", "team", "office", "admin", "enquiries", "inquiries", "mail", "hi", "general",
               "bonjour", "contacto", "kontakt", "ventas", "business"}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+")
_BLOCK = ("noreply", "no-reply", "donotreply", "sentry", "wixpress", "@2x", ".png", ".jpg", ".webp", ".gif", ".svg")
_PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "domain.com", "yourdomain.com", "email.com", "company.com"}
CONTACT_PATHS = ("/contact", "/contact-us", "/about")
MAX_CONTACT_FETCHES = 4  # homepage + up to 3 contact-type pages


def _base_host(url: str) -> str:
    h = (urllib.parse.urlparse(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def extract_emails(html: str, host: str) -> list[str]:
    """Role-based addresses on the company's own domain only. Named/personal addresses and other domains are ignored."""
    found = []
    for m in _EMAIL.finditer(urllib.parse.unquote(html)):
        e = m.group(0).strip(".").lower()
        local, _, dom = e.partition("@")
        if any(b in e for b in _BLOCK) or local not in ROLE_LOCALS or dom in _PLACEHOLDER_DOMAINS:
            continue
        if not (dom == host or host.endswith("." + dom) or dom.endswith("." + host)):
            continue
        if e not in found:
            found.append(e)
    return found[:3]


def discover_contacts(url: str, fetch, page_lang: str = "") -> dict:
    """Public contact paths from the company's own pages: role-based emails, else a contact-form URL. Never guesses addresses."""
    host = _base_host(url)
    root = urllib.parse.urlparse(url)
    base = f"{root.scheme}://{root.netloc}"
    emails, form, lang = [], None, (page_lang or "").split("-")[0].lower()
    for i, path in enumerate(("",) + CONTACT_PATHS):
        if i >= MAX_CONTACT_FETCHES:
            break
        try:
            fr = fetch(base + path if path else url, timeout=10.0)
        except Exception:  # unreachable page / blocked / non-HTML: skip it
            continue
        if getattr(fr, "status", 200) >= 400:
            continue
        html = getattr(fr, "html", "") or ""
        if not lang:
            m = re.search(r"<html[^>]*\blang=[\"']?([A-Za-z]{2})", html, re.I)
            lang = m.group(1).lower() if m else ""
        for e in extract_emails(html, host):
            if e not in emails:
                emails.append(e)
        if path and "<form" in html.lower() and not form:
            form = base + path
        if emails:
            break
    return {"emails": emails[:3], "form": form, "lang": lang or "en"}


DAY = 86400.0
ACTIVE = {"released", "sent", "replied", "quoted"}


def match_lead(leads: dict, name: str) -> tuple[str | None, list[str]]:
    """Find one lead by company/domain text. Returns (key, candidates): key is set only for a single clear match."""
    q = name.strip().lower()
    if not q:
        return None, []
    hits = [k for k, l in leads.items() if q == (l.get("company") or "").lower() or q == _base_host(l["url"])]
    if not hits:
        hits = [k for k, l in leads.items() if q in (l.get("company") or "").lower() or q in _base_host(l["url"])]
    return (hits[0] if len(hits) == 1 else None), hits


def split_name_amount(args: list[str]) -> tuple[str, float | None]:
    if args:
        try:
            return " ".join(args[:-1]), float(args[-1].lstrip("$"))
        except ValueError:
            pass
    return " ".join(args), None


def new_lead(item: dict, now: float | None = None) -> dict:
    """A lead record from one released batch item (see Daemon.run_cycle)."""
    return {"url": item["url"], "company": item.get("company") or "", "ceo": item.get("ceo", "there"), "status": "released",
            "t": now or time.time(), "followups": 0, "next_followup": None, "message": item.get("message", ""),
            "findings": item.get("findings", []), "score": item.get("score"), "html_kb": item.get("html_kb"),
            "images": item.get("images"), "lang": item.get("lang", "en"), "contacts": {}, "quote": None}
