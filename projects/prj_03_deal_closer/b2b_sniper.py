"""B2B Sniper: technical/conversion diagnostics for a company URL + a surgical (<110 words) CEO outreach audit."""
from __future__ import annotations

import gzip
import ipaddress
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser

MAX_WORDS = 110
MAX_BYTES = 5_000_000
CTA_WORDS = re.compile(r"\b(get|start|book|schedule|request|try|buy|contact|talk|demo|quote|sign ?up|subscribe|download|free|join)\b", re.I)
GENERIC_CTA = re.compile(r"^(learn more|click here|read more|submit|more|here|continue)$", re.I)
PROOF_WORDS = re.compile(r"(testimonial|case stud(?:y|ies)|trusted by|rated \d|\d(?:\.\d)?/5|<?blockquote|"
                         r"\d[\d,]*\+? (?:customers|clients|companies|shippers|teams|users))", re.I)


class UnsafeURL(ValueError):
    pass


def check_url_safe(url: str, allow_private: bool = False) -> str:
    """SSRF guard: only http(s) and, unless allowed, only public IPs."""
    p = urllib.parse.urlparse(url)
    if p.scheme not in {"http", "https"} or not p.hostname:
        raise UnsafeURL(f"unsupported URL: {url!r}")
    if allow_private:
        return url
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror as exc:
        raise UnsafeURL(f"cannot resolve {p.hostname}: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise UnsafeURL(f"{p.hostname} resolves to non-public address {ip}")
    return url


@dataclass
class FetchResult:
    url: str
    status: int
    ttfb_s: float
    total_s: float
    html_bytes: int
    transfer_bytes: int
    compressed: bool
    https: bool
    headers: dict = field(default_factory=dict)
    html: str = ""


def fetch(url: str, allow_private: bool = False, timeout: float = 15.0) -> FetchResult:
    check_url_safe(url, allow_private)

    class Guard(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            check_url_safe(newurl, allow_private)
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(Guard)
    req = urllib.request.Request(url, headers={"User-Agent": "B2BSniper/1.0 (+diagnostic)", "Accept-Encoding": "gzip, deflate",
                                               "Accept": "text/html,application/xhtml+xml"})
    t0 = time.perf_counter()
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        resp = exc
    ttfb = time.perf_counter() - t0
    raw = resp.read(MAX_BYTES)
    total = time.perf_counter() - t0
    enc = (resp.headers.get("Content-Encoding") or "").lower()
    body = raw
    try:
        if enc == "gzip":
            body = gzip.decompress(raw)
        elif enc == "deflate":
            body = zlib.decompress(raw)
    except (OSError, zlib.error):
        body = raw
    charset = resp.headers.get_content_charset() or "utf-8"
    return FetchResult(resp.geturl(), resp.status if hasattr(resp, "status") else resp.code, ttfb, total, len(body), len(raw),
                       enc in {"gzip", "deflate", "br"}, resp.geturl().startswith("https://"),
                       {k.lower(): v for k, v in resp.headers.items()}, body.decode(charset, errors="replace"))


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta: dict[str, str] = {}
        self.title = ""
        self._in_title = False
        self.h1 = 0
        self.imgs = 0
        self.imgs_no_alt = 0
        self.blocking_scripts = 0
        self.scripts = 0
        self.stylesheets = 0
        self.forms: list[int] = []
        self._form_idx = -1
        self.links: list[tuple[str, str]] = []
        self._link_href = None
        self._link_text: list[str] = []
        self.buttons: list[str] = []
        self._btn: list[str] | None = None
        self.in_head = False
        self.lang = ""
        self.canonical = ""
        self.has_ldjson = False
        self.favicon = False
        self.text: list[str] = []
        self.tel_or_mail = False
        self.in_script = False
        self.viewport = ""
        self.charset = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "html":
            self.lang = a.get("lang", "")
        elif tag == "head":
            self.in_head = True
        elif tag == "body":
            self.in_head = False
        elif tag == "title":
            self._in_title = True
        elif tag == "meta":
            if a.get("charset"):
                self.charset = True
            key = (a.get("name") or a.get("property") or "").lower()
            if key:
                self.meta[key] = a.get("content", "")
        elif tag == "link":
            rel = (a.get("rel") or "").lower()
            if "canonical" in rel:
                self.canonical = a.get("href", "")
            if "stylesheet" in rel:
                self.stylesheets += 1
            if "icon" in rel:
                self.favicon = True
        elif tag == "script":
            self.in_script = True
            if a.get("type") == "application/ld+json":
                self.has_ldjson = True
            elif a.get("src"):
                self.scripts += 1
                if self.in_head and "async" not in a and "defer" not in a and a.get("type") != "module":
                    self.blocking_scripts += 1
        elif tag == "h1":
            self.h1 += 1
        elif tag == "img":
            self.imgs += 1
            if not (a.get("alt") or "").strip() and "alt" not in a:
                self.imgs_no_alt += 1
        elif tag == "form":
            self.forms.append(0)
        elif tag in {"input", "select", "textarea"}:
            if self.forms and a.get("type", "text") not in {"hidden", "submit", "button", "checkbox"}:
                self.forms[-1] += 1
        elif tag == "a":
            self._link_href, self._link_text = a.get("href", ""), []
            if (a.get("href") or "").startswith(("tel:", "mailto:")):
                self.tel_or_mail = True
        elif tag == "button":
            self._btn = []

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script":
            self.in_script = False
        elif tag == "a" and self._link_href is not None:
            self.links.append((" ".join("".join(self._link_text).split()), self._link_href))
            self._link_href = None
        elif tag == "button" and self._btn is not None:
            self.buttons.append(" ".join("".join(self._btn).split()))
            self._btn = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._link_href is not None:
            self._link_text.append(data)
        if self._btn is not None:
            self._btn.append(data)
        if not self.in_script:
            self.text.append(data)


def parse_page(html: str) -> dict:
    p = PageParser()
    p.feed(html)
    text = " ".join(" ".join(p.text).split())
    ctas = [t for t, _ in p.links if t and CTA_WORDS.search(t)] + [b for b in p.buttons if b and CTA_WORDS.search(b)]
    generic = [t for t, _ in p.links if GENERIC_CTA.match(t)] + [b for b in p.buttons if GENERIC_CTA.match(b)]
    return {
        "title": p.title.strip(), "meta_description": p.meta.get("description", "").strip(),
        "viewport": p.meta.get("viewport", ""), "og_tags": sorted(k for k in p.meta if k.startswith("og:")),
        "canonical": p.canonical, "lang": p.lang, "h1_count": p.h1, "images": p.imgs, "images_missing_alt": p.imgs_no_alt,
        "scripts": p.scripts, "blocking_scripts": p.blocking_scripts, "stylesheets": p.stylesheets,
        "form_fields": p.forms, "ctas": ctas, "generic_ctas": generic, "has_structured_data": p.has_ldjson,
        "has_favicon": p.favicon, "text_words": len(text.split()),
        "social_proof": bool(PROOF_WORDS.search(text)), "has_phone_or_email_link": p.tel_or_mail,
        "has_pricing_link": any(re.search(r"pric|plans|quote", t + h, re.I) for t, h in p.links),
        "has_contact_link": any(re.search(r"contact|demo|book|talk", t + h, re.I) for t, h in p.links),
    }


@dataclass
class Finding:
    area: str  # speed | seo | conversion | funnel | trust
    severity: int  # 1-3
    keyword: str
    detail: str  # full diagnostic sentence
    short: str  # <=14-word outreach phrasing

    def to_dict(self):
        return asdict(self)


def diagnose(fr: FetchResult, page: dict) -> tuple[list[Finding], dict]:
    f: list[Finding] = []
    if fr.ttfb_s > 0.8:
        f.append(Finding("speed", 3, "server", f"Server took {fr.ttfb_s:.2f}s to respond (target < 0.8s).", f"your server takes {fr.ttfb_s:.1f}s before sending a single byte"))
    elif fr.ttfb_s > 0.4:
        f.append(Finding("speed", 2, "server", f"Server took {fr.ttfb_s:.2f}s to respond.", f"server response takes {fr.ttfb_s:.1f}s"))
    if fr.total_s > 3:
        f.append(Finding("speed", 3, "load", f"HTML download took {fr.total_s:.2f}s.", f"the page needs {fr.total_s:.1f}s just to download"))
    if fr.html_bytes > 10_000 and not fr.compressed:
        f.append(Finding("speed", 2, "compression", f"{fr.html_bytes // 1024} KB HTML served without gzip/brotli.", f"{fr.html_bytes // 1024} KB of HTML is served uncompressed"))
    if page["blocking_scripts"] >= 2:
        f.append(Finding("speed", 2, "blocking scripts", f"{page['blocking_scripts']} render-blocking scripts in <head>.", f"{page['blocking_scripts']} render-blocking scripts delay first paint"))
    if not page["viewport"]:
        f.append(Finding("seo", 3, "mobile", "Missing viewport meta tag; page is not mobile-friendly.", "there is no mobile viewport tag, so phones get a shrunken desktop page"))
    if not page["meta_description"]:
        f.append(Finding("seo", 2, "meta description", "No meta description; search snippets are auto-generated.", "there is no meta description for search results"))
    elif len(page["meta_description"]) > 170:
        f.append(Finding("seo", 1, "meta description", "Meta description is over 170 characters and will be truncated.", "your meta description gets truncated in search"))
    t = page["title"]
    if not t or len(t) < 15 or t.lower() in {"home", "untitled", "welcome"}:
        f.append(Finding("seo", 2, "title", f"Weak page title: {t!r}.", f"your page title is just '{t or 'empty'}'"))
    if page["h1_count"] != 1:
        f.append(Finding("seo", 1, "h1", f"{page['h1_count']} <h1> elements (expected exactly 1).", f"{page['h1_count']} competing H1 headings"))
    if page["images"] and page["images_missing_alt"] / page["images"] > 0.3:
        f.append(Finding("seo", 1, "alt", f"{page['images_missing_alt']}/{page['images']} images lack alt text.", f"{page['images_missing_alt']} of {page['images']} images lack alt text"))
    if not page["ctas"]:
        f.append(Finding("conversion", 3, "call to action", "No clear call-to-action found.", "no clear call-to-action on the page"))
    elif len(page["generic_ctas"]) >= 2:
        f.append(Finding("conversion", 2, "call to action", f"{len(page['generic_ctas'])} generic CTAs ({', '.join(page['generic_ctas'][:3])}).", f"calls to action say '{page['generic_ctas'][0]}' instead of a specific outcome"))
    if page["form_fields"] and max(page["form_fields"]) > 6:
        n = max(page["form_fields"])
        f.append(Finding("funnel", 3, "form", f"Lead form has {n} fields; each extra field typically reduces completion.", f"your lead form asks for {n} fields"))
    if not page["social_proof"]:
        f.append(Finding("trust", 2, "social proof", "No testimonials, case studies or customer counts detected.", "there is no visible social proof"))
    if not page["has_phone_or_email_link"] and not page["has_contact_link"]:
        f.append(Finding("funnel", 2, "contact", "No contact path (tel/mailto/contact link).", "there is no obvious contact path"))
    if not fr.https:
        f.append(Finding("trust", 3, "https", "Site is not served over HTTPS (ignored for local demo targets).", "the site is not on HTTPS"))
    if not page["has_structured_data"]:
        f.append(Finding("seo", 1, "structured data", "No JSON-LD structured data.", "there is no structured data for rich results"))
    f.sort(key=lambda x: (-x.severity, x.area))

    score = 100
    for x in f:
        score -= {3: 12, 2: 6, 1: 2}[x.severity]
    scores = {"overall": max(0, score), "issues": len(f)}
    return f, scores


def word_count(s: str) -> int:
    return len(s.split())


def _domain(url: str) -> str:
    return urllib.parse.urlparse(url).hostname or url


def template_outreach(ceo: str, company: str, findings: list[Finding], sender: str) -> str:
    """Deterministic, always-valid fallback. Trims findings until it fits the word budget."""
    picks = findings[:3] or []
    while True:
        if picks:
            items = "; ".join(f"({i}) {p.short}" for i, p in enumerate(picks, 1))
            body = (f"Hi {ceo}, I ran a quick technical review of {company}'s site and found fixable leaks between visitors and enquiries: "
                    f"{items}. I've written up the evidence with fixes ordered by effort. Want me to send the one-page audit? - {sender}")
        else:
            body = (f"Hi {ceo}, I ran a quick technical review of {company}'s site and found no major leaks - nicely done. "
                    f"I did note a few minor refinements. Want me to send the short audit? - {sender}")
        if word_count(body) <= MAX_WORDS - 5 or len(picks) <= 1:
            return body
        picks = picks[:-1]


def validate_outreach(text: str, ceo: str, findings: list[Finding]) -> list[str]:
    errs = []
    if word_count(text) > MAX_WORDS:
        errs.append(f"{word_count(text)} words (> {MAX_WORDS})")
    if ceo.lower() not in text.lower():
        errs.append("does not address the CEO by name")
    if re.search(r"\[[^\]]+\]|\{[^}]+\}|<[^>]+>", text):
        errs.append("contains unfilled placeholder")
    if findings and not any(f.keyword.lower() in text.lower() or any(w in text.lower() for w in f.short.lower().split()[-3:]) for f in findings[:5]):
        errs.append("does not reference a concrete finding")
    if "?" not in text:
        errs.append("no call-to-action question")
    if re.search(r"\b(guarantee|100%|revolutionary|game[- ]changing)\b", text, re.I):
        errs.append("hype/claims language")
    return errs


def generate_outreach(llm, url: str, ceo: str, company: str, findings: list[Finding], sender: str = "Alex") -> tuple[str, dict]:
    fallback = template_outreach(ceo, company, findings, sender)
    facts = "\n".join(f"- {f.detail}" for f in findings[:5]) or "- no major issues"
    prompt = (f"Write a cold outreach message to {ceo}, CEO of {company} ({_domain(url)}).\n"
              f"Verified diagnostic findings (use only these, never invent numbers):\n{facts}\n\n"
              f"Rules: under {MAX_WORDS - 15} words total; address {ceo} by name; cite the 2-3 most revenue-relevant findings "
              f"with their measured numbers; no flattery, no hype, no guarantees; end with one low-friction question; sign as {sender}. "
              f"Output only the message.")
    meta = {"source": "template", "attempts": 0, "errors": []}
    for attempt in range(2):
        res = llm.complete(prompt, system="You are a senior B2B growth consultant writing surgical, evidence-based outreach.",
                           fallback=fallback, max_tokens=300)
        meta["attempts"] += 1
        text = res.text.strip().strip('"')
        errs = validate_outreach(text, ceo, findings)
        if not errs:
            meta["source"] = "llm" if res.live else "template"
            return text, meta
        meta["errors"].append(errs)
        prompt += f"\n\nYour previous draft was rejected: {'; '.join(errs)}. Fix this."
    return fallback, meta


def run_sniper(url: str, ceo: str = "there", company: str | None = None, llm=None, allow_private: bool = False,
               html_file: str | None = None, sender: str = "Alex") -> dict:
    if html_file:
        html = open(html_file, encoding="utf-8", errors="replace").read()
        fr = FetchResult(url, 200, 0.0, 0.0, len(html.encode()), len(html.encode()), True, url.startswith("https"), {}, html)
    else:
        fr = fetch(url, allow_private=allow_private)
    page = parse_page(fr.html)
    findings, scores = diagnose(fr, page)
    if allow_private:  # local demo/test targets are plain http by construction
        findings = [f for f in findings if f.keyword != "https"]
        scores["overall"] = min(100, scores["overall"] + (12 if not fr.https else 0))
        scores["issues"] = len(findings)
    company = company or _domain(url)
    if llm is None:
        from config import Settings
        from llm import LLMClient
        llm = LLMClient(Settings.load())
    outreach, meta = generate_outreach(llm, url, ceo, company, findings, sender)
    return {
        "url": url, "company": company, "ceo": ceo, "status": fr.status,
        "performance": {"ttfb_s": round(fr.ttfb_s, 3), "total_s": round(fr.total_s, 3), "html_kb": round(fr.html_bytes / 1024, 1),
                        "compressed": fr.compressed},
        "page": page, "findings": [f.to_dict() for f in findings], "scores": scores,
        "outreach": outreach, "outreach_words": word_count(outreach), "outreach_meta": meta,
    }


def load_targets(path: str, limit: int = 500) -> list[dict]:
    """CSV with columns url,ceo,company (company optional). Blank/invalid URLs are skipped."""
    import csv
    out = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            url = (row.get("url") or "").strip()
            if url:
                out.append({"url": url, "ceo": (row.get("ceo") or "there").strip(), "company": (row.get("company") or "").strip() or None})
            if len(out) >= limit:
                break
    return out


def run_batch(targets: list[dict], llm, sender: str = "Alex", allow_private: bool = False) -> list[dict]:
    """Audit many prospects; one failure never aborts the batch. Local fetch/parse is free - only the draft uses the LLM
    (identical drafts hit the cache), and the CFO breaker degrades to the deterministic template when budget runs out."""
    results = []
    for t in targets:
        try:
            r = run_sniper(t["url"], t["ceo"], t["company"], llm=llm, allow_private=allow_private, sender=sender)
            r["ready"] = not validate_outreach(r["outreach"], r["ceo"], [Finding(**f) for f in r["findings"]])
        except (UnsafeURL, urllib.error.URLError, OSError, ValueError) as exc:
            r = {"url": t["url"], "ceo": t["ceo"], "error": str(exc), "ready": False}
        results.append(r)
    return results


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("url")
    ap.add_argument("--ceo", default="there")
    ap.add_argument("--company")
    ap.add_argument("--sender", default="Alex")
    ap.add_argument("--html-file", help="analyze a saved HTML file instead of fetching")
    ap.add_argument("--allow-private", action="store_true", help="allow private/loopback targets (disables SSRF guard)")
    a = ap.parse_args(argv)
    try:
        r = run_sniper(a.url, a.ceo, a.company, allow_private=a.allow_private, html_file=a.html_file, sender=a.sender)
    except (UnsafeURL, urllib.error.URLError, OSError) as exc:
        print(f"error: {exc}")
        return 1
    print(json.dumps(r, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
