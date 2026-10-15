"""Gumroad / LemonSqueezy launch kit for the CRM Clipper extension.

Claims policy: every feature line is taken from what the packaged extension actually does (checked in tests against
manifest.json / db.js). The LLM may only polish the hero paragraph, and its output is rejected unless it passes
validation (no invented numbers, no superlatives, no guarantees) - then the deterministic copy is used.
Review-derived statistics and quotes are NEVER used in customer-facing copy (they may come from a sample set).
"""
from __future__ import annotations

import re

PRODUCT = "Offline CRM Clipper"
TITLE = f"{PRODUCT}: Clip Leads Into a Private, Offline CRM - Lifetime Deal"
TAGLINE = "Save leads from any page in one click. Your data stays in your browser until you choose to sync it."
PRICE_SOLO, PRICE_TEAM = 39, 99

# (feature, evidence token that must exist in the extension source) - verified by tests.
FEATURES = [
    ("One-click clipping from the toolbar popup or the right-click menu (selection, page or link)", "contextMenus"),
    ("Offline-first: clips are stored locally in your browser (IndexedDB) - no account, no server required", "indexedDB"),
    ("Optional webhook sync to your own endpoint (Zapier, Make, n8n, your CRM), with automatic retry and backoff", "markFailed"),
    ("Signed deliveries: add a secret and each webhook carries an HMAC-SHA256 signature you can verify", "HMAC"),
    ("Auto-detects email addresses in selected text and pre-fills the form", "extractEmail"),
    ("Lead stages (lead, contacted, qualified, won, lost), tags and notes; instant local search", "stage"),
    ("One-click CSV export of every clip (spreadsheet-formula safe)", "toCSV"),
    ("Asks for access to your webhook host only when you add it - no blanket site permissions", "optional_host_permissions"),
]
THEMES = {
    "pricing": "no per-seat subscription - one payment, yours to keep",
    "performance": "instant, local - nothing to load from a server",
    "missing_feature": "offline capture and a webhook for syncing wherever you need",
    "support": "simple enough to need very little support",
}
HYPE = re.compile(r"\b(guarantee[sd]?|best|#1|number one|revolutionary|game[- ]changing|unlimited|risk[- ]free|"
                  r"thousands?|millions?|trusted by|award)\b", re.I)


def hero_ok(text: str) -> bool:
    nums = set(re.findall(r"\b\d[\d,]*(?:\.\d+)?\b", text))  # standalone numbers only ("SHA256" is not a claim)
    return bool(text) and len(text.split()) <= 90 and not HYPE.search(text) and nums <= {str(PRICE_SOLO), str(PRICE_TEAM)}


def hero_fallback(themes: list[str]) -> str:
    hooks = "; ".join(THEMES[t] for t in themes if t in THEMES) or THEMES["pricing"]
    return (f"{PRODUCT} is a lightweight Chrome extension for saving leads while you browse. Clip a name, email, "
            f"company and notes in one click and keep everything in a private, offline database in your browser. "
            f"Why it is different: {hooks}.")


def build_launch_copy(report: dict, llm, sample_data: bool = True) -> tuple[str, dict]:
    themes = list(report.get("categories", {}))[:4]
    fallback = hero_fallback(themes)
    facts = "; ".join(f for f, _ in FEATURES[:5])
    res = llm.complete(
        f"Write a 2-3 sentence product description for '{PRODUCT}', a Chrome extension priced at one-time ${PRICE_SOLO}. "
        f"Use ONLY these facts: {facts}. Angles that matter to buyers: {', '.join(THEMES[t] for t in themes if t in THEMES)}. "
        f"No statistics, no superlatives, no guarantees. Output only the description.",
        system="You write plain, specific, honest software product copy. Never invent claims, numbers or testimonials.",
        fallback=fallback, max_tokens=300)
    hero = res.text.strip().strip('"')
    source = "llm" if res.live else "template"
    if not hero_ok(hero):
        hero, source = fallback, "template"
    md = [f"# Launch Kit - {PRODUCT}", "",
          "> Internal doc. Review the **[bracketed]** items before publishing; everything else is ready to paste.", "",
          "## Product title (Gumroad / LemonSqueezy)", "", TITLE, "",
          "## Tagline", "", TAGLINE, "",
          f"## Description  _(source: {source})_", "", hero, "",
          "### What you get", ""] + [f"- {f}" for f, _ in FEATURES] + [
          "", "### How it works", "",
          "1. Install the extension and pin it to your toolbar.",
          "2. Browse as usual. Select text on a page, click the icon (or right-click -> *Clip to CRM*), add a name, stage and note.",
          "3. Your clips stay on your device. Add a webhook URL in settings and they sync to your own tools whenever you are online.", "",
          "### Who it is for", "",
          "Freelancers, consultants, small agencies and founders who prospect in the browser and want a fast, private place "
          "to capture leads without paying per-seat CRM pricing.", "",
          "## Pricing tiers (suggested - your call)", "",
          "| Tier | Price | Includes |", "|---|---|---|",
          f"| **Lifetime - Solo** | **${PRICE_SOLO}** one-time | the extension, all v1.x updates you download, personal/commercial use on your own devices |",
          f"| **Lifetime - Team (5 users)** | ${PRICE_TEAM} one-time | five installs for one team |", "",
          "Tip: price on Gumroad as a fixed price (not pay-what-you-want) and describe it as a *launch price* only if you actually "
          "plan to raise it - do not show a fake 'was' price.", "",
          "## FAQ", "",
          "**Does it send my data anywhere?** No. Clips live in your browser's IndexedDB. The only network request it makes is the "
          "webhook you configure yourself, and it asks Chrome for permission to that one host.", "",
          "**Does it work offline?** Yes. Clipping, search and export work offline; sync retries automatically when you are back online.", "",
          "**How do I install it?** [Add Chrome Web Store link after publishing.] Until then: unzip the download, open "
          "`chrome://extensions`, enable *Developer mode*, choose *Load unpacked* and select the folder.", "",
          "**Can I verify webhook deliveries?** Yes - set a secret and check the `X-Signature: sha256=...` header (HMAC-SHA256 of the body).", "",
          "**Refund policy:** [state your policy here - e.g. refunds within 14 days.]", "",
          "## Gumroad / LemonSqueezy checklist", "",
          "- [ ] Upload `crm_clipper_extension.zip` as the deliverable (manifest.json is at the zip root, ready for the Chrome Web Store).",
          "- [ ] Add 3-5 screenshots of the popup, the clip list and the CSV export (take them from the loaded extension).",
          "- [ ] Publish to the Chrome Web Store ($5 one-time developer fee) and paste the link above; privacy policy: 'no data collected'.",
          "- [ ] Do not add testimonials, user counts or ratings until they are real.", ""]
    if sample_data:
        md += ["---", "_Internal note (delete before publishing): pain themes were derived from the bundled **sample** review set, "
               "not real market data. Run with `REVIEWS_FILE=your_reviews.csv` (columns: rating,text) to ground the positioning "
               "in real complaints. No review statistics or quotes are used in the copy above._", ""]
    return "\n".join(md), {"hero_source": source, "themes": themes}
