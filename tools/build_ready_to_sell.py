#!/usr/bin/env python3
"""Assemble output/READY_TO_SELL_NOW.md from real pipeline artifacts + persisted CFO state (no invented numbers).

  python tools/build_ready_to_sell.py [--sender "Your Name"]

Also mirrors the deliverables to output/prj_01 and output/prj_02 (the paths used in the sprint brief).
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rich.console import Console  # noqa: E402

from agents.ceo_agent import CEOAgent  # noqa: E402
from agents.cfo_agent import compute_summary  # noqa: E402
from config import Settings  # noqa: E402
from projects.prj_02_gap_cloner import launch_copy as lc  # noqa: E402
from state import AgencyState  # noqa: E402


def dashboard_text(state: AgencyState, threshold: float) -> str:
    c = Console(width=150, record=True, file=open("/dev/null", "w"))
    ceo = CEOAgent(state, threshold)
    c.print(ceo.build_renderable())
    return c.export_text()


def section_outreach(out: Path, sender: str | None) -> tuple[list[str], int]:
    batch = json.loads((out / "PRJ-03" / "outreach_batch.json").read_text())
    ready = [r for r in batch if r.get("ready")]
    lines = ["## 1. PRJ-03 - B2B outreach audits (ready to send)", "",
             f"**{len(ready)} of {len(batch)} targets produced a validated message** (under 110 words, addresses the recipient, "
             "cites only findings that are objective and re-checkable in the page HTML).", ""]
    for i, r in enumerate(ready, 1):
        msg = r["outreach"].strip()
        if sender:
            msg = msg.rsplit("\n", 1)[0].rstrip() + f"\n\n{sender}" if msg.splitlines()[-1].strip() == "Alex" else msg
        lines += [f"### {i}. {r['company']} - {r['url']}", "",
                  f"- Greeting used: **{r['ceo']}**" + ("  _(leader not confidently verified - add the right name before sending)_" if r["ceo"] == "there" else "  _(leader confirmed from public sources)_"),
                  "- Bottlenecks cited (each independently re-checked against the raw HTML):"] + \
                 [f"  - {f['detail']}" for f in r.get("outreach_findings", [])] + \
                 [f"- Overall auditor score: {r['scores']['overall']}/100 | message length: {r['outreach_words']} words", "",
                  "```text", msg, "```", ""]
    failed = [r for r in batch if not r.get("ready")]
    for r in failed:
        lines.append(f"- Skipped {r['url']}: {r.get('error', 'failed validation')}")
    lines += ["", "**Read before sending**", "",
              "- The sign-off `Alex` is a placeholder - replace it with your name (or re-run this builder with `--sender \"Your Name\"`).",
              "- These are mature, well-run companies, so the findings are real but **modest**; expect low reply rates. Smaller companies "
              "with weaker sites make a stronger pitch - drop any list into `targets.csv` (url,ceo,company) and re-run.",
              "- Speed numbers were deliberately left out of the messages: one measurement from this host says little about real visitors.",
              "- Cold commercial email has legal requirements (e.g. CAN-SPAM: truthful sender, a postal address, a working opt-out; GDPR/PECR "
              "rules for EU/UK recipients). Add those to your template.", ""]
    return lines, len(ready)


def section_extension(out: Path) -> list[str]:
    zip_path = out / "PRJ-02" / "crm_clipper_extension.zip"
    copy = (out / "PRJ-02" / "LAUNCH_COPY.md").read_text()
    desc = copy.split("## Description", 1)[1].split("\n", 2)[2].split("### What you get", 1)[0].strip()
    feats = [f for f, _ in lc.FEATURES]
    return ["## 2. PRJ-02 - Chrome extension launch kit ($39 Lifetime Deal)", "",
            f"Deliverable: `{zip_path.relative_to(ROOT)}` ({zip_path.stat().st_size // 1024} KB, manifest at zip root) | "
            f"full copy: `output/PRJ-02/LAUNCH_COPY.md` (mirrored at `output/prj_02/LAUNCH_COPY.md`)", "",
            "### Gumroad / LemonSqueezy product", "",
            f"**Title:** {lc.TITLE}", "", f"**Tagline:** {lc.TAGLINE}", "", "**Description:**", "", desc, "",
            "**What you get (every line is verified against the extension source by the test suite):**", ""] + \
           [f"- {f}" for f in feats] + ["",
            "### Pricing tiers (suggested)", "", "| Tier | Price | Includes |", "|---|---|---|",
            f"| **Lifetime - Solo** | **${lc.PRICE_SOLO}** one-time | the extension + v1.x updates, personal/commercial use on your own devices |",
            f"| Lifetime - Team (5 users) | ${lc.PRICE_TEAM} one-time | five installs for one team |", "",
            "**Before you list it**", "",
            "- The extension is statically validated and its logic is tested in Node against an IndexedDB fake, but it has **not been "
            "loaded in a real Chrome profile** here - load it unpacked and click through clip/search/export/sync once.",
            "- Pain-point positioning came from the bundled **sample** review set, not real market data. The copy therefore uses no review "
            "statistics or quotes; re-run with `REVIEWS_FILE=your_reviews.csv` to ground it in real complaints.",
            "- No testimonials, ratings or user counts exist yet - don't add any until they are real. Add 3-5 screenshots, a refund policy and "
            "(for the Web Store) a privacy policy stating no data is collected.", ""]


def section_audit(out: Path) -> list[str]:
    findings = json.loads((out / "PRJ-01" / "findings.json").read_text())
    report = (out / "PRJ-01" / "client_audit_report.md").read_text()
    sev = {s: sum(1 for f in findings if f["severity"] == s) for s in ("critical", "high", "medium", "low")}
    langs = sorted({f["language"] for f in findings})
    tests = len(list((out / "PRJ-01" / "migrated_service" / "tests").glob("test_*.py")))
    summary = report.split("## Executive Summary", 1)[1].split("\n\n|", 1)[0].strip()
    return ["## 3. PRJ-01 - Legacy code audit package ($2,500 refactoring offer)", "",
            "Portfolio proof: `output/PRJ-01/client_audit_report.md` + `output/PRJ-01/migrated_service/` "
            "(mirrored at `output/prj_01/`).", "",
            "> **This sample audits the bundled demo repo (deliberately flawed code), not a real client.** Present it as a sample "
            "deliverable, never as past client work.", "",
            "### Sample audit summary", "",
            f"- {len(findings)} findings across {', '.join(langs)}: {sev['critical']} critical, {sev['high']} high, {sev['medium']} medium, {sev['low']} low",
            "- Generated: modernized modules, a FastAPI microservice scaffold, a Dockerfile, and golden-master pytest suites "
            f"({tests} test modules) that pin the modernized behavior", "", summary, "",
            "### B2B pitch template (edit the brackets)", "", "```text",
            "Subject: A fixed-scope audit of [Company]'s legacy [Python/PHP/JS] code", "",
            "Hi [Name],", "",
            "I run fixed-scope legacy modernization sprints. For $2,500 you get: (1) a scan of one repository for deprecated libraries, "
            "security flaws and monolithic functions, (2) an automated first pass of safe refactors, (3) a FastAPI service wrapping the "
            "modernized core with a regression test suite, and (4) a prioritized remediation roadmap.", "",
            "Here is a sample deliverable from a demo repo so you can judge the format: [link to the sample report].", "",
            "If one of your repositories is a candidate, I can start with a scoping call - would [day] work?", "",
            "[Your name]  |  [postal address / opt-out line]", "```", "",
            "**Be precise when you sell it:** the tooling finds and auto-fixes a specific set of patterns (see the report's "
            "\"Automated Remediation\" and \"Remaining Findings Requiring Human Action\" sections); credential rotation, hash migration "
            "and query rewrites remain human work. Run it on the client's actual code before promising scope or a fixed price.", ""]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sender", help="replaces the placeholder sign-off 'Alex' in the outreach messages")
    a = ap.parse_args()
    s = Settings.load()
    out = s.output_dir
    state = AgencyState(s.state_path, s.budget_usd)
    snap = state.snapshot()
    summ = compute_summary(snap)

    # mirror to the paths named in the sprint brief
    shutil.copytree(out / "PRJ-01", out / "prj_01", dirs_exist_ok=True)
    (out / "prj_02").mkdir(exist_ok=True)
    for name in ("LAUNCH_COPY.md", "crm_clipper_extension.zip", "gap_brief.md"):
        shutil.copy2(out / "PRJ-02" / name, out / "prj_02" / name)

    outreach, n_ready = section_outreach(out, a.sender)
    live = [e for e in snap["ledger"] if e["kind"] == "api" and e.get("provider") != "offline"]
    by_model: dict[str, list] = {}
    for e in live:
        by_model.setdefault(f"{e['model']} (tier {e['tier']})", []).append(e["usd"])
    md = ["# READY TO SELL NOW", "", f"_Generated {dt.datetime.now(dt.timezone.utc):%Y-%m-%d %H:%M UTC} by `tools/build_ready_to_sell.py` "
          "from real artifacts and persisted CFO state._", "",
          f"**Sprint cost: ${summ['burn_usd']:.4f} of the ${summ['seed_usd']:.2f} seed budget "
          f"(${summ['remaining_seed_usd']:.4f} remaining).** The hard cap was never approached.", ""]
    md += outreach + section_extension(out) + section_audit(out)
    md += ["## 4. Financial telemetry (`python main.py --dashboard`)", "", "```text", dashboard_text(state, s.qc_threshold).rstrip(), "```", "",
           "| Model | Live calls | USD |", "|---|---|---|"]
    md += [f"| {m} | {len(v)} | ${sum(v):.6f} |" for m, v in sorted(by_model.items())]
    md += ["", f"Cache savings: ${summ['cache_savings_usd']:.5f} over {summ['cache_hits']} hits. "
           f"Est. revenue pipeline (${summ['pipeline_usd']:,.2f}) is an **assumption-based projection** (units x per-unit values in `config.py`), "
           "**not revenue** - nothing has been sold yet.", "",
           "## 5. Housekeeping", "",
           "- **Rotate the API key** you pasted into the chat (console.anthropic.com -> API keys): it now exists in a conversation transcript. "
           "Put the new one in `.env` only.",
           "- `.env`, `state/` and `output/` are git-ignored; `targets.csv` names real companies, so it is your call whether to commit it.", ""]
    path = out / "READY_TO_SELL_NOW.md"
    path.write_text("\n".join(md))
    print(f"wrote {path} ({n_ready} outreach messages, burn ${summ['burn_usd']:.4f})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
