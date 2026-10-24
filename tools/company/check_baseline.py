#!/usr/bin/env python3
"""Regression check for the company apps (see COMPANY_APPS.md).
usage: check_baseline.py <report.md> <app-key> [--write]
Reads the Markdown report of one scan and compares it with baselines.json: counts of cards by severity and scope, the number of attack scenarios, and the identities of the
HIGH / CRITICAL cards (stored as short hashes: the repository never holds the class names of an unfixed finding). Prints what is NEW or GONE; exit code 1 when a new
HIGH / CRITICAL card appears. --write stores the counts of this report as the new baseline (do it only after reading every difference)."""
import sys, re, json, hashlib, collections, os

def parse(path):
    t = open(path, encoding="utf-8", errors="ignore").read()
    sec = t.split("## Security scan", 1)[1].split("## Third-Party", 1)[0] if "## Security scan" in t else ""
    cards = []
    for b in re.split(r"\n#### (?=\d+\. \[)", sec)[1:]:
        h = b.split("\n", 1)[0]; m = re.match(r"\d+\. \[(\w+)\] (.*)", h)
        loc = re.search(r"- Location: `([^`]+)`", b); sc = re.search(r"Scope: (\w*)", b)
        cards.append(dict(sev=m.group(1), title=re.sub(r"\s*\(x\d+\)$", "", m.group(2)).strip(), loc=loc.group(1) if loc else "", scope=sc.group(1) if sc else "OTHER"))
    scen = t.split("## Attack scenarios", 1)[1].split("## MASVS", 1)[0] if "## Attack scenarios" in t else ""
    return cards, len(re.findall(r"^### \d+\. \[", scen, re.M)), t

def ident(c): return hashlib.sha1((c["title"] + "|" + c["loc"]).encode()).hexdigest()[:10]

def main():
    path, key = sys.argv[1], sys.argv[2]; write = "--write" in sys.argv
    here = os.path.dirname(os.path.abspath(__file__)); bp = os.path.join(here, "baselines.json")
    base = json.load(open(bp)); app = base["apps"][key]
    cards, scen, t = parse(path)
    cur = dict(cards=dict(collections.Counter(c["sev"] for c in cards)), scope=dict(collections.Counter(c["scope"] for c in cards)), scenarios=scen,
               high_plus=sorted(ident(c) for c in cards if c["sev"] in ("HIGH", "CRITICAL")))
    old = app.get("baseline")
    print(f"{key}: cards {cur['cards']} | scope {cur['scope']} | scenarios {scen}")
    bad = 0
    if old:
        new = [c for c in cards if c["sev"] in ("HIGH", "CRITICAL") and ident(c) not in old["high_plus"]]
        gone = [h for h in old["high_plus"] if h not in cur["high_plus"]]
        for c in new: print(f"  NEW {c['sev']}: {c['title']} | {c['loc']} | scope {c['scope']}")
        print(f"  HIGH+ gone since the baseline: {len(gone)}; scenarios {old['scenarios']} -> {scen}; cards by severity {old['cards']} -> {cur['cards']}")
        bad = len(new)
    if write: app["baseline"] = cur; json.dump(base, open(bp, "w"), indent=1); print("  baseline written")
    sys.exit(1 if bad else 0)

main()
