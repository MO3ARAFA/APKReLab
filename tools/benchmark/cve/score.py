#!/usr/bin/env python3
"""2.0.0 step 1: score the real-CVE benchmark. Reads cases.json (frozen before any scan) and the reports
<dir>/<id>_before.md and <dir>/<id>_after.md written by SandboxScan, and prints one line per case.
A card MATCHES a case when: its rule is in the case's rules (a trailing * is a prefix) AND one of the case's
anchors appears in the card text (title, Location, evidence). Severity order CRITICAL > HIGH > MEDIUM > LOW.
  DETECTED      = a matching card at MEDIUM or above in 'before', and in 'after' no matching card at that severity or above
  NOT-DIFFERENT = a matching card at MEDIUM or above in 'before' and the same or higher in 'after'
  LOW-ONLY      = matching cards in 'before' only at LOW
  MISSED        = no matching card in 'before'
Usage: score.py <reports dir> [--json out.json] [--secondary] [--mustfix]\n  --mustfix (2.0.2): the HEADLINE metric: how many valid in-scope cases put a card of the advisory's class in the Verdict's MUST FIX list, and in how many the patched build drops it.
  --secondary (added in 2.0.1, after run 1, NOT part of the frozen score): the fix is also "gate-visible" when the before card says "no validation seen"
  and the after card says "validation-like calls seen on the path", the very condition the MUST FIX gate uses."""
import json, re, sys, os
SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
def cards(path):
    if not os.path.exists(path): return None
    t = open(path, encoding="utf-8", errors="replace").read()
    out = []
    for m in re.finditer(r"^#### \d+\. \[(\w+)\] (.*?)(?=^#### |^## |\Z)", t, re.M | re.S):
        body = m.group(0); r = re.search(r"Rule: ([\w-]+)", body)
        out.append((SEV.get(m.group(1), 0), r.group(1) if r else "", body))
    return out
def ruleok(rule, rules): return any(rule == x or (x.endswith("*") and rule.startswith(x[:-1])) for x in rules)
def best(cs, case):
    hits = [(s, r, b) for s, r, b in cs if ruleok(r, case["rules"]) and any(a in b for a in case["anchors"])]
    return max(hits, key=lambda h: h[0]) if hits else None
def valflag(card):
    """Secondary, defined AFTER run 1 (2.0.1): the card's own 'Why:' line says 'no validation seen' or 'validation-like calls seen on the path'."""
    m = re.search(r"^- Why: (.*)$", card[2], re.M)
    w = m.group(1) if m else ""
    return "no-val" if "no validation seen" in w else "val-like" if "validation-like calls seen" in w else "-"
def mustfix_cards(path):
    """2.0.2: the (number, severity, text) of the cards the report's Verdict lists under MUST FIX."""
    if not os.path.exists(path): return None
    t = open(path, encoding="utf-8", errors="replace").read()
    m = re.search(r"- \*\*MUST FIX:\*\*(.*?)(?=\n- \*\*CONFIDENCE|\Z)", t.split("## App info")[0], re.S)
    out = []
    for n, sev, _ in (re.findall(r"#(\d+) \[(\w+)\] (.*?) \(", m.group(1)) if m else []):
        b = re.search(r"^#### %s\. .*?(?=^#### |^## |\Z)" % n, t, re.M | re.S)
        out.append((int(n), sev, b.group(0) if b else ""))
    return out
def main():
    d = sys.argv[1]; cases = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases.json")))
    res = []
    for c in cases:
        if c["scope"] != "in": res.append((c["id"], c["cve"], "OUT-OF-SCOPE", "", "")); continue
        b = cards(os.path.join(d, c["id"] + "_before.md")); a = cards(os.path.join(d, c["id"] + "_after.md"))
        if b is None or a is None: res.append((c["id"], c["cve"], "NOT-SCANNED", "", "")); continue
        hb = best(b, c); ha = best(a, c)
        inv = {v: k for k, v in SEV.items()}
        if hb is None: v = "MISSED"
        elif hb[0] < 2: v = "LOW-ONLY"
        elif ha is not None and ha[0] >= hb[0]: v = "NOT-DIFFERENT"
        else: v = "DETECTED"
        res.append((c["id"], c["cve"], v, (inv[hb[0]] + " " + hb[1]) if hb else "-", (inv[ha[0]] + " " + ha[1]) if ha else "-"))
        if "--secondary" in sys.argv and hb is not None and hb[0] >= 2:
            sec = "gate-visible" if (v == "DETECTED" or (ha is not None and valflag(hb) == "no-val" and valflag(ha) == "val-like")) else "-"
            print("   secondary %s: before %s, after %s -> %s" % (c["id"], valflag(hb), valflag(ha) if ha else "gone", sec))
    for r in res: print("%s %-15s %-13s before: %-40s after: %s" % r)
    ins = [r for r in res if r[2] != "OUT-OF-SCOPE"]
    print("in scope: %d  DETECTED: %d  NOT-DIFFERENT: %d  LOW-ONLY: %d  MISSED: %d  NOT-SCANNED: %d" % (len(ins),
          *[sum(r[2] == k for r in ins) for k in ("DETECTED", "NOT-DIFFERENT", "LOW-ONLY", "MISSED", "NOT-SCANNED")]))
    if "--mustfix" in sys.argv:
        ok = [c for c in cases if c["scope"] == "in" and c.get("valid_pair", True)]
        rec = drop = 0
        for c in ok:
            b = mustfix_cards(os.path.join(d, c["id"] + "_before.md")); a = mustfix_cards(os.path.join(d, c["id"] + "_after.md"))
            if b is None or a is None: continue
            rb = [x for x in b if any(an in x[2] for an in c["anchors"])]; ra = [x for x in a if any(an in x[2] for an in c["anchors"])]
            if rb: rec += 1
            if rb and not ra: drop += 1
            print("   mustfix %s: before related %d of %d, after related %d of %d" % (c["id"], len(rb), len(b), len(ra), len(a)))
        print("HEADLINE (2.0.2): MUST FIX recall %d of %d valid in-scope cases; of those, the patched build drops the card in %d" % (rec, len(ok), drop))
    if "--json" in sys.argv: json.dump(res, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
if __name__ == "__main__": main()
