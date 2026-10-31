#!/usr/bin/env python3
"""2.0.0 step 1: score the real-CVE benchmark. Reads cases.json (frozen before any scan) and the reports
<dir>/<id>_before.md and <dir>/<id>_after.md written by SandboxScan, and prints one line per case.
A card MATCHES a case when: its rule is in the case's rules (a trailing * is a prefix) AND one of the case's
anchors appears in the card text (title, Location, evidence). Severity order CRITICAL > HIGH > MEDIUM > LOW.
  DETECTED      = a matching card at MEDIUM or above in 'before', and in 'after' no matching card at that severity or above
  NOT-DIFFERENT = a matching card at MEDIUM or above in 'before' and the same or higher in 'after'
  LOW-ONLY      = matching cards in 'before' only at LOW
  MISSED        = no matching card in 'before'
Usage: score.py <reports dir> [--json out.json]"""
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
    for r in res: print("%s %-15s %-13s before: %-40s after: %s" % r)
    ins = [r for r in res if r[2] != "OUT-OF-SCOPE"]
    print("in scope: %d  DETECTED: %d  NOT-DIFFERENT: %d  LOW-ONLY: %d  MISSED: %d  NOT-SCANNED: %d" % (len(ins),
          *[sum(r[2] == k for r in ins) for k in ("DETECTED", "NOT-DIFFERENT", "LOW-ONLY", "MISSED", "NOT-SCANNED")]))
    if "--json" in sys.argv: json.dump(res, open(sys.argv[sys.argv.index("--json") + 1], "w"), indent=1)
if __name__ == "__main__": main()
