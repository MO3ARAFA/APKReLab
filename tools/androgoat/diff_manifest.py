#!/usr/bin/env python3
"""Usage: python3 diff_manifest.py report_0.41.0.md report_0.42.0.md
Compares the MANIFEST findings (Location: AndroidManifest.xml) of two exported Markdown reports of the SAME apk
(Report chip -> Markdown). Expected result for 0.41.0 -> 0.42.0 (pure refactor): no ADDED / REMOVED / SEVERITY lines.
Allowed differences: new `Rule: manifest-...` ids, `CWE-489` on the testOnly finding, and Confidence on a few findings."""
import re, sys
def load(p):
    t = open(p, encoding="utf-8", errors="ignore").read()
    out = {}
    for blk in re.split(r"\n(?=#### \d+\. \[)", t):
        m = re.match(r"#### \d+\. \[(\w+)\] (.+?)(?: \(x\d+\))?\n", blk)
        if not m or "Location: `AndroidManifest.xml`" not in blk:
            continue
        rule = re.search(r"Rule: (manifest-[\w-]+)", blk)
        cwe = re.search(r"CWE: (CWE-\d+)", blk)
        conf = re.search(r"Confidence: (\w+)", blk)
        out[m.group(2)] = (m.group(1), rule.group(1) if rule else "-", cwe.group(1) if cwe else "-", conf.group(1) if conf else "-")
    return out
a, b = load(sys.argv[1]), load(sys.argv[2])
bad = 0
for t in sorted(set(a) - set(b)): print("REMOVED   ", t); bad += 1
for t in sorted(set(b) - set(a)): print("ADDED     ", t); bad += 1
for t in sorted(set(a) & set(b)):
    if a[t][0] != b[t][0]: print("SEVERITY  ", t, a[t][0], "->", b[t][0]); bad += 1
    elif a[t][2:] != b[t][2:] or a[t][1] != b[t][1]:
        print("info      ", t, "| rule", a[t][1], "->", b[t][1], "| cwe", a[t][2], "->", b[t][2], "| conf", a[t][3], "->", b[t][3])
print(f"\n{len(a)} manifest findings (old) vs {len(b)} (new); {bad} real difference(s)")
sys.exit(1 if bad else 0)
