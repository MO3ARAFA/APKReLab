#!/usr/bin/env python3
"""Usage: python3 compare.py findings.txt
findings.txt = text of APKReLab's Security list / exported Report for the AndroGoat APK.
Prints which AndroGoat vulnerabilities the scanner caught (OK) and which it missed (MISS)."""
import json, sys, os
here = os.path.dirname(os.path.abspath(__file__))
exp = json.load(open(os.path.join(here, "androgoat_expected.json"), encoding="utf-8"))
txt = open(sys.argv[1], encoding="utf-8", errors="ignore").read().lower()
ok = 0
for e in exp:
    hit = [m for m in e["match_any"] if m.lower() in txt]
    ok += bool(hit)
    print(("OK   " if hit else "MISS ") + e["vuln"] + ("" if hit else "   <- need check: " + ", ".join(e["match_any"]) + "  [" + e["via"] + "]"))
print(f"\n{ok}/{len(exp)} covered")
