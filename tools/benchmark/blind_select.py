#!/usr/bin/env python3
"""Phase 4 (docs/VALIDATION.md): picks the blind apps from an F-Droid index, by a rule fixed BEFORE any download.

  python3 -I tools/benchmark/blind_select.py <index-v1.json> <touched.txt> [seed] [count]

Candidates: every package of the index that is not in touched.txt (one package name per line: every name ever written in the repository, ./private, the
benchmark and recall-kit folders) and whose latest version's APK is 3-40 MB. They are sorted by name, shuffled with the given seed, and the first [count] are
taken as they come: no app is skipped after this point for any reason other than a failed download.
"""
import json, random, sys


def main():
    idx, touched_path = sys.argv[1], sys.argv[2]
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 20261031
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 3
    touched = {l.strip() for l in open(touched_path, encoding="utf-8") if l.strip()}
    data = json.load(open(idx, encoding="utf-8"))
    cands = []
    for pkg, versions in data["packages"].items():
        if pkg in touched or not versions:
            continue
        v = max(versions, key=lambda x: x.get("versionCode", 0))
        if 3_000_000 <= v.get("size", 0) <= 40_000_000 and v.get("apkName"):
            cands.append((pkg, v["versionCode"], v.get("versionName", ""), v["apkName"], v.get("hash", ""), v.get("size", 0)))
    cands.sort()
    random.Random(seed).shuffle(cands)
    print("candidates=%d seed=%d" % (len(cands), seed))
    for c in cands[:count]:
        print("\t".join(str(x) for x in c))


if __name__ == "__main__":
    main()
