#!/usr/bin/env python3
"""Independent check of the SCA matcher: for boundary versions of every advisory range, compare the app's answer (ScaOracle.kt) with a separate
implementation of the OSV range semantics on the RAW advisory data (this script). usage: oracle.py <advisory-database> <vulns.json> <out pairs.tsv> | compare <kotlin.tsv>"""
import glob, json, re, sys, collections
sys.path.insert(0, "/tmp/sca"); import mvn
adv_dir, vulns_json = sys.argv[2], sys.argv[3]
hand = json.load(open(vulns_json))["vulns"]
gen_ids = {v["id"].split(" / ")[0] for v in hand if v["id"].startswith("GHSA-")}
gen_coords = {(v["group"] + ":" + v["artifact"], v["id"].split(" / ")[0]) for v in hand if v["id"].startswith("GHSA-")}   # (coordinate, advisory) pairs that were generated
raw = collections.defaultdict(list)           # coordinate -> [(ghsa id, affected entry)]
for f in glob.glob(adv_dir + "/advisories/github-reviewed/*/*/*/*.json"):
    d = json.load(open(f))
    if d["id"] not in gen_ids: continue
    for a in d.get("affected", []):
        p = a.get("package", {})
        if p.get("ecosystem") == "Maven" and (p["name"], d["id"]) in gen_coords: raw[p["name"]].append((d["id"], a))
def neighbours(v):
    out = {v}
    parts = re.split(r"([.\-])", v)
    for i in range(len(parts) - 1, -1, -1):
        if parts[i].isdigit():
            n = int(parts[i]); 
            if n > 0: out.add("".join(parts[:i] + [str(n - 1)] + parts[i + 1:]))
            out.add("".join(parts[:i] + [str(n + 1)] + parts[i + 1:])); break
    return out
if sys.argv[1] == "pairs":
    pairs = set()
    for c, lst in raw.items():
        for _, a in lst:
            for r in a.get("ranges", []):
                for e in r.get("events", []):
                    for k in ("introduced", "fixed", "last_affected"):
                        if k in e and e[k] != "0": pairs |= {(c, x) for x in neighbours(e[k])}
            pairs |= {(c, x) for x in a.get("versions", [])[:3]}
        pairs.add((c, "0.0.1")); pairs.add((c, "999.0.0"))
    open(sys.argv[4], "w").write("\n".join(f"{c}\t{v}" for c, v in sorted(pairs)) + "\n"); print("pairs", len(pairs))
else:
    bad = 0; n = 0; both_empty = 0
    for line in open(sys.argv[4]):
        c, v, ids = line.rstrip("\n").split("\t"); got = set(filter(None, ids.split(",")))
        exp = {i for (i, a) in raw.get(c, []) if mvn.affected(v, a)}
        n += 1
        if not exp and not got: both_empty += 1
        if exp != got:
            bad += 1
            if bad <= 12: print("DIFF", c, v, "expected-only", sorted(exp - got)[:3], "app-only", sorted(got - exp)[:3])
    print("pairs", n, "| identical", n - bad, "| differing", bad, "| of the identical, both empty:", both_empty)
