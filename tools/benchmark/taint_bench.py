#!/usr/bin/env python3
"""APK ReLab taint benchmark: scores the "Taint on SSA" export (.txt) against a ground-truth list for that app.

  python3 taint_bench.py b3nac_injuredandroid-taint.txt [more .txt ...]
  python3 taint_bench.py *.txt --save run.json         # remember this run
  python3 taint_bench.py *.txt --baseline run.json     # next version: prints regressions (exit code 1 on any)

The expected list is picked by the class prefix of the flows (expected_taint/<app>.json, field "app_prefix").

Every flow lands in exactly ONE bucket, and the evidence level is part of the bucket, so the numbers cannot look better than they are:
  TP-verified    the owner read the smali and confirmed the flow (status "verified")
  TP-documented  a public write-up of the test app names this weakness, not checked here (status "documented")
  LIBRARY        the flow is inside third-party code, kept out of precision (status "library")
  BENIGN         reviewed and NOT a weakness (status "benign"): the only bucket that counts against precision
  UNREVIEWED     nobody has judged it yet: printed as a review sheet (class, method, instruction) to open in the smali
Recall = INDEPENDENT expected entries that a flow matches / INDEPENDENT expected entries. An entry is independent only when it was written
from the app's own vulnerability list or from reading its code BEFORE looking at what the tool reported ("independent": true). An entry
written after seeing the tool's output (the default) proves nothing about recall, so it is shown but never counted: recall stays
"n/a" until independent entries exist.
Precision is computed over REVIEWED flows only: TP / (TP + BENIGN). With few reviewed flows the number means little: n is printed.
"""
import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def parse(text):
    hdr = {}
    m = re.search(r"methods analysed: (\d+).*?failed: (\d+), time (\d+) ms", text)
    if m:
        hdr = {"methods": int(m.group(1)), "failed": int(m.group(2)), "ms": int(m.group(3))}
    cmp_ = re.search(r"both: (\d+), only old: (\d+), only new: (\d+)(?:, [^\n]*?: (\d+))?", text)
    compare = None
    if cmp_:
        compare = {"both": int(cmp_.group(1)), "only_old": int(cmp_.group(2)), "only_new": int(cmp_.group(3)),
                   "merged": int(cmp_.group(4) or 0)}
    flows = []
    for b in re.split(r"\n(?=\d+\. \[)", text)[1:]:
        h = re.match(r"(\d+)\. \[(\w+)\] (.*?) \((CWE-\d+)\)", b)
        s = re.search(r"sink:\s+(\S+) in (L[^\s;]+;)->(\S+) @insn (\d+)", b)
        src = re.search(r"source: (.*)", b)
        if not h or not s:
            continue
        flows.append({"n": int(h.group(1)), "sev": h.group(2), "title": h.group(3), "cwe": h.group(4),
                      "api": s.group(1), "cls": s.group(2), "method": s.group(3), "insn": int(s.group(4)),
                      "source": src.group(1).strip() if src else "",
                      "reach": "entry:  not reachable" not in b})
    return hdr, compare, flows


def load_lists():
    out = []
    d = os.path.join(HERE, "expected_taint")
    for f in sorted(os.listdir(d)):
        if f.endswith(".json"):
            out.append(json.load(open(os.path.join(d, f), encoding="utf-8")))
    return out


def pick(lists, flows):
    for l in lists:
        if any(f["cls"].startswith(l["app_prefix"]) for f in flows):
            return l
    return None


def hit(e, f):
    if e["class"] not in f["cls"]:
        return False
    if "method" in e and e["method"] not in f["method"]:
        return False
    if "title_any" in e and not any(t.lower() in f["title"].lower() for t in e["title_any"]):
        return False
    return True


def score(lst, flows):
    res = {"app": lst["app"], "flows": len(flows), "entries": [], "buckets": {}}
    bucket = {}
    for e in lst.get("entries", []):
        got = [f for f in flows if hit(e, f)]
        res["entries"].append({"id": e["id"], "status": e["status"], "independent": bool(e.get("independent")), "found": bool(got), "known_gap": bool(e.get("known_gap")),
                               "reach": (got[0]["reach"] if got else None)})
        for f in got:
            bucket[(f["cls"], f["method"], f["insn"], f["title"])] = {"verified": "TP-verified", "documented": "TP-documented",
                                                                      "library": "LIBRARY", "benign": "BENIGN"}[e["status"]]
    review = []
    for f in flows:
        k = (f["cls"], f["method"], f["insn"], f["title"])
        b = bucket.get(k, "UNREVIEWED")
        res["buckets"][b] = res["buckets"].get(b, 0) + 1
        if b == "UNREVIEWED":
            review.append(f)
    res["review"] = review
    return res


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(2)
    opt = {}
    for k in ("--save", "--baseline"):
        if k in args:
            i = args.index(k)
            opt[k] = args[i + 1]
            del args[i:i + 2]
    lists = load_lists()
    runs, tot, bad = [], {}, 0
    ent_tot = ent_found = 0
    for path in args:
        hdr, compare, flows = parse(open(path, encoding="utf-8", errors="ignore").read())
        lst = pick(lists, flows)
        if lst is None:
            print("%s: no expected_taint list matches the flows (%d flows)\n" % (os.path.basename(path), len(flows)))
            continue
        r = score(lst, flows)
        r["compare"] = compare
        runs.append(r)
        print("== %s  (%d flows, %s ms, failed %s)" % (lst["app"], len(flows), hdr.get("ms"), hdr.get("failed")))
        if compare:
            print("   old-vs-new: %s" % compare)
        for e in r["entries"]:
            st = "FOUND" if e["found"] else ("KNOWN GAP" if e["known_gap"] else "MISS")
            if not e["found"] and not e["known_gap"]:
                bad += 1
            if e["independent"]:
                ent_tot += 1
                ent_found += 1 if e["found"] else 0
            extra = "" if e["reach"] is None else ("  reachable" if e["reach"] else "  NOT reachable")
            print("   %-12s %-14s %s%s%s" % (st, e["status"], e["id"], extra, "" if e["independent"] else "  (derived from tool output: not counted)"))
        print("   buckets: %s\n" % r["buckets"])
        for b, n in r["buckets"].items():
            tot[b] = tot.get(b, 0) + n
    if not runs:
        sys.exit(2)
    tpv = tot.get("TP-verified", 0)
    tp = tpv + tot.get("TP-documented", 0)
    be = tot.get("BENIGN", 0)
    allf = sum(tot.values())
    reviewed = tp + be
    print("TOTAL flows %d: %s" % (allf, tot))
    if ent_tot:
        print("recall    %d/%d INDEPENDENT entries found (%.0f%%)  [n=%d]" % (ent_found, ent_tot, 100.0 * ent_found / ent_tot, ent_tot))
    else:
        print("recall    n/a: no independent expected entry yet (every entry so far was written after seeing the tool's output)")
    if reviewed:
        print("precision %d/%d over REVIEWED flows (%.0f%%)  [n=%d; %d of %d flows are still UNREVIEWED, so this is NOT the precision of the tool]" % (tp, reviewed, 100.0 * tp / reviewed, reviewed, tot.get("UNREVIEWED", 0), allf))
        print("          verified by the owner only: %d/%d" % (tpv, tpv + be))
    print("reviewed share %.0f%% of all flows\n" % (100.0 * reviewed / max(1, allf)))
    rev = [(r["app"], f) for r in runs for f in r["review"]]
    if rev:
        print("REVIEW SHEET (open in the smali, decide TP / BENIGN, then add to expected_taint/):")
        for app, f in rev:
            print("  %-16s [%s] %s%s  %s.%s @insn %d  src=%s  %s" % (app, f["sev"], f["title"][:42], "", f["cls"][1:-1].split("/")[-1], f["method"].split("(")[0], f["insn"], f["source"], "reach" if f["reach"] else "NOT reachable"))
    if "--baseline" in opt:
        old = json.load(open(opt["--baseline"], encoding="utf-8"))
        om = {(r["app"], e["id"]): e["found"] for r in old for e in r["entries"]}
        for r in runs:
            for e in r["entries"]:
                if om.get((r["app"], e["id"])) and not e["found"]:
                    print("REGRESSION: %s / %s was found before and is missing now" % (r["app"], e["id"]))
                    bad += 1
    if "--save" in opt:
        json.dump([{k: v for k, v in r.items() if k != "review"} for r in runs], open(opt["--save"], "w"), indent=1)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
