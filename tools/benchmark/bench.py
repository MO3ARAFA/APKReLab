#!/usr/bin/env python3
"""APK ReLab benchmark: checks an exported Markdown report against a list of KNOWN vulnerabilities of that app.

  python3 bench.py report.md                      # expected list picked by package: expected/<package>.json
  python3 bench.py report.md --save run.json      # remember the result of this run
  python3 bench.py report.md --expected expected_heldout/<pkg>.json --measure   # held-out apps: recall line, never fails on a MISS
  python3 bench.py report.md --baseline run.json  # also print regressions against an earlier run (exit code 1 on any)
  python3 bench.py report.md --evidence           # 1.2.0: also print the card(s) that matched each expected entry

Per expected entry: FOUND, FOUND (not traced as reachable) when "reach" is required, FOUND (AI says false positive),
MISS, or KNOWN GAP (a MISS the owner already accepted). Also lists HIGH/CRITICAL code findings that match NO expected entry
(candidates for false positives). Exit code 1 when an entry that is not a known gap is missed, or a regression is found.
"""
import json, os, re, sys

RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
HERE = os.path.dirname(os.path.abspath(__file__))


def parse(text):
    pkg = (re.search(r"^# APK ReLab report: (\S+)", text, re.M) or [None, ""])[1]
    sec = text.split("## Security scan", 1)[1] if "## Security scan" in text else ""
    sec = re.split(r"\n## (?!#)", sec, maxsplit=1)[0]
    out = []
    for b in re.split(r"\n#### (?=\d+\. \[)", sec)[1:]:
        head = b.split("\n", 1)[0]
        m = re.match(r"\d+\. \[(\w+)\] (.*)", head)
        if not m:
            continue
        loc = re.search(r"- Location: `([^`]+)`", b)
        rule = re.search(r"Rule: ([a-z0-9-]+)", b)
        ai = re.search(r"- AI triage: (TRUE POSITIVE|FALSE POSITIVE|NEEDS REVIEW)", b)
        out.append({
            "n": (re.match(r"(\d+)\.", head) or [None, ""])[1],                 # 1.2.0: the card number, for --evidence
            "sev": m.group(1), "title": m.group(2), "loc": loc.group(1) if loc else "",
            "rule": rule.group(1) if rule else "",
            # 0.75.2: a finding that absorbed another rule's finding of the same class (SecurityScanner.dedupe) counts for both rule ids
            "also": re.findall(r"Also matched by: ([a-z0-9-]+) \(merged\)", b), "reach": ("Reachable from an exported component" in b) or ("Probably reachable from an exported component" in b),
            "ai": ai.group(1) if ai else "",
        })
    return pkg, out


def matches(e, f):
    if "class" in e and e["class"] not in f["loc"]:
        return False
    if "rule" in e:
        want = [e["rule"]] if isinstance(e["rule"], str) else e["rule"]
        if f["rule"] not in want and not any(a in want for a in f.get("also", [])):
            return False
    if "title_any" in e and not any(t.lower() in f["title"].lower() for t in e["title_any"]):
        return False
    return RANK[f["sev"]] <= RANK[e.get("min_severity", "INFO")]


def judge(e, found):
    if not found:
        return "KNOWN GAP" if e.get("known_gap") else "MISS"
    if e.get("reach") and not any(f["reach"] for f in found):
        return "FOUND-NOREACH"
    if all(f["ai"] == "FALSE POSITIVE" for f in found):
        return "FOUND-AI-FP"
    return "FOUND"


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(2)
    measure = "--measure" in args
    if measure:
        args.remove("--measure")
    evidence = "--evidence" in args          # 1.2.0 (self_check): print the card(s) that matched each entry
    if evidence:
        args.remove("--evidence")
    opt = {}
    for k in ("--save", "--baseline", "--expected"):
        if k in args:
            i = args.index(k)
            opt[k] = args[i + 1]
            del args[i:i + 2]
    pkg, findings = parse(open(args[0], encoding="utf-8", errors="ignore").read())
    exp_path = opt.get("--expected") or os.path.join(HERE, "expected", pkg + ".json")
    if not os.path.exists(exp_path):
        print("no expected list for package %r (looked for %s)" % (pkg, exp_path))
        sys.exit(2)
    expected = json.load(open(exp_path, encoding="utf-8"))
    status, used, bad = {}, set(), 0
    print("Benchmark: %s (%d findings parsed, %d expected)\n" % (pkg, len(findings), len(expected)))
    for e in expected:
        if e.get("out_of_scope"):
            status[e["id"]] = "OUT OF SCOPE"
            print("%-14s %s   <- %s" % ("OUT OF SCOPE", e["vuln"], e["out_of_scope"]))
            continue
        found = [f for f in findings if matches(e, f)]
        for f in found:
            used.add(id(f))
        s = judge(e, found)
        status[e["id"]] = s
        bad += s in ("MISS", "FOUND-NOREACH")
        print("%-14s %s" % (s, e["vuln"]) + ("" if s.startswith("FOUND") and s == "FOUND" else "   <- %s" % e.get("hint", "")))
        if evidence:
            for f in found[:3]:
                print("    card #%s [%s] %s | %s" % (f["n"], f["sev"], f["title"][:70], f["loc"]))
    ok = sum(1 for s in status.values() if s == "FOUND")
    inscope = sum(1 for s in status.values() if s != "OUT OF SCOPE")
    print("\n%d/%d found, %d known gap(s), %d need attention, %d out of scope" % (ok, inscope, sum(1 for s in status.values() if s == "KNOWN GAP"), bad, len(status) - inscope))
    if measure:
        ind = [e for e in expected if e.get("independent") and not e.get("out_of_scope")]
        hit = sum(1 for e in ind if status[e["id"]] == "FOUND")
        print("RECALL (independent entries, presence check, upper bound): %d/%d = %d%%" % (hit, len(ind), round(100.0 * hit / len(ind)) if ind else 0))
    extra = [f for f in findings if id(f) not in used and RANK[f["sev"]] <= 1 and f["loc"] not in ("AndroidManifest.xml",)
             and not f["loc"].startswith("res/") and f["loc"] != "resources.arsc" and not f["rule"].startswith("manifest-")]
    if measure:
        print("UNREVIEWED HIGH/CRITICAL code findings (precision is unknown until each is read): %d" % len(extra))
    if extra:
        print("\nHIGH/CRITICAL code findings not in the expected list (check for false positives):")
        for f in extra:
            print("  [%s] %s | %s | %s" % (f["sev"], f["title"][:60], f["loc"].split(".")[-1], f["ai"] or "not triaged"))
    regress = 0
    if "--baseline" in opt:
        base = json.load(open(opt["--baseline"], encoding="utf-8")).get("status", {})
        order = {"FOUND": 0, "FOUND-AI-FP": 1, "FOUND-NOREACH": 1, "KNOWN GAP": 2, "MISS": 3}
        print("\nAgainst baseline:")
        for k, s in status.items():
            if k in base and order.get(s, 3) > order.get(base[k], 3):
                regress += 1
                print("  REGRESSION %s: %s -> %s" % (k, base[k], s))
            elif k in base and order.get(s, 3) < order.get(base[k], 3):
                print("  improved   %s: %s -> %s" % (k, base[k], s))
        if not regress:
            print("  no regression")
    if "--save" in opt:
        json.dump({"package": pkg, "status": status}, open(opt["--save"], "w"), indent=1)
    sys.exit(1 if (regress or (bad and not measure)) else 0)


main()
