#!/usr/bin/env python3
"""APK ReLab release self-check (1.2.0): the scanner's accuracy on the benchmark apps as a tracked number, before every release.

  python3 tools/sandbox/self_check.py --reports DIR [--baseline-dir DIR] [--write-baseline] [--apps FILE]

DIR holds one Markdown report per app, named <package>.md (tools/sandbox/self_check.sh writes them from the APKs with SandboxScan).
For each app of tools/benchmark/self_check_apps.json:
  - recall: tools/benchmark/bench.py on the report against the app's expected list, with the card that matched each entry (--evidence);
  - judged true positives kept: against <baseline-dir>/<package>.bench.json (an entry that was FOUND and is now worse is a REGRESSION);
  - flow set: the data-flow cards (Rule: taint-flow / taint-xclass) as "title | location | why" against <baseline-dir>/<package>.flows: N new / M lost.
Exit code 1 when a judged true positive is lost (bench regression) or an app's report is missing. A lost or new flow is printed, not fatal: removing a false
flow is a release goal; the release notes must say which flows went and why.
--write-baseline stores this run's results as the baseline (do it at every tagged release, after the numbers were reviewed).
Held-out apps (Sieve) are scored with --measure: their recall is a blind number; the others are tuning apps and say so.
"""
import json, os, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BENCH = os.path.join(HERE, "..", "benchmark")


def flows(report_text):
    """The data-flow cards of a report as sorted lines (title | location | the 'Why flagged' sentence up to the method)."""
    sec = report_text.split("## Security scan", 1)[1] if "## Security scan" in report_text else ""
    out = set()
    for b in re.split(r"\n#### (?=\d+\. \[)", sec)[1:]:
        if not re.search(r"Rule: (taint-flow|taint-xclass)\b", b):
            continue
        title = re.sub(r"^\d+\. \[\w+\] ", "", b.split("\n", 1)[0])   # the severity is not part of a flow's identity
        loc = (re.search(r"- Location: `([^`]+)`", b) or [None, ""])[1]
        why = (re.search(r"- Why flagged: (.*?)(?: Found by|\n)", b) or [None, ""])[1]
        out.add("%s | %s | %s" % (title, loc, why.strip()))
    return sorted(out)


def must_fix_cards(report_text):
    """Card numbers of the Verdict's MUST FIX lines ("  - #12 [HIGH] ..." or "  - CHECK FIRST: #12 ...")."""
    v = report_text.split("## Security scan", 1)[0]
    m = re.search(r"- \*\*MUST FIX:\*\*(.*?)(?=\n- \*\*[A-Z ]+:\*\*|\Z)", v, re.S)
    if not m:
        return []
    return [int(n) for n in re.findall(r"^\s*- (?:CHECK FIRST: )?#(\d+) \[", m.group(1), re.M)] + \
           [int(n) for n in re.findall(r"\A (?:CHECK FIRST: )?#(\d+) \[", m.group(1))]          # a single-line MUST FIX


def found_cards(bench_stdout):
    """Card numbers bench.py --evidence names under a FOUND or FOUND-NOREACH entry (the cards that match an expected issue); FOUND-AI-FP, MISS and
    KNOWN GAP entries do not count."""
    out, cur = set(), False
    for line in bench_stdout.split("\n"):
        st = re.match(r"^([A-Z][A-Z-]+(?: [A-Z]+)?) {2,}", line)
        if st:
            cur = st.group(1) in ("FOUND", "FOUND-NOREACH")
        elif cur:
            n = re.match(r"^\s+card #(\d+) ", line)
            if n:
                out.add(int(n.group(1)))
    return out


def top3(report_text, bench_stdout):
    """(hits, size) of MUST FIX: how many of its (at most three) cards match an expected issue of the app's list."""
    must = must_fix_cards(report_text)
    good = found_cards(bench_stdout)
    return sum(1 for n in must if n in good), len(must)


def expected_file(app):
    """bench.py's expected list for the app; a taint_bench list (expected_taint) is converted on the fly (documented / verified entries)."""
    path = os.path.join(BENCH, app["expected"])
    data = json.load(open(path, encoding="utf-8"))
    if isinstance(data, list):
        return path
    entries = [{"id": e["id"], "vuln": e["id"], "class": e["class"], "title_any": e.get("title_any", [])}
               for e in data.get("entries", []) if e.get("status") in ("documented", "verified")]
    fd, tmp = tempfile.mkstemp(prefix="selfcheck-", suffix=".json")
    with os.fdopen(fd, "w") as fh:
        json.dump(entries, fh)
    return tmp


def main():
    a = sys.argv[1:]
    def opt(k, d=None):
        return a[a.index(k) + 1] if k in a else d
    reports = opt("--reports")
    if not reports:
        print(__doc__)
        return 2
    base_dir = opt("--baseline-dir", os.path.join(BENCH, "baselines", "current"))
    apps = json.load(open(opt("--apps", os.path.join(BENCH, "self_check_apps.json")), encoding="utf-8"))
    write = "--write-baseline" in a
    fail = 0
    summary = []
    tot_hit = tot_size = 0
    for app in apps:
        pkg, name = app["package"], app["name"]
        rep = os.path.join(reports, pkg + ".md")
        print("=" * 70)
        if not os.path.exists(rep):
            print("%s: NO REPORT (%s missing)" % (name, rep))
            summary.append("%s: not run" % name)
            fail = 1
            continue
        exp = expected_file(app)
        cmd = [sys.executable, os.path.join(BENCH, "bench.py"), rep, "--expected", exp, "--evidence"]
        if app.get("heldout"):
            cmd.append("--measure")
        bjson = os.path.join(base_dir, pkg + ".bench.json")
        if os.path.exists(bjson) and not write:
            cmd += ["--baseline", bjson]
        tmp_save = tempfile.mktemp(prefix="selfcheck-", suffix=".json")
        cmd += ["--save", tmp_save]
        r = subprocess.run(cmd, capture_output=True, text=True)
        print(r.stdout.rstrip())
        m = re.search(r"^(\d+)/(\d+) found", r.stdout, re.M)
        regress = len(re.findall(r"^  REGRESSION ", r.stdout, re.M))
        if regress:
            fail = 1
        text = open(rep, encoding="utf-8", errors="ignore").read()
        hit, size = top3(text, r.stdout)
        t3 = "top3 %d/%d" % (hit, size) if size else "top3 n/a (MUST FIX empty)"
        tot_hit += hit; tot_size += size
        print("\nTOP3: %s (MUST FIX cards that match an expected issue)" % t3)
        now = flows(text)
        fpath = os.path.join(base_dir, pkg + ".flows")
        if os.path.exists(fpath) and not write:
            old = [l for l in open(fpath, encoding="utf-8").read().split("\n") if l]
            new, lost = sorted(set(now) - set(old)), sorted(set(old) - set(now))
            flow_line = "flow set identical to the baseline (%d)" % len(now) if not new and not lost else "%d new / %d lost flow(s) against the baseline" % (len(new), len(lost))
            print("\nFLOWS: " + flow_line)
            for l in new:
                print("  NEW  " + l)
            for l in lost:
                print("  LOST " + l)
        else:
            flow_line = "%d flow(s), no baseline" % len(now)
            print("\nFLOWS: " + flow_line)
        if write:
            os.makedirs(base_dir, exist_ok=True)
            open(fpath, "w", encoding="utf-8").write("\n".join(now) + ("\n" if now else ""))
            os.replace(tmp_save, bjson)
        elif os.path.exists(tmp_save):
            os.remove(tmp_save)
        summary.append("%s: %s%s%s; %s; %s" % (name, ("%s/%s" % (m.group(1), m.group(2))) if m else "?", " (held-out)" if app.get("heldout") else " (tuning set)",
                                           ", %d REGRESSION(S)" % regress if regress else "", t3, flow_line))
    print("=" * 70)
    print("Recall: " + " | ".join(summary))
    print("top3_accuracy: %s" % ("%d/%d = %d%% of MUST FIX cards match an expected issue" % (tot_hit, tot_size, 100 * tot_hit // tot_size) if tot_size else "n/a (every MUST FIX empty)"))
    print("SELF-CHECK " + ("FAILED" if fail else "PASSED") + (" (baseline written to %s)" % base_dir if write else ""))
    return fail


if __name__ == "__main__":
    sys.exit(main())
