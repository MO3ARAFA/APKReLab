#!/usr/bin/env python3
"""Recall by injection (0.86.1): adds the cases of cases.py to a hard-linked copy of a decoded real app, scans it with the real pipeline
(tools/sandbox/SandboxScanReach.kt, manifest edited with -Dmanifest) and reports, per case, whether a card of an expected rule shows up for the
injected class and at which severity.

usage: run_recall.py <snapshot-dir> <host> [<host> ...]     (a host is a decoded app: /home/claude/apps/dec_<host>, <host>.apk)
       <snapshot-dir> holds ss2/ kout/ irk/ (see tools/sandbox/batch.sh); writes tools/recall/results-<host>.md
"""
import os, re, subprocess, sys, shutil
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cases import CASES, SEV

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
APPS = "/home/claude/apps"; WORK = os.environ.get("RECALL_WORK", "/home/claude/inj"); TC = "/home/claude/tc"
STD = TC + "/kotlinc/lib/kotlin-stdlib.jar"; JSONJ = TC + "/jsonx/usr/share/java/json-android.jar"

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)

def base_manifest(snap, host):
    out = f"{WORK}/{host}.manifest.xml"
    if not os.path.exists(out):
        os.makedirs(f"{WORK}/axd", exist_ok=True)
        cp = f"{snap}/kout:{snap}/irk:{TC}/stubs_out:{JSONJ}"
        if not os.path.exists(f"{WORK}/axd/AxmlDumpKt.class"):
            r = sh(f"{TC}/kotlinc/bin/kotlinc -nowarn -cp {cp} -d {WORK}/axd {os.path.dirname(os.path.abspath(__file__))}/AxmlDump.kt")
        r = sh(f"java -cp {WORK}/axd:{cp}:{STD} AxmlDumpKt {APPS}/{host}.apk {out}")
    return open(out, encoding="utf-8").read()

def code_package(host, manifest_pkg, snap="/home/claude/tc/v864"):
    """The package the scanner itself treats as the app's code (SecurityScanner.codePackage): Quillpad's manifest says io.github.quillpad, its
    code is org.qosp.notes; injected classes must go where the code is, or the scope and the app-bound tests differ from a real finding."""
    cp = f"{snap}/kout:{snap}/irk:{TC}/stubs_out:{JSONJ}"
    out = f"{WORK}/axd"
    os.makedirs(out, exist_ok=True)
    if not os.path.exists(f"{out}/CodePkgKt.class"):
        sh(f"{TC}/kotlinc/bin/kotlinc -nowarn -cp {cp} -d {out} {os.path.dirname(os.path.abspath(__file__))}/CodePkg.kt")
    r = sh(f"java -cp {out}:{cp}:{STD} CodePkgKt {APPS}/dec_{host} {manifest_pkg}")
    return r.stdout.strip() or manifest_pkg

def build(host, snap):
    manifest = base_manifest(snap, host)
    pk = re.search(r'package="([^"]+)"', manifest).group(1)
    pk = code_package(host, pk, snap)
    pkp = pk.replace(".", "/") + "/inj"
    ov = f"{WORK}/{host}"
    shutil.rmtree(ov, ignore_errors=True)
    os.makedirs(WORK, exist_ok=True)
    r = sh(f"cp -al {APPS}/dec_{host} {ov}")
    assert r.returncode == 0, r.stderr
    d = f"{ov}/smali_inj"; os.makedirs(d, exist_ok=True)
    snippets = []; types = {}
    for c in CASES:
        types[c["id"]] = []
        for key, text in c["smali"].items():
            text = text.replace("{P}", pkp).replace("{PK}", pk.replace('"', ""))
            m = re.search(r"^\.class[^\n]* (L[^;]+;)", text, re.M)
            t = m.group(1)
            rel = t[1:-1] + ".smali"
            if sh(f"ls {ov}/smali*/{rel} 2>/dev/null").stdout.strip():
                raise SystemExit(f"class {t} already exists in {host}: rename the case class")
            path = f"{d}/{rel}"; os.makedirs(os.path.dirname(path), exist_ok=True)
            open(path, "w", encoding="utf-8").write(text)
            types[c["id"]].append(t[1:-1].replace("/", "."))
        for line in c.get("manifest", []):
            snippets.append(line.replace("{PK}", pk))
    mtext = manifest.replace("</application>", "\n".join(snippets) + "\n</application>", 1)
    mpath = f"{ov}.manifest.xml"; open(mpath, "w", encoding="utf-8").write(mtext)
    return ov, mpath, types, pk

def scan(host, snap, ov, mpath):
    out = f"{WORK}/{host}.report.md"
    cp = f"{snap}/ss2:{snap}/kout:{snap}/irk:{TC}/stubs_out:{STD}:{JSONJ}"
    r = sh(f"java -Xmx3g -Dmanifest={mpath} -Dsecretformats={REPO}/app/src/main/assets/secret_formats.json -cp {cp} SandboxScanReachKt {ov} {APPS}/{host}.apk {out}")
    if r.returncode != 0: raise SystemExit(r.stderr[-800:])
    return out

def parse(report):
    t = open(report, encoding="utf-8").read().split("## Security scan", 1)[1]
    cards = []
    for b in re.split(r"\n#### (?=\d+\. \[)", t)[1:]:
        h = b.split("\n", 1)[0]; m = re.match(r"\d+\. \[(\w+)\] (.*)", h)
        loc = re.search(r"- Location: `([^`]+)`", b); ru = re.search(r"Rule: ([a-z0-9-]+)", b)
        # merged cards: "Also matched by: rule-a, rule-b (merged)"
        also = re.search(r"Also matched by: ([^\n]*)", b)
        rules = {ru.group(1)} if ru else set()
        if also: rules |= set(re.findall(r"[a-z][a-z0-9-]+", also.group(1).replace("(merged)", "")))
        cards.append(dict(sev=m.group(1), title=m.group(2), loc=loc.group(1) if loc else "", rules=rules))
    return cards

def evaluate(cards, types):
    rows = []
    for c in CASES:
        mine = [k for k in cards if any(k["loc"] == t or k["loc"].startswith(t) for t in types[c["id"]])]
        match = [k for k in mine if k["rules"] & set(c["rules"])]
        best = max(match, key=lambda k: SEV.get(k["sev"], 0)) if match else None
        other = sorted({k["sev"] + " " + k["title"][:34] for k in mine if k not in match})
        if best is None: verdict = "MISSED"
        elif SEV[best["sev"]] >= SEV[c["sev"]]: verdict = "DETECTED"
        else: verdict = "LOWER"
        rows.append((c, verdict, best["sev"] if best else "-", other))
    return rows

def main():
    snap = sys.argv[1]; hosts = sys.argv[2:]
    allrows = {}
    for host in hosts:
        ov, mpath, types, pk = build(host, snap)
        rep = scan(host, snap, ov, mpath)
        rows = evaluate(parse(rep), types)
        allrows[host] = rows
        md = [f"# Recall by injection on {host} ({pk}): {len(CASES)} cases\n", "| case | pattern | kind | expected | result | best severity | other cards for the class |", "|---|---|---|---|---|---|---|"]
        for c, v, s, other in rows:
            md.append(f"| {c['id']} | {c['name']} | {c['kind']} | {c['sev']}+ ({'/'.join(c['rules'][:2])}) | **{v}** | {s} | {'; '.join(other)[:90]} |")
        must = [r for r in rows if r[0]["kind"] == "must"]; probe = [r for r in rows if r[0]["kind"] == "probe"]
        md.append("\nmust-cases (%d): rule fired for %d (at the expected severity or higher for %d, LOWER for %d), MISSED %d" % (len(must), sum(1 for r in must if r[1] != "MISSED"), sum(1 for r in must if r[1] == "DETECTED"), sum(1 for r in must if r[1] == "LOWER"), sum(1 for r in must if r[1] == "MISSED")))
        md.append("probes (%d): " % len(probe) + ", ".join("%s=%s/%s" % (r[0]["id"], r[1], r[2]) for r in probe))
        open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f"results-{host}.md"), "w", encoding="utf-8").write("\n".join(md) + "\n")
        print("\n".join(md))
main()
