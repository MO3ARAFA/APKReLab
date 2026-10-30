#!/usr/bin/env python3
"""Builds assets/vulns.json from the GitHub Advisory Database (reviewed, Maven ecosystem), keeping the hand-checked entries.

usage: gen_vulns.py <advisory-database checkout> <existing vulns.json> <out vulns.json> [--report]
Source: https://github.com/github/advisory-database (CC-BY 4.0), advisories/github-reviewed/**/GHSA-*.json (OSV format).
Selection: packages an Android app can plausibly bundle (see PREFIXES + the coordinates the scanner itself detects), not every server-side Maven artifact.
Ranges: OSV events introduced / fixed / last_affected  ->  [from, to) pairs ("" = unbounded). last_affected has no exclusive end: it becomes the next
version after it ("<last_affected>.0" is NOT used: the pair is written as [from, last_affected + "+"], decoded by LibVuln as "to the end of that version").
"""
import glob, json, os, re, sys, collections

PREFIXES = (
    "com.squareup.", "com.google.protobuf", "com.google.guava", "com.google.code.gson", "com.google.android.", "com.google.http-client", "com.google.oauth-client",
    "com.google.zxing", "com.google.firebase", "com.google.crypto.tink", "com.fasterxml.", "org.bouncycastle", "org.apache.commons", "commons-", "org.jsoup", "io.netty",
    "io.grpc", "org.apache.httpcomponents", "org.apache.logging.log4j", "log4j", "org.slf4j", "ch.qos.logback", "com.android.", "androidx.", "org.jetbrains.kotlin",
    "org.jetbrains.kotlinx", "io.sentry", "com.github.bumptech", "com.facebook", "com.airbnb", "org.greenrobot", "io.reactivex", "org.xerial", "org.yaml",
    "net.minidev", "com.thoughtworks.xstream", "org.dom4j", "xerces", "xalan", "com.jcraft", "org.eclipse.jgit", "com.nimbusds", "com.auth0", "io.jsonwebtoken",
    "org.apache.tika", "org.apache.pdfbox", "org.apache.poi", "org.apache.xmlgraphics", "com.itextpdf", "org.jdom", "org.json", "com.alibaba", "net.sf.json",
    "org.codehaus.jackson", "org.codehaus.jettison", "org.eclipse.jetty", "org.apache.santuario", "org.apache.mina", "org.apache.sshd", "com.squareup",
    "org.conscrypt", "net.lingala.zip4j", "org.zeroturnaround", "com.github.junrar", "org.tukaani", "org.brotli", "com.h2database", "org.hsqldb", "net.sourceforge",
    "io.undertow", "org.glassfish", "javax.", "jakarta.", "org.springframework", "com.mikepenz", "com.github.", "io.realm", "io.ktor", "io.coil-kt", "com.bugsnag",
    "com.getkeepsafe", "io.branch", "com.adjust", "com.appsflyer", "com.onesignal", "com.braze", "com.mixpanel", "com.segment", "com.amplitude", "net.openid",
)

def sev(d):
    s = (d.get("database_specific", {}) or {}).get("severity", "")
    return {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(s, "MEDIUM")

def ranges_of(aff):
    out = []; ends = []
    for r in aff.get("ranges", []):
        if r.get("type") not in ("ECOSYSTEM", "SEMVER"): continue
        lo = None
        for e in r.get("events", []):
            if "introduced" in e: lo = "" if e["introduced"] == "0" else e["introduced"]
            elif "fixed" in e:
                if lo is not None: out.append([lo, e["fixed"]]); ends.append(e["fixed"])
                lo = None
            elif "last_affected" in e:
                if lo is not None: out.append([lo, e["last_affected"] + "+"]); ends.append(None)
                lo = None
        if lo is not None: out.append([lo, ""]); ends.append(None)
    vs = aff.get("versions", [])
    return out, ends, vs

def main():
    adv_dir, old_path, out_path = sys.argv[1:4]
    old = json.load(open(old_path)); hand = old["vulns"]
    hand_keys = collections.defaultdict(set)
    for v in hand:
        for m in re.findall(r"CVE-\d+-\d+", v["id"]): hand_keys[(v["group"], v["artifact"])].add(m)
    seen = set()
    entries = []; skipped_dup = 0; skipped_noranges = 0
    for f in sorted(glob.glob(os.path.join(adv_dir, "advisories/github-reviewed/*/*/*/*.json"))):
        d = json.load(open(f))
        if d.get("withdrawn"): continue
        cves = [a for a in d.get("aliases", []) if a.startswith("CVE-")]
        summary = (d.get("summary") or "").strip().replace("\n", " ")[:150]
        cwes = (d.get("database_specific", {}) or {}).get("cwe_ids", []) or []
        byp = collections.defaultdict(lambda: ([], [], []))
        for a in d.get("affected", []):
            p = a.get("package", {})
            if p.get("ecosystem") != "Maven" or ":" not in p.get("name", ""): continue
            name = p["name"]
            if not name.startswith(PREFIXES): continue
            rs, ends, vs = ranges_of(a)
            B = byp[name]; B[0].extend(rs); B[1].extend(ends); B[2].extend(vs)
        for name, (rs, ends, vs) in byp.items():
            g, art = name.split(":", 1)
            if not rs:
                skipped_noranges += 1; continue
            if any(c in hand_keys.get((g, art), ()) for c in cves): skipped_dup += 1; continue
            fixed = sorted({e for e in ends if e}, key=lambda x: [int(t) if t.isdigit() else 0 for t in re.split(r"[.\-]", x)])
            # dedupe ranges
            uniq = []
            for r in rs:
                if r not in uniq: uniq.append(r)
            entries.append({
                "group": g, "artifact": art, "ranges": uniq,
                "id": d["id"] + ((" / " + " / ".join(cves)) if cves else ""),
                "severity": sev(d), "summary": summary,
                "fixed": (", ".join(fixed[-3:]) + " or newer") if fixed else "see the advisory",
                "cwe": cwes[0] if cwes else "CWE-1395", "src": "ghsa"})
    out = {"schema": 1, "comment": old.get("comment", "") + " Entries with src=ghsa come from the GitHub Advisory Database (CC-BY 4.0), generated by tools/sca/gen_vulns.py.",
           "vulns": hand + entries}
    json.dump(out, open(out_path, "w"), separators=(",", ":"))
    print("hand", len(hand), "ghsa entries", len(entries), "coordinates", len({(e['group'], e['artifact']) for e in entries}), "| skipped (CVE already hand-checked)", skipped_dup,
          "| skipped (no ranges)", skipped_noranges, "| bytes", os.path.getsize(out_path))
main()
