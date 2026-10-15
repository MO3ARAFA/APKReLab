"""PRJ-03 pipeline: diagnose a target site and produce a validated CEO outreach audit.

By default the target is a pair of local fixture sites served over real HTTP (so timings, compression and
redirect handling are exercised without touching third-party servers). Set TARGET_URL / TARGET_CEO /
TARGET_COMPANY to point the pipeline at a real prospect instead.
"""
from __future__ import annotations

import csv
import gzip
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from projects.common import check, run_pytest
from projects.prj_03_deal_closer import b2b_sniper as bs

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"


class FixtureHandler(BaseHTTPRequestHandler):
    """/bad: slow, uncompressed, padded (simulated flawed origin). /good: fast + gzip."""

    def log_message(self, *a):  # silence
        pass

    def do_GET(self):
        if self.path.startswith("/bad"):
            time.sleep(0.9)  # simulated slow origin
            body = (FIX / "bad_site.html").read_bytes() + b"<!--" + b"x" * 60_000 + b"-->"
            enc = None
        elif self.path.startswith("/good"):
            body = gzip.compress((FIX / "good_site.html").read_bytes())
            enc = "gzip"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if enc:
            self.send_header("Content-Encoding", enc)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_fixture_server() -> tuple[ThreadingHTTPServer, str]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def run(out_dir: Path, llm, dry_run: bool = False, feedback: list[str] | None = None) -> dict:
    out_dir = Path(out_dir)
    external = os.getenv("TARGET_URL")
    srv = None
    try:
        if external:
            base, allow = None, False
            target, ceo, company = external, os.getenv("TARGET_CEO", "there"), os.getenv("TARGET_COMPANY") or None
            good = None
        else:
            srv, base = start_fixture_server()
            allow = True
            target, ceo, company = f"{base}/bad", "Dana", "Northwind Industrial"
            good = bs.run_sniper(f"{base}/good", "Priya", "Contoso Logistics", llm=llm, allow_private=True)
        result = bs.run_sniper(target, ceo, company, llm=llm, allow_private=allow)
    finally:
        if srv:
            srv.shutdown()

    batch_ready = 0
    targets_file = os.getenv("TARGETS_FILE")
    if targets_file:  # real prospect list: url,ceo,company (max TARGETS_MAX, default 500)
        batch = bs.run_batch(bs.load_targets(targets_file, int(os.getenv("TARGETS_MAX", "500"))), llm)
        batch_ready = sum(1 for r in batch if r.get("ready"))
        with (out_dir / "outreach_batch.csv").open("w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["url", "ceo", "score", "words", "ready", "outreach", "error"])
            for r in batch:
                w.writerow([r["url"], r["ceo"], r.get("scores", {}).get("overall", ""), r.get("outreach_words", ""),
                            r["ready"], r.get("outreach", ""), r.get("error", "")])
    (out_dir / "diagnostics.json").write_text(json.dumps(result, indent=2))
    (out_dir / "outreach.txt").write_text(result["outreach"] + "\n")
    f = result["findings"]
    md = [f"# Diagnostic audit: {result['company']}", "", f"Target: `{result['url']}`  |  Score: **{result['scores']['overall']}/100**  |  Issues: {result['scores']['issues']}", "",
          "## Performance", "", f"- TTFB: {result['performance']['ttfb_s']}s", f"- Download: {result['performance']['total_s']}s",
          f"- HTML size: {result['performance']['html_kb']} KB (compressed: {result['performance']['compressed']})", "",
          "## Findings (by impact)", "", "| Area | Severity | Finding |", "|---|---|---|"]
    md += [f"| {x['area']} | {x['severity']} | {x['detail']} |" for x in f]
    md += ["", f"## Outreach to {result['ceo']} ({result['outreach_words']} words, source: {result['outreach_meta']['source']})", "", f"> {result['outreach']}", ""]
    (out_dir / "audit.md").write_text("\n".join(md))

    passed, total, tail = run_pytest(HERE / "tests", cwd=HERE)
    checks = [
        check("page fetched over HTTP (200)", result["status"] == 200, str(result["status"])),
        check("diagnostics found speed + SEO + conversion issues",
              {"speed", "seo"} <= {x["area"] for x in f} and any(x["area"] in {"conversion", "funnel"} for x in f), str(sorted({x['area'] for x in f}))),
        check(f"outreach under {bs.MAX_WORDS} words", result["outreach_words"] < bs.MAX_WORDS, f"{result['outreach_words']} words"),
        check("outreach passes validation (CEO name, finding, CTA, no placeholders)",
              not bs.validate_outreach(result["outreach"], result["ceo"], [bs.Finding(**x) for x in f]),
              str(bs.validate_outreach(result["outreach"], result["ceo"], [bs.Finding(**x) for x in f]))),
        check("scoring discriminates good vs flawed site", good is None or good["scores"]["overall"] > result["scores"]["overall"] + 20,
              f"good={good and good['scores']['overall']} bad={result['scores']['overall']}"),
        check("project tests pass", total >= 8 and passed == total, f"{passed}/{total}\n{tail if passed != total else ''}"),
    ]
    artifacts = {"diagnostics": str(out_dir / "diagnostics.json"), "outreach": str(out_dir / "outreach.txt"), "audit": str(out_dir / "audit.md")}
    return {"artifacts": artifacts, "checks": checks,
            "summary": f"Diagnosed {result['company']} (score {result['scores']['overall']}/100, {len(f)} issues); outreach {result['outreach_words']} words.",
            "units": {"audits_ready": batch_ready or 1},
            "metrics": {"score": result["scores"]["overall"], "issues": len(f), "words": result["outreach_words"], "tests": f"{passed}/{total}"}}


if __name__ == "__main__":
    from config import Settings
    from llm import LLMClient
    out = Path("output/PRJ-03")
    out.mkdir(parents=True, exist_ok=True)
    r = run(out, LLMClient(Settings.load()))
    for c in r["checks"]:
        print("PASS" if c["passed"] else "FAIL", c["name"], c["detail"])
    print((out / "outreach.txt").read_text())
