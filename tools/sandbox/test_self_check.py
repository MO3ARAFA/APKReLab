#!/usr/bin/env python3
"""1.2.0: tests of tools/sandbox/self_check.py on fixture reports (no APK needed).  python3 tools/sandbox/test_self_check.py"""
import json, os, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "self_check.py")

CARD = """#### {n}. [{sev}] {title}

- Location: `{loc}`
- CWE: CWE-22 | Confidence: HIGH | Rule: {rule} | Scope: APP
- Why flagged: {why} Found by the SSA data-flow engine.
- Fix: fix

"""


def report(cards):
    body = "".join(CARD.format(n=i + 1, **c) for i, c in enumerate(cards))
    return "# APK ReLab report: com.example.app\n\n## Security scan\n\nHeuristic static scan\n\n### Findings\n\n" + body + "\n## Attack scenarios\n"


A = dict(sev="HIGH", title="Untrusted input is used as a file path", loc="com.example.app.Store", rule="taint-flow", why="Data from Intent.getStringExtra() reaches FileOutputStream.<init>() in method Store.save().")
B = dict(sev="HIGH", title="Untrusted input is loaded into a WebView", loc="com.example.app.Web", rule="taint-flow", why="Data from Intent.getData() reaches WebView.loadUrl() in method Web.open().")
EXPECTED = [{"id": "file", "vuln": "Path from an Intent", "class": "Store", "title_any": ["file path"], "independent": True},
            {"id": "web", "vuln": "URL from an Intent", "class": "Web", "title_any": ["WebView"], "independent": True}]


class SelfCheckTest(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="selfchecktest-")
        self.reports = os.path.join(self.d, "reports"); os.makedirs(self.reports)
        self.base = os.path.join(self.d, "base")
        exp = os.path.join(self.d, "expected.json"); json.dump(EXPECTED, open(exp, "w"))
        self.apps = os.path.join(self.d, "apps.json")
        json.dump([{"name": "Fixture", "package": "com.example.app", "expected": exp}], open(self.apps, "w"))

    def run_check(self, cards, *extra):
        open(os.path.join(self.reports, "com.example.app.md"), "w").write(report(cards))
        r = subprocess.run([sys.executable, SCRIPT, "--reports", self.reports, "--baseline-dir", self.base, "--apps", self.apps] + list(extra), capture_output=True, text=True)
        return r.returncode, r.stdout

    def test_identical_run_passes(self):
        self.assertEqual(self.run_check([A, B], "--write-baseline")[0], 0)
        code, out = self.run_check([A, B])
        self.assertEqual(code, 0, out)
        self.assertIn("2/2 found", out)
        self.assertIn("flow set identical to the baseline (2)", out)
        self.assertIn("card #1 [HIGH] Untrusted input is used as a file path", out)      # card-level evidence
        self.assertIn("SELF-CHECK PASSED", out)

    def test_lost_true_positive_fails(self):
        self.run_check([A, B], "--write-baseline")
        code, out = self.run_check([A])
        self.assertEqual(code, 1, out)
        self.assertIn("REGRESSION web: FOUND -> MISS", out)
        self.assertIn("SELF-CHECK FAILED", out)

    def test_lost_flow_is_reported(self):
        self.run_check([A, B], "--write-baseline")
        b2 = dict(B, why="Data from Intent.getData() reaches WebView.loadUrl() in method Web.other().")
        code, out = self.run_check([A, b2])
        self.assertEqual(code, 0, out)                                                      # the TP is still found: a changed flow is printed, not fatal
        self.assertIn("1 new / 1 lost flow(s) against the baseline", out)
        self.assertIn("LOST Untrusted input is loaded into a WebView | com.example.app.Web | Data from Intent.getData() reaches WebView.loadUrl() in method Web.open().", out)

    def test_missing_report_fails(self):
        code, out = subprocess.run([sys.executable, SCRIPT, "--reports", self.reports, "--baseline-dir", self.base, "--apps", self.apps], capture_output=True, text=True).returncode, ""
        self.assertEqual(code, 1)

    def test_taint_list_is_converted(self):
        exp = os.path.join(self.d, "taint.json")
        json.dump({"app": "X", "app_prefix": "Lcom/example/app/", "entries": [{"id": "w", "class": "Web", "title_any": ["WebView"], "status": "documented"},
                                                                               {"id": "lib", "class": "net/x/Y", "title_any": ["x"], "status": "library"}]}, open(exp, "w"))
        json.dump([{"name": "Fixture", "package": "com.example.app", "expected": exp}], open(self.apps, "w"))
        code, out = self.run_check([B])
        self.assertIn("1/1 found", out)                                                    # the library entry is not counted


if __name__ == "__main__":
    unittest.main()
