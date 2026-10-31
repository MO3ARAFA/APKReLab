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

    # phase 2: top3_accuracy = MUST FIX cards (Verdict) that match an expected issue (bench.py --evidence FOUND cards)
    def run_with_verdict(self, cards, must_lines):
        v = "## Verdict\n\n- **VERDICT:** x\n- **CRITICAL PATH:** none\n- **MUST FIX:**" + ("".join("\n  - " + l for l in must_lines) if len(must_lines) > 1 else " " + must_lines[0]) + \
            "\n- **CONFIDENCE:** weak\n- **NOT SEEN:** n\n\n"
        open(os.path.join(self.reports, "com.example.app.md"), "w").write(report(cards).replace("## Security scan", v + "## Security scan", 1))
        return subprocess.run([sys.executable, SCRIPT, "--reports", self.reports, "--baseline-dir", self.base, "--apps", self.apps], capture_output=True, text=True).stdout

    def test_top3_counts_must_fix_cards_that_match_an_expected_issue(self):
        c = dict(sev="HIGH", title="Weak cipher", loc="com.example.app.Other", rule="crypto", why="x.")
        out = self.run_with_verdict([A, B, c], ["#1 [HIGH] file in Store", "→ to verify: x", "Evidence: 1.0 (real SSA source+path)", "CHECK FIRST: #3 [HIGH] Weak cipher in Other", "→ to verify: y"])
        self.assertIn("TOP3: top3 1/2", out)
        self.assertIn("top3_accuracy: 1/2 = 50%", out)

    def test_top3_twin_empty_must_fix_is_not_a_score(self):
        out = self.run_with_verdict([A, B], ["no HIGH/CRITICAL finding passes the MUST FIX gate"])
        self.assertIn("top3 n/a (MUST FIX empty)", out)
        self.assertIn("top3_accuracy: n/a", out)

    def test_top3_twin_a_card_the_ai_marked_false_positive_does_not_count(self):
        fp = dict(B, why=B["why"] + " Found by the SSA data-flow engine.\n- AI triage: FALSE POSITIVE (read)")
        out = self.run_with_verdict([A, fp], ["#1 [HIGH] file in Store", "→ to verify: x", "#2 [HIGH] web in Web", "→ to verify: y"])
        self.assertIn("FOUND-AI-FP", out)
        self.assertIn("TOP3: top3 1/2", out)

    def test_top3_single_line_must_fix(self):
        out = self.run_with_verdict([A, B], ["#2 [HIGH] web in Web"])
        self.assertIn("TOP3: top3 1/1", out)


if __name__ == "__main__":
    unittest.main()
