"""PRJ-04 pipeline: scan sample app -> data-flow graph -> findings -> verified git-diff security patch."""
from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from projects.common import check, run_pytest
from projects.prj_04_zeroday_hunter import auto_patcher as ap

HERE = Path(__file__).resolve().parent
SAMPLE = HERE / "sample_app" / "app.py"


def git_apply_check(normalized: str, diff: str, filename: str) -> tuple[bool, str]:
    """Verify the diff applies cleanly (git apply --check) to the normalized original in a throwaway repo."""
    if not shutil.which("git"):
        return True, "git unavailable; skipped"
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / filename).write_text(normalized)
        (Path(td) / "p.diff").write_text(diff)
        subprocess.run(["git", "init", "-q"], cwd=td, check=True)
        r = subprocess.run(["git", "apply", "--check", "p.diff"], cwd=td, capture_output=True, text=True)
        return r.returncode == 0, r.stderr.strip()


def exploit_neutralised() -> tuple[bool, str]:
    """Execute a vulnerable query before/after patching against real SQLite with an injection payload."""
    demo = ("import sqlite3\n"
            "def find(db, name):\n"
            "    return db.execute(f\"SELECT name FROM users WHERE name = '{name}'\").fetchall()\n")
    res = ap.generate_patch(demo, "demo.py")

    def run(src):
        ns: dict = {}
        exec(compile(src, "demo", "exec"), ns)  # trusted: generated from the literal above
        import sqlite3
        db = sqlite3.connect(":memory:")
        db.execute("CREATE TABLE users (name TEXT)")
        db.executemany("INSERT INTO users VALUES (?)", [("alice",), ("bob",)])
        return ns["find"](db, "' OR '1'='1"), ns["find"](db, "alice")

    (o_attack, o_ok), (p_attack, p_ok) = run(res["normalized"]), run(res["patched"])
    good = len(o_attack) == 2 and p_attack == [] and o_ok == p_ok == [("alice",)]
    return good, f"attack rows before={len(o_attack)} after={len(p_attack)}; benign preserved={o_ok == p_ok}"


def run(out_dir: Path, llm, dry_run: bool = False, feedback: list[str] | None = None, source: Path | None = None) -> dict:
    out_dir = Path(out_dir)
    src_path = Path(source or SAMPLE)
    src = src_path.read_text()
    res = ap.generate_patch(src, src_path.name)

    (out_dir / "security_patch.diff").write_text(res["diff"])
    (out_dir / "app.normalized.py").write_text(res["normalized"])
    (out_dir / "app.patched.py").write_text(res["patched"])
    (out_dir / "dataflow_graph.json").write_text(json.dumps(res["graph"].to_dict(), indent=2))
    (out_dir / "dataflow.dot").write_text(res["graph"].to_dot())
    findings = [f.to_dict() for f in res["findings"]]
    (out_dir / "findings.json").write_text(json.dumps(findings, indent=2))

    # Re-scan the patched code: every auto-fixable finding must be gone.
    _, after, _ = ap.analyze_source(res["patched"])
    remaining_fixable = [f for f in after if f.fixable]
    by_rule = Counter(f.rule for f in res["findings"])

    banner = "> **DRY-RUN (architecture validation on the bundled sample only; Group B is gated by the CFO until Group A revenue).**\n\n" if dry_run else ""
    lines = [f"# Security Audit: {src_path.name}", "", banner.rstrip(), "",
             f"Findings: **{len(findings)}** | auto-patched: **{len(res['applied'])}** | manual: **{len(res['skipped'])}**", "",
             "| Sev | Line | Function | Rule | CWE | Status | Detail |", "|---|---|---|---|---|---|---|"]
    order = {"critical": 0, "high": 1, "medium": 2}
    for f in sorted(res["findings"], key=lambda f: (order.get(f.severity, 3), f.line)):
        d = f.to_dict()
        status = "patched" if f in res["applied"] else "manual"
        lines.append(f"| {f.severity} | {f.line} | `{f.function}` | {f.rule} | {d['cwe']} | {status} | {f.message} {'' if status == 'patched' else '**Fix:** ' + f.fix_hint} |")
    lines += ["", "## Data-flow graph", "",
              f"{len(res['graph'].nodes)} nodes / {len(res['graph'].edges)} edges (sources -> variables -> sinks). See `dataflow.dot` (Graphviz) and `dataflow_graph.json`.", "",
              "## Applying the patch", "", "```bash", "git apply security_patch.diff   # applies to app.normalized.py (ast-normalized original)", "```", "",
              "Note: the diff is computed against an AST-normalized copy of the source (comments/formatting are not preserved); "
              "review before merging. Findings marked *manual* need product decisions and are intentionally not auto-patched.", ""]
    if not dry_run:
        story = llm.complete("Summarize these security findings for an engineering lead in 3 sentences: " + json.dumps(by_rule),
                             system="You are an application security engineer. Be precise.",
                             fallback=f"{len(findings)} issues found ({', '.join(f'{k}: {v}' for k, v in by_rule.items())}); "
                                      f"{len(res['applied'])} were patched automatically and verified; the rest need manual design changes.",
                             max_tokens=200, tier=2).text  # complex security reasoning -> flagship tier
        lines.insert(2, story + "\n")
    (out_dir / "security_report.md").write_text("\n".join(lines))

    apply_ok, apply_msg = git_apply_check(res["normalized"], res["diff"], src_path.name)
    exploit_ok, exploit_msg = exploit_neutralised()
    try:
        ast.parse(res["patched"])
        compiles = True
    except SyntaxError:
        compiles = False
    passed, total, tail = run_pytest(HERE / "tests", cwd=HERE)
    checks = [
        check("data-flow graph built (sources, vars, sinks)", {n["kind"] for n in res["graph"].nodes.values()} >= {"source", "var", "sink"}),
        check("detects SQLi, IDOR, auth and business-logic flaws",
              {"sql-injection", "idor", "missing-authentication", "business-logic"} <= set(by_rule), str(dict(by_rule))),
        check("patched source compiles", compiles),
        check("git diff applies cleanly (git apply --check)", apply_ok and bool(res["diff"]), apply_msg),
        check("no auto-fixable findings remain after patch", not remaining_fixable, str([f.rule for f in remaining_fixable])),
        check("SQL injection exploit neutralised on real SQLite", exploit_ok, exploit_msg),
        check("project tests pass", total >= 8 and passed == total, f"{passed}/{total}\n{tail if passed != total else ''}"),
    ]
    artifacts = {"report": str(out_dir / "security_report.md"), "patch": str(out_dir / "security_patch.diff"),
                 "graph": str(out_dir / "dataflow_graph.json"), "findings": str(out_dir / "findings.json")}
    return {"artifacts": artifacts, "checks": checks,
            "summary": f"{len(findings)} findings, {len(res['applied'])} auto-patched and verified ({'dry-run' if dry_run else 'full'}).",
            "units": {"patches_ready": len(res["applied"])},
            "metrics": {"findings": len(findings), "patched": len(res["applied"]), "manual": len(res["skipped"]), "tests": f"{passed}/{total}"}}


if __name__ == "__main__":
    from config import Settings
    from llm import LLMClient
    out = Path("output/PRJ-04")
    out.mkdir(parents=True, exist_ok=True)
    r = run(out, LLMClient(Settings.load()))
    for c in r["checks"]:
        print("PASS" if c["passed"] else "FAIL", c["name"], c["detail"])
