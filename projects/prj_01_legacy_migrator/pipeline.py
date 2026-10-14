"""PRJ-01 pipeline: scan -> modernize -> generate FastAPI service + pytest suite -> B2B audit report."""
from __future__ import annotations

import json
import ast
import shutil
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from projects.common import check, run_pytest
from projects.prj_01_legacy_migrator import analyzer, refactor

HERE = Path(__file__).resolve().parent
DEFAULT_REPO = HERE / "sample_legacy_repo"


def build_report(client: str, findings, post_findings, fixes, endpoints, quarantined, tests, risk_before, risk_after, narrative) -> str:
    by_sev = Counter(f.severity for f in findings)
    by_cat = Counter(f.category for f in findings)
    lines = [f"# Legacy Modernization Audit - {client}", "",
             "## Executive Summary", "", narrative, "",
             "| Metric | Value |", "|---|---|",
             f"| Findings | {len(findings)} |",
             f"| Risk score (before) | {risk_before}/100 |",
             f"| Risk score (after automated fixes) | {risk_after}/100 |",
             f"| Automated fixes applied | {sum(fixes.values())} |",
             f"| Endpoints generated | {len(endpoints)} |",
             f"| Quarantined (unsafe to expose) | {len(quarantined)} |",
             f"| Characterization tests | {tests[0]}/{tests[1]} passing |", "",
             "## Findings by Severity", "", "| Severity | Count |", "|---|---|"]
    for s in ["critical", "high", "medium", "low"]:
        lines.append(f"| {s} | {by_sev.get(s, 0)} |")
    lines += ["", "## Findings by Category", "", "| Category | Count |", "|---|---|"]
    lines += [f"| {c} | {n} |" for c, n in by_cat.most_common()]
    lines += ["", "## Detailed Findings", "", "| Sev | File:Line | Rule | Issue |", "|---|---|---|---|"]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda f: (order[f.severity], f.file, f.line)):
        lines.append(f"| {f.severity} | `{f.file}:{f.line}` | {f.rule} | {f.message} |")
    lines += ["", "## Automated Remediation", ""]
    lines += [f"- {k}: {v}" for k, v in sorted(fixes.items())] or ["- none"]
    lines += ["", "## Remaining Findings Requiring Human Action", ""]
    remaining = Counter(f.rule for f in post_findings)
    lines += [f"- {r}: {n}" for r, n in remaining.most_common()] or ["- none"]
    lines += ["", "## Migration Roadmap", "",
              "1. **Week 1** - rotate every credential flagged `hardcoded-secret`; remove `eval`/shell execution paths.",
              "2. **Week 2** - replace string-built SQL with parameterized queries; swap weak hashes for argon2/bcrypt.",
              "3. **Week 3-4** - deploy the generated FastAPI service behind the legacy app (strangler pattern); "
              "split monolithic functions behind the pinned characterization tests.",
              "4. **Week 5+** - port PHP/JS components, retire deprecated libraries, add CI gates (this analyzer + pytest).", ""]
    if quarantined:
        lines += ["## Quarantined Functions", ""] + [f"- `{q}` - contains code-execution risk; not exposed as an endpoint" for q in quarantined] + [""]
    return "\n".join(lines) + "\n"


def run(out_dir: Path, llm, dry_run: bool = False, feedback: list[str] | None = None, repo: Path | None = None) -> dict:
    out_dir = Path(out_dir)
    repo = Path(repo or DEFAULT_REPO)
    svc = out_dir / "migrated_service"
    if svc.exists():
        shutil.rmtree(svc)
    (svc / "tests").mkdir(parents=True)

    findings = analyzer.scan_repo(repo)
    risk_before = analyzer.risk_score(findings)

    # Modernize every parseable Python module; the first module with functions becomes the service core.
    fixes: Counter = Counter()
    overrides_path = repo / "characterization_inputs.json"
    overrides = json.loads(overrides_path.read_text()) if overrides_path.exists() else {}
    cores, all_funcs, all_records, modernized = [], [], [], {}
    for py in sorted(repo.rglob("*.py")):
        rel = str(py.relative_to(repo))
        try:
            new_src, fx = refactor.modernize_source(py.read_text())
        except SyntaxError:
            continue  # py2 file: reported, needs manual port
        fixes.update(fx)
        modname = "core_" + py.stem.replace("legacy_", "")
        (svc / f"{modname}.py").write_text(new_src)
        modernized[rel] = svc / f"{modname}.py"
        # quarantine functions that contain exec/shell findings (by line range)
        tree = ast.parse(new_src)
        q = set()
        for n in tree.body:
            if isinstance(n, ast.FunctionDef):
                for sub in ast.walk(n):
                    if isinstance(sub, ast.Call):
                        nm = analyzer._dotted(sub.func)
                        if nm in {"eval", "exec", "os.system", "os.popen"}:
                            q.add(n.name)
        funcs = refactor.inspect_functions(new_src, q)
        jobs = {f.name: refactor.candidate_args(f, overrides) for f in funcs if f.pure and not f.quarantined}
        if dry_run:
            jobs = dict(list(jobs.items())[:3])
        records = refactor.characterize(svc / f"{modname}.py", jobs)
        (svc / "tests" / f"test_{modname}.py").write_text(refactor.render_tests(modname, records))
        cores.append((modname, funcs, records))
        all_funcs += funcs
        all_records += records

    endpoints, quarantined_all = [], []
    for modname, funcs, records in cores:
        service_src, names = refactor.render_service(modname, funcs)
        # the first core module becomes service.py; additional modules are reported but not exposed
        if modname == cores[0][0]:
            (svc / "service.py").write_text(service_src)
            (svc / "tests" / "test_api.py").write_text(refactor.render_api_tests(modname, funcs, records))
            endpoints += names
        quarantined_all += [f.name for f in funcs if f.quarantined]
    (svc / "requirements.txt").write_text("fastapi>=0.110\nuvicorn>=0.29\npydantic>=2\npytest>=8\nhttpx>=0.27\n")
    (svc / "Dockerfile").write_text(refactor.DOCKERFILE)
    (svc / "README.md").write_text("# Migrated service\n\nGenerated by PRJ-01. Run: `uvicorn service:app --reload`; "
                                   "test: `pytest`.\n\nTests pin the behavior of the *modernized* code (golden master).\n")

    compiled = True
    for py in svc.rglob("*.py"):
        try:
            compile(py.read_text(), str(py), "exec")
        except SyntaxError:
            compiled = False
    passed, total, tail = run_pytest(svc / "tests", cwd=svc)

    # re-scan modernized code to measure automated remediation
    post = analyzer.scan_repo(svc)
    post = [f for f in post if not f.file.startswith("tests")]
    risk_after = analyzer.risk_score(post)

    base = (f"{len(findings)} findings across {len({f.file for f in findings})} files "
            f"({sum(1 for f in findings if f.severity == 'critical')} critical). Automated fixes reduced the risk score "
            f"from {risk_before} to {risk_after}; the remaining items need human decisions (credential rotation, "
            f"hash migration, query rewrites).")
    narrative = llm.complete(
        "Write a 3-sentence executive summary for a CTO from this audit data: " + base,
        system="You write crisp B2B security/modernization audit summaries. No hype.", fallback=base, max_tokens=250).text

    report = build_report(repo.name, findings, post, dict(fixes), endpoints, quarantined_all, (passed, total),
                          risk_before, risk_after, narrative)
    (out_dir / "client_audit_report.md").write_text(report)
    (out_dir / "findings.json").write_text(json.dumps([f.to_dict() for f in findings], indent=2))

    langs = {f.language for f in findings}
    checks = [
        check("detected Python+PHP+JS issues", {"python", "php", "javascript"} <= langs, f"languages: {sorted(langs)}"),
        check("detected security, deprecated and maintainability categories",
              {"security", "deprecated", "maintainability"} <= {f.category for f in findings}),
        check("monolithic function detected", any(f.rule == "monolithic-function" for f in findings)),
        check("modernized modules compile", compiled and bool(modernized)),
        check("automated fixes applied", sum(fixes.values()) >= 4, f"{sum(fixes.values())} fixes"),
        check("risk reduced by automated fixes", risk_after <= risk_before and len(post) < len(findings),
              f"{risk_before}->{risk_after}"),
        check("generated pytest suite passes", total >= 8 and passed == total, f"{passed}/{total}\n{tail if passed != total else ''}"),
        check("quarantine of code-exec functions", "run_report" in quarantined_all, str(quarantined_all)),
        check("FastAPI endpoints generated", len(endpoints) >= 5, f"{len(endpoints)} endpoints"),
    ]
    artifacts = {"audit_report": str(out_dir / "client_audit_report.md"), "findings": str(out_dir / "findings.json"),
                 "service": str(svc / "service.py"), "tests": str(svc / "tests")}
    return {"artifacts": artifacts, "checks": checks, "summary": f"Audit of {repo.name}: {base}",
            "metrics": {"findings": len(findings), "risk_before": risk_before, "risk_after": risk_after,
                        "tests": f"{passed}/{total}", "endpoints": len(endpoints)}}


if __name__ == "__main__":
    import argparse
    from config import Settings
    from llm import LLMClient
    ap = argparse.ArgumentParser(description="Run the legacy migrator on a repo")
    ap.add_argument("repo", nargs="?", default=str(DEFAULT_REPO))
    ap.add_argument("--out", default="output/PRJ-01")
    a = ap.parse_args()
    r = run(Path(a.out), LLMClient(Settings.load()), repo=Path(a.repo))
    print(json.dumps(r["metrics"], indent=2))
    for c in r["checks"]:
        print(("PASS" if c["passed"] else "FAIL"), c["name"], c["detail"])
