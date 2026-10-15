"""PRJ-05 pipeline: profile sample data -> persist PII-free model -> generate synthetic rows -> validate."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from projects.common import check, run_pytest
from projects.prj_05_synthetic_foundry import make_sample, synthetic_engine as se

HERE = Path(__file__).resolve().parent
SAMPLE = HERE / "sample_data" / "customers_sample.csv"


def leaked_values(real: list[dict], model: dict, files: list[Path]) -> list[str]:
    """Any raw PII value from the input that appears verbatim in a persisted artifact."""
    pii_cols = model["privacy"]["pii_columns"]
    secrets = {str(r[c]) for c in pii_cols for r in real if r.get(c) not in (None, "")}
    blob = "\n".join(p.read_text() for p in files)
    return sorted(s for s in secrets if s in blob)


def run(out_dir: Path, llm, dry_run: bool = False, feedback: list[str] | None = None, data_path: Path | None = None) -> dict:
    out_dir = Path(out_dir)
    data_path = Path(data_path or SAMPLE)
    if not data_path.exists() and data_path == SAMPLE:
        make_sample.write(SAMPLE)
    real = se.load_dataset(data_path)
    n_rows = 200 if dry_run else 2000

    model = se.fit(real, k_min=3, seed=0)
    synth = se.sample(model, n_rows, seed=1)
    report = se.validate(real, synth, model)

    (out_dir / "privacy_safe_model.json").write_text(json.dumps(model, indent=2))
    se.write_csv(synth, out_dir / "synthetic_data.csv")
    (out_dir / "validation_report.json").write_text(json.dumps(report, indent=2))

    # Determinism + differential-noise variants
    synth2 = se.sample(model, 50, seed=1)
    deterministic = synth2 == se.sample(model, 50, seed=1)
    dp_model = se.fit(real, k_min=3, epsilon=2.0, seed=0)
    dp_report = se.validate(real, se.sample(dp_model, 500, seed=1), dp_model)

    md = ["# Synthetic Data Validation Report", "", "> DRY-RUN: reduced volume (Group B gated until Group A revenue)." if dry_run else "",
          f"**Validation score: {report['validation_score']}/100** (privacy gate: {'PASS' if report['privacy']['passed'] else 'FAIL'})", "",
          f"Source rows: {len(real)} | synthetic rows: {n_rows} | PII columns (never modeled): {', '.join(report['privacy']['pii_columns']) or 'none'}", "",
          "## Formula", "", f"`{report['formula']}`", "", "## Components", "", "| Component | Score |", "|---|---|"]
    md += [f"| {k} | {v} |" for k, v in report["components"].items()]
    md += ["", "## Per-column fit", "", "| Column | Metric |", "|---|---|"] + [f"| {c} | {d} |" for c, d in report["columns"].items()]
    md += ["", "## Strongest correlations (real vs synthetic)", "", "| Pair | Real | Synthetic |", "|---|---|---|"]
    for p in sorted(report["correlations"], key=lambda p: -abs(p["real"]))[:6]:
        md.append(f"| {p['pair'][0]} x {p['pair'][1]} | {p['real']} | {p['synthetic']} |")
    md += ["", "## Privacy", "", f"- PII values leaked into synthetic output: **{report['privacy']['pii_values_leaked']}**",
           f"- Exact non-PII row matches with source: **{report['privacy']['exact_row_match_rate']:.2%}**",
           f"- Median distance-to-closest-record ratio (synthetic vs real NN): **{report['privacy']['dcr_ratio_median']}** (>=1 means no closer to a real record than real records are to each other)",
           f"- With Laplace noise epsilon=2.0 on released statistics: score {dp_report['validation_score']}",
           "", "Raw rows and PII values are never written to the model file. Noise on statistics is *not* a formal end-to-end differential-privacy guarantee.", ""]
    (out_dir / "validation_report.md").write_text("\n".join(md))

    leaks = leaked_values(real, model, [out_dir / "privacy_safe_model.json", out_dir / "synthetic_data.csv", out_dir / "validation_report.md",
                                        out_dir / "validation_report.json"])
    passed, total, tail = run_pytest(HERE / "tests", cwd=HERE)
    checks = [
        check("validation score >= 90", report["validation_score"] >= 90, str(report["validation_score"])),
        check("privacy gate passes (no PII leak, no row copies, DCR ok)", report["privacy"]["passed"], str(report["privacy"])),
        check("no raw PII value appears in any persisted artifact", not leaks, f"{len(leaks)} leaked"),
        check("PII columns detected (name/email/phone/ssn)", {"full_name", "email", "phone", "ssn"} <= set(report["privacy"]["pii_columns"])),
        check("generation is reproducible for a fixed seed", deterministic),
        check("noised-statistics variant still valid", dp_report["validation_score"] >= 80 and dp_report["privacy"]["passed"], str(dp_report["validation_score"])),
        check("project tests pass", total >= 8 and passed == total, f"{passed}/{total}\n{tail if passed != total else ''}"),
    ]
    artifacts = {"synthetic_data": str(out_dir / "synthetic_data.csv"), "model": str(out_dir / "privacy_safe_model.json"),
                 "validation_json": str(out_dir / "validation_report.json"), "report": str(out_dir / "validation_report.md")}
    return {"artifacts": artifacts, "checks": checks,
            "summary": f"Generated {n_rows} synthetic rows; validation score {report['validation_score']}/100; privacy gate "
                       f"{'passed' if report['privacy']['passed'] else 'FAILED'} ({'dry-run' if dry_run else 'full'}).",
            "units": {"datasets_generated": 1},
            "metrics": {"validation_score": report["validation_score"], "rows": n_rows, "tests": f"{passed}/{total}"}}


if __name__ == "__main__":
    from config import Settings
    from llm import LLMClient
    out = Path("output/PRJ-05")
    out.mkdir(parents=True, exist_ok=True)
    r = run(out, LLMClient(Settings.load()))
    for c in r["checks"]:
        print("PASS" if c["passed"] else "FAIL", c["name"], c["detail"])
