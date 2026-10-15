"""PRJ-02 pipeline: review pain extraction + Chrome MV3 CRM clipper packaging."""
from __future__ import annotations

import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from projects.common import check, run_pytest
from projects.prj_02_gap_cloner import launch_copy, make_icons, review_pain_extractor as rpe, validate_extension

HERE = Path(__file__).resolve().parent
EXT_SRC = HERE / "crm_clipper_extension"


def run(out_dir: Path, llm, dry_run: bool = False, feedback: list[str] | None = None,
        reviews_path: Path | None = None) -> dict:
    out_dir = Path(out_dir)
    env_reviews = os.getenv("REVIEWS_FILE")
    using_sample = not (reviews_path or env_reviews)
    reviews_path = Path(reviews_path or env_reviews or HERE / "sample_data" / "competitor_reviews.json")

    reviews = rpe.load_reviews(reviews_path)
    report = rpe.analyze(reviews)
    (out_dir / "pain_report.json").write_text(json.dumps(report, indent=2))

    # Hybrid pre-processing: mining/clustering is local. Customer-facing copy gets themes only - never review stats/quotes.
    copy_md, copy_meta = launch_copy.build_launch_copy(report, llm, sample_data=using_sample)
    (out_dir / "LAUNCH_COPY.md").write_text(copy_md)
    hero = copy_md.split("## Description", 1)[1].split("\n\n", 2)[1]
    (out_dir / "gap_brief.md").write_text(rpe.brief_markdown(report, "Competitor CRM", hero))

    # Package the extension (regenerate icons if missing) and ship a Web-Store-ready zip.
    make_icons.make(EXT_SRC / "icons") if not (EXT_SRC / "icons" / "icon128.png").exists() else None
    ext_out = out_dir / "crm_clipper_extension"
    if ext_out.exists():
        shutil.rmtree(ext_out)
    shutil.copytree(EXT_SRC, ext_out)
    zip_path = out_dir / "crm_clipper_extension.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(ext_out.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(ext_out))  # manifest.json must be at zip root

    ext_checks = validate_extension.validate(ext_out)
    failed_ext = [f"{n} {d}".strip() for n, c, d in ext_checks if not c]
    passed, total, tail = run_pytest(HERE / "tests", cwd=HERE)
    with zipfile.ZipFile(zip_path) as z:
        names = z.namelist()

    cats = report["categories"]
    checks = [
        check("only 1-2 star reviews analyzed", 0 < report["reviews_analyzed"] < report["reviews_total"]),
        check("pricing/performance/missing-feature pain extracted",
              all(cats.get(c, {}).get("reviews_mentioning", 0) > 0 for c in ("pricing", "performance", "missing_feature"))),
        check("ranked feature opportunities (>=5)", len(report["missing_feature_opportunities"]) >= 5),
        check("extension passes MV3 validation", not failed_ext, "; ".join(failed_ext)),
        check("launch copy has title, $39 price, tiers and FAQ",
              all(x in copy_md for x in (launch_copy.TITLE, "$39", "Pricing tiers", "## FAQ", "Gumroad")), ""),
        check("launch copy contains no unverifiable claims", not launch_copy.HYPE.search(copy_md.split("## Gumroad", 1)[0]
                                                                                         .replace("Do not add testimonials", ""))),
        check("extension zip has manifest at root", "manifest.json" in names and "db.js" in names),
        check("project tests pass (python + node IndexedDB)", total >= 8 and passed == total, f"{passed}/{total}\n{tail if passed != total else ''}"),
    ]
    artifacts = {"pain_report": str(out_dir / "pain_report.json"), "gap_brief": str(out_dir / "gap_brief.md"),
                 "extension": str(ext_out / "manifest.json"), "extension_zip": str(zip_path),
                 "launch_copy": str(out_dir / "LAUNCH_COPY.md")}
    return {"artifacts": artifacts, "checks": checks,
            "summary": f"Analyzed {report['reviews_analyzed']} low-star reviews; top pain '{report['top_pain']}'; "
                       f"extension packaged ({len(names)} files, {passed}/{total} tests).",
            "units": {"extensions_packaged": 1},
            "metrics": {"reviews_analyzed": report["reviews_analyzed"], "opportunities": len(report["missing_feature_opportunities"]),
                        "tests": f"{passed}/{total}"}}


if __name__ == "__main__":
    from config import Settings
    from llm import LLMClient
    out = Path("output/PRJ-02")
    out.mkdir(parents=True, exist_ok=True)
    r = run(out, LLMClient(Settings.load()))
    for c in r["checks"]:
        print("PASS" if c["passed"] else "FAIL", c["name"], c["detail"])
