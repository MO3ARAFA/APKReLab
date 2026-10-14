import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE.parents[1]))

from projects.prj_02_gap_cloner import review_pain_extractor as rpe  # noqa: E402
from projects.prj_02_gap_cloner import validate_extension as ve  # noqa: E402

SAMPLE = HERE / "sample_data" / "competitor_reviews.json"


def test_only_low_star_reviews_analyzed():
    reviews = rpe.load_reviews(SAMPLE)
    rep = rpe.analyze(reviews)
    assert rep["reviews_analyzed"] == sum(1 for r in reviews if r.rating <= 2)
    assert rep["reviews_analyzed"] < rep["reviews_total"]


def test_categories_detected():
    rep = rpe.analyze(rpe.load_reviews(SAMPLE))
    for cat in ("pricing", "performance", "missing_feature", "support"):
        assert rep["categories"][cat]["reviews_mentioning"] >= 3


def test_pricing_points_extracted():
    rep = rpe.analyze(rpe.load_reviews(SAMPLE))
    assert {89, 99, 120, 200} <= set(rep["pricing"]["price_points_mentioned"])


def test_feature_extraction_and_clustering():
    feats = rpe.extract_features("I wish it had an offline mode. No way to merge duplicates!")
    assert "offline mode" in feats and "merge duplicates" in feats
    rep = rpe.analyze(rpe.load_reviews(SAMPLE))
    top = rep["missing_feature_opportunities"][0]
    assert "offline" in top["feature"]


def test_positive_reviews_ignored():
    rep = rpe.analyze([rpe.Review(5, "Too expensive but great"), rpe.Review(1, "Way too expensive")])
    assert rep["reviews_analyzed"] == 1


def test_csv_loading(tmp_path):
    p = tmp_path / "r.csv"
    p.write_text("rating,text\n1,Slow and laggy\n5,Great\nx,bad row\n")
    assert len(rpe.load_reviews(p)) == 2


def test_extension_validates():
    failures = [n for n, c, d in ve.validate(HERE / "crm_clipper_extension") if not c]
    assert failures == []


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_extension_logic_in_node():
    p = subprocess.run(["node", str(HERE / "tests" / "ext_logic.test.js"), str(HERE / "crm_clipper_extension" / "db.js")],
                       capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
