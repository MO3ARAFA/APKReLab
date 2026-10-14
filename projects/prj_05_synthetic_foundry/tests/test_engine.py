import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE.parents[1]))

from projects.prj_05_synthetic_foundry import synthetic_engine as se  # noqa: E402

REAL = se.load_dataset(HERE / "sample_data" / "customers_sample.csv")


@pytest.fixture(scope="module")
def model():
    return se.fit(REAL)


def test_schema_inference(model):
    t = {s["name"]: s.get("pii_type", s["type"]) for s in model["schema"]}
    assert t["full_name"] == "name" and t["email"] == "email" and t["ssn"] == "ssn" and t["phone"] == "phone"
    assert t["customer_id"] == "identifier" and t["age"] == "numeric" and t["region"] == "categorical"
    assert t["signup_date"] == "date" and t["churned"] == "categorical"


def test_value_based_pii_detection():
    assert se.detect_pii("contact", ["a@b.com", "c@d.org", "e@f.net"]) == "email"
    assert se.detect_pii("misc", ["4111111111111111", "5500005555555559"]) == "card"  # Luhn-valid test numbers
    assert se.detect_pii("score", ["10", "20", "30"]) is None


def test_model_contains_no_raw_pii(model):
    blob = json.dumps(model)
    for r in REAL:
        for c in ("full_name", "email", "phone", "ssn"):
            assert r[c] not in blob
    assert model["privacy"]["raw_rows_stored"] is False


def test_numeric_quantiles_are_trimmed(model):
    q = model["columns"]["annual_income"]["quantiles"]
    vals = sorted(float(r["annual_income"]) for r in REAL)
    assert q[0] > vals[0] and q[-1] < vals[-1]  # exact min / max are not released
    assert q == sorted(q)


def test_rare_categories_suppressed():
    rows = [{"c": "common"} for _ in range(50)] + [{"c": "rare1"}, {"c": "rare2"}]
    m = se.fit(rows, k_min=3)
    cats = dict(m["columns"]["c"]["categories"])
    assert "rare1" not in cats and "OTHER" in cats


def test_sampling_shape_and_types(model):
    s = se.sample(model, 300, seed=5)
    assert len(s) == 300 and set(s[0]) == set(REAL[0])
    assert all(isinstance(r["age"], int) for r in s)
    assert {r["region"] for r in s} <= {"north", "south", "east", "west", "OTHER"}
    assert all(r["email"].endswith("@example.com") for r in s)
    assert all(r["phone"].startswith("555-01") for r in s)


def test_deterministic(model):
    assert se.sample(model, 40, seed=9) == se.sample(model, 40, seed=9)
    assert se.sample(model, 40, seed=9) != se.sample(model, 40, seed=10)


def test_validation_high_fidelity_and_privacy(model):
    rep = se.validate(REAL, se.sample(model, 1000, seed=1), model)
    assert rep["validation_score"] >= 90
    assert rep["privacy"]["passed"] and rep["privacy"]["pii_values_leaked"] == 0


def test_validation_detects_bad_synthetic_data(model):
    bad = se.sample(model, 400, seed=1)
    for r in bad:  # destroy marginals + correlations
        r["age"] = 18
        r["annual_income"] = 1.0
        r["region"] = "south"
    rep = se.validate(REAL, bad, model)
    assert rep["fidelity_score"] < 75


def test_validation_detects_pii_leak(model):
    leak = se.sample(model, 100, seed=1)
    leak[0]["email"] = REAL[0]["email"]
    rep = se.validate(REAL, leak, model)
    assert rep["privacy"]["pii_values_leaked"] == 1 and not rep["privacy"]["passed"] and rep["validation_score"] <= 50


def test_validation_detects_row_copying(model):
    copied = [{**r} for r in REAL]  # real rows verbatim
    rep = se.validate(REAL, copied, model)
    assert rep["privacy"]["exact_row_match_rate"] > 0.5 and not rep["privacy"]["passed"]


def test_correlations_preserved(model):
    rep = se.validate(REAL, se.sample(model, 1500, seed=2), model)
    pair = next(p for p in rep["correlations"] if set(p["pair"]) == {"age", "annual_income"})
    assert pair["real"] > 0.4 and abs(pair["real"] - pair["synthetic"]) < 0.12


def test_ks_statistic_known_values():
    assert se.ks_statistic([1, 2, 3], [1, 2, 3]) == 0
    assert se.ks_statistic([1, 2, 3], [10, 11, 12]) == 1


def test_cholesky_reconstructs():
    a = [[1.0, 0.6], [0.6, 1.0]]
    L = se.cholesky(a)
    assert abs(L[1][0] * L[0][0] - 0.6) < 1e-9 and abs(L[1][0] ** 2 + L[1][1] ** 2 - 1) < 1e-9


def test_epsilon_noise_changes_stats_but_keeps_validity():
    m0, m1 = se.fit(REAL, epsilon=None), se.fit(REAL, epsilon=1.0, seed=3)
    assert m0["columns"]["age"]["quantiles"] != m1["columns"]["age"]["quantiles"]
    assert se.validate(REAL, se.sample(m1, 600, seed=1), m1)["validation_score"] >= 75


def test_json_input(tmp_path):
    p = tmp_path / "d.json"
    p.write_text(json.dumps({"rows": [{"x": i, "g": "a" if i % 2 else "b"} for i in range(60)]}))
    rows = se.load_dataset(p)
    m = se.fit(rows)
    assert len(se.sample(m, 10)) == 10


def test_nulls_preserved():
    rows = [{"x": i if i % 4 else "", "g": "a" if i % 2 else "b"} for i in range(200)]
    m = se.fit(rows)
    s = se.sample(m, 1000, seed=1)
    assert 0.15 < sum(1 for r in s if r["x"] == "") / 1000 < 0.35
