"""Privacy-preserving synthetic data engine (pure Python, no numpy).

Pipeline: ingest CSV/JSON -> detect PII -> fit a *statistical profile* (marginals + Gaussian-copula correlation)
-> persist ONLY the profile (never raw rows / PII) -> sample synthetic records -> validate fidelity + privacy.

Privacy notes (be precise about what is and is not guaranteed):
  * PII columns are never modeled: only their detected type is stored; synthetic values come from independent
    generators (fictional ranges), so no original PII can be reproduced.
  * Numeric marginals are stored as trimmed quantiles (1st..99th percentile) so exact min/max are not released.
  * Categories rarer than k_min are merged into "OTHER" (k-anonymity style suppression).
  * Optional Laplace noise (epsilon) is applied to released statistics. This is a noised-statistics release, not an
    end-to-end formal differential-privacy proof of the whole pipeline.
"""
from __future__ import annotations

import csv
import json
import math
import random
import re
from datetime import date
from pathlib import Path
from statistics import NormalDist

ND = NormalDist()
PROBS = [0.01] + [round(p * 0.05, 2) for p in range(1, 20)] + [0.99]  # 21 knots
NAME_PII = [
    ("email", r"e[-_]?mail"), ("ssn", r"ssn|social[-_]?sec|national[-_]?id|tax[-_]?id"),
    ("phone", r"phone|mobile|\btel\b|fax"), ("name", r"(^|_)(first|last|full|sur|given|middle)?_?name$|^name$|surname"),
    ("address", r"address|street|postcode|postal|zip"), ("ip", r"(^|_)ip(_?addr(ess)?)?$"),
    ("dob", r"birth|dob"), ("card", r"card[-_]?(num|no)|credit|iban|passport|licen[sc]e"),
]
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
SSN_RE = re.compile(r"^\d{3}-\d{2}-\d{4}$")
PHONE_RE = re.compile(r"^\+?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}$")
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Synthetic pools: fictional by construction and disjoint from typical real data.
SYN_FIRST = ["Alex", "Blair", "Casey", "Drew", "Emery", "Finley", "Gray", "Harper", "Indy", "Jules", "Kai", "Lane", "Morgan", "Nico", "Oak", "Parker"]
SYN_LAST = ["Testwell", "Samplewood", "Mockridge", "Fakeman", "Dummerton", "Synthford", "Placeholder", "Examplar", "Stubbs", "Mockingham"]


def luhn_ok(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    tot = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x = x * 2 - 9 if x * 2 > 9 else x * 2
        tot += x
    return tot % 10 == 0


# ---------------------------------------------------------------- ingestion & typing
def load_dataset(path: Path) -> list[dict]:
    path = Path(path)
    if path.suffix == ".json":
        data = json.loads(path.read_text())
        if isinstance(data, dict):
            data = next((v for v in data.values() if isinstance(v, list)), [data])
        return [dict(r) for r in data]
    if path.suffix == ".csv":
        with path.open(newline="") as fh:
            return list(csv.DictReader(fh))
    raise ValueError(f"unsupported dataset type: {path.suffix}")


def _num(v):
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def detect_pii(col: str, vals: list) -> str | None:
    c = col.lower()
    for kind, pat in NAME_PII:
        if re.search(pat, c):
            return kind
    s = [str(v) for v in vals if v not in (None, "")]
    if not s:
        return None
    frac = lambda f: sum(1 for x in s if f(x)) / len(s)  # noqa: E731
    if frac(lambda x: EMAIL_RE.match(x)) > 0.5:
        return "email"
    if frac(lambda x: SSN_RE.match(x)) > 0.5:
        return "ssn"
    if frac(lambda x: PHONE_RE.match(x)) > 0.5:
        return "phone"
    if frac(lambda x: IP_RE.match(x)) > 0.5:
        return "ip"
    if frac(lambda x: luhn_ok(x) and x.replace("-", "").replace(" ", "").isdigit()) > 0.5:
        return "card"
    return None


def infer_column(col: str, vals: list) -> dict:
    nonnull = [v for v in vals if v not in (None, "")]
    null_rate = 1 - len(nonnull) / len(vals) if vals else 0.0
    base = {"name": col, "null_rate": round(null_rate, 4)}
    if not nonnull:
        return {**base, "type": "empty"}
    pii = detect_pii(col, vals)
    if pii:
        return {**base, "type": "pii", "pii_type": pii}
    uniq = len({str(v) for v in nonnull})
    nums = [_num(v) for v in nonnull]
    if re.search(r"(^|_)id$", col.lower()) or (uniq == len(nonnull) and len(nonnull) > 20 and all(n is not None and float(n).is_integer() for n in nums)):
        return {**base, "type": "identifier"}
    if all(DATE_RE.match(str(v)) for v in nonnull):
        return {**base, "type": "date"}
    if all(n is not None for n in nums) and not (set(map(str, nonnull)) <= {"0", "1"}):
        return {**base, "type": "numeric", "integer": all(float(n).is_integer() for n in nums)}
    if uniq / len(nonnull) > 0.9 and len(nonnull) > 20:
        return {**base, "type": "identifier"}  # high-cardinality free text: not modeled, never stored
    return {**base, "type": "categorical"}


# ---------------------------------------------------------------- fitting
def _quantile(sorted_vals: list[float], p: float) -> float:
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = p * (len(sorted_vals) - 1)
    lo = int(math.floor(pos))
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def _laplace(rng: random.Random, scale: float) -> float:
    u = rng.random() - 0.5
    return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))


def cholesky(a: list[list[float]]) -> list[list[float]]:
    n = len(a)
    ridge = 0.0
    for _ in range(8):
        L = [[0.0] * n for _ in range(n)]
        try:
            for i in range(n):
                for j in range(i + 1):
                    s = sum(L[i][k] * L[j][k] for k in range(j))
                    if i == j:
                        v = a[i][i] + ridge - s
                        if v <= 1e-12:
                            raise ValueError
                        L[i][j] = math.sqrt(v)
                    else:
                        L[i][j] = (a[i][j] - s) / L[j][j]
            return L
        except ValueError:
            ridge = ridge * 10 or 1e-6
    raise ValueError("correlation matrix is not positive semi-definite")


def pearson(x: list[float], y: list[float]) -> float:
    n = len(x)
    mx, my = sum(x) / n, sum(y) / n
    sx = math.sqrt(sum((a - mx) ** 2 for a in x))
    sy = math.sqrt(sum((b - my) ** 2 for b in y))
    if sx == 0 or sy == 0:
        return 0.0
    return sum((a - mx) * (b - my) for a, b in zip(x, y)) / (sx * sy)


def _to_number(col: dict, v):
    if col["type"] == "date":
        return float(date.fromisoformat(str(v)).toordinal())
    return _num(v)


def latent_scores(col: dict, vals: list, model_col: dict, rng: random.Random) -> list[float]:
    """Map a column to standard-normal latent scores (rank-based for numeric, interval-based for categorical)."""
    n = len(vals)
    out = [0.0] * n
    if col["type"] in {"numeric", "date"}:
        idx = [(i, _to_number(col, v)) for i, v in enumerate(vals) if v not in (None, "")]
        idx.sort(key=lambda t: t[1])
        # average ranks for ties
        i = 0
        while i < len(idx):
            j = i
            while j + 1 < len(idx) and idx[j + 1][1] == idx[i][1]:
                j += 1
            u = ((i + j) / 2 + 0.5) / len(idx)
            for k in range(i, j + 1):
                out[idx[k][0]] = ND.inv_cdf(min(max(u, 1e-4), 1 - 1e-4))
            i = j + 1
    else:  # categorical: latent drawn within the category's cumulative-probability interval
        cum, acc = {}, 0.0
        for cat, p in model_col["categories"]:
            cum[cat] = (acc, acc + p)
            acc += p
        for i, v in enumerate(vals):
            if v in (None, ""):
                continue
            lo, hi = cum.get(str(v), cum.get("OTHER", (0.0, 1.0)))
            u = lo + rng.random() * (hi - lo)
            out[i] = ND.inv_cdf(min(max(u, 1e-4), 1 - 1e-4))
    return out


def fit(rows: list[dict], k_min: int = 3, epsilon: float | None = None, seed: int = 0) -> dict:
    """Return a privacy-safe statistical profile. Raw values/PII are never included."""
    if not rows:
        raise ValueError("empty dataset")
    rng = random.Random(seed)
    cols = list(rows[0].keys())
    n = len(rows)
    schema, model_cols = [], {}
    for c in cols:
        vals = [r.get(c) for r in rows]
        info = infer_column(c, vals)
        schema.append(info)
        nonnull = [v for v in vals if v not in (None, "")]
        if info["type"] in {"numeric", "date"}:
            xs = sorted(_to_number(info, v) for v in nonnull)
            q = [_quantile(xs, p) for p in PROBS]
            if epsilon:
                scale = max(xs[-1] - xs[0], 1e-9) / (epsilon * max(len(xs), 1)) * len(PROBS)
                q = [x + _laplace(rng, scale) for x in q]
            q.sort()  # keep monotone after noise
            dec = 0
            if info["type"] == "numeric" and not info["integer"]:
                dec = min(4, max(len(str(v).split(".")[1]) if "." in str(v) else 0 for v in nonnull))
            model_col = {"quantiles": [round(x, 6) for x in q], "decimals": dec}
        elif info["type"] == "categorical":
            counts: dict[str, float] = {}
            for v in nonnull:
                counts[str(v)] = counts.get(str(v), 0) + 1
            if epsilon:
                counts = {k: max(0.0, v + _laplace(rng, 1 / epsilon)) for k, v in counts.items()}
            rare = {k for k, v in counts.items() if v < k_min}
            merged = {k: v for k, v in counts.items() if k not in rare}
            if rare:
                merged["OTHER"] = sum(counts[k] for k in rare)
            total = sum(merged.values()) or 1
            model_col = {"categories": [[k, round(v / total, 6)] for k, v in sorted(merged.items(), key=lambda kv: -kv[1])]}
        else:
            model_col = {}
        model_cols[c] = model_col
    modeled = [s for s in schema if s["type"] in {"numeric", "date", "categorical"}]
    lat = {s["name"]: latent_scores(s, [r.get(s["name"]) for r in rows], model_cols[s["name"]], rng) for s in modeled}
    names = [s["name"] for s in modeled]
    corr = [[1.0 if i == j else round(pearson(lat[a], lat[b]), 4) for j, b in enumerate(names)] for i, a in enumerate(names)]
    lam = 0.05  # shrink toward identity: stabilises small-sample estimates
    corr = [[corr[i][j] * (1 - lam) + (lam if i == j else 0) for j in range(len(names))] for i in range(len(names))]
    return {"version": 1, "rows_seen": n, "k_min": k_min, "epsilon": epsilon, "schema": schema, "columns": model_cols,
            "copula": {"columns": names, "correlation": [[round(x, 4) for x in r] for r in corr]},
            "privacy": {"raw_rows_stored": False, "pii_values_stored": False,
                        "pii_columns": [s["name"] for s in schema if s["type"] == "pii"]}}


# ---------------------------------------------------------------- sampling
def _qfun(q: list[float], u: float) -> float:
    if u <= PROBS[0]:
        return q[0]
    if u >= PROBS[-1]:
        return q[-1]
    for i in range(1, len(PROBS)):
        if u <= PROBS[i]:
            f = (u - PROBS[i - 1]) / (PROBS[i] - PROBS[i - 1])
            return q[i - 1] + f * (q[i] - q[i - 1])
    return q[-1]


def _fake_pii(kind: str, i: int, rng: random.Random) -> str:
    if kind == "email":
        return f"user{i:06d}.{rng.randint(1000, 9999)}@example.com"  # RFC 2606 reserved domain
    if kind == "ssn":
        return f"9{rng.randint(0, 99):02d}-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}"  # 9xx = never issued
    if kind == "phone":
        return f"555-01{rng.randint(0, 99):02d}"  # reserved fictional range
    if kind == "name":
        return f"{rng.choice(SYN_FIRST)} {rng.choice(SYN_LAST)}"
    if kind == "address":
        return f"{rng.randint(1, 999)} Example Street"
    if kind == "ip":
        return f"192.0.2.{rng.randint(1, 254)}"  # TEST-NET-1
    if kind == "dob":
        return f"19{rng.randint(50, 99)}-01-01"
    return f"SYN-{rng.randint(10**7, 10**8 - 1)}"


def sample(model: dict, n: int, seed: int = 1) -> list[dict]:
    rng = random.Random(seed)
    names = model["copula"]["columns"]
    L = cholesky(model["copula"]["correlation"]) if names else []
    rows = []
    for i in range(n):
        eps = [rng.gauss(0, 1) for _ in names]
        z = [sum(L[r][k] * eps[k] for k in range(r + 1)) for r in range(len(names))]
        zmap = dict(zip(names, z))
        row = {}
        for s in model["schema"]:
            c, t = s["name"], s["type"]
            if t not in {"empty"} and rng.random() < s["null_rate"]:
                row[c] = ""
                continue
            if t == "empty":
                row[c] = ""
            elif t == "pii":
                row[c] = _fake_pii(s["pii_type"], i, rng)
            elif t == "identifier":
                row[c] = 100000 + i
            elif t in {"numeric", "date"}:
                v = _qfun(model["columns"][c]["quantiles"], ND.cdf(zmap[c]))
                if t == "date":
                    row[c] = date.fromordinal(max(1, int(round(v)))).isoformat()
                elif s.get("integer"):
                    row[c] = int(round(v))
                else:
                    row[c] = round(v, model["columns"][c]["decimals"])
            else:
                u, acc = ND.cdf(zmap[c]), 0.0
                cats = model["columns"][c]["categories"]
                row[c] = cats[-1][0]
                for cat, p in cats:
                    acc += p
                    if u <= acc:
                        row[c] = cat
                        break
        rows.append(row)
    return rows


# ---------------------------------------------------------------- validation
def ks_statistic(a: list[float], b: list[float]) -> float:
    a, b = sorted(a), sorted(b)
    i = j = 0
    d = 0.0
    while i < len(a) and j < len(b):
        x = min(a[i], b[j])
        while i < len(a) and a[i] <= x:
            i += 1
        while j < len(b) and b[j] <= x:
            j += 1
        d = max(d, abs(i / len(a) - j / len(b)))
    return d


def validate(real: list[dict], synth: list[dict], model: dict, rng_seed: int = 3) -> dict:
    schema = model["schema"]
    num_scores, cat_scores, detail = {}, {}, {}
    for s in schema:
        c = s["name"]
        if s["type"] in {"numeric", "date"}:
            a = [_to_number(s, r[c]) for r in real if r.get(c) not in (None, "")]
            b = [_to_number(s, r[c]) for r in synth if r.get(c) not in (None, "")]
            ks = ks_statistic(a, b)
            ma, mb = sum(a) / len(a), sum(b) / len(b)
            sa = math.sqrt(sum((x - ma) ** 2 for x in a) / len(a)) or 1.0
            num_scores[c] = 1 - ks
            detail[c] = {"ks": round(ks, 4), "mean_err_in_sd": round(abs(ma - mb) / sa, 4)}
        elif s["type"] == "categorical":
            fa, fb = {}, {}
            for r in real:
                if r.get(c) not in (None, ""):
                    fa[str(r[c])] = fa.get(str(r[c]), 0) + 1
            for r in synth:
                if r.get(c) not in (None, ""):
                    fb[str(r[c])] = fb.get(str(r[c]), 0) + 1
            ta, tb = sum(fa.values()), sum(fb.values())
            allk = set(fa) | set(fb)
            rare = {k for k in fa if fa[k] < model["k_min"]}  # suppressed in the model: fold into OTHER on both sides
            def p(f, t, k):
                return (sum(f.get(x, 0) for x in rare) + f.get("OTHER", 0)) / t if k == "OTHER" else f.get(k, 0) / t
            keys = (allk - rare) | ({"OTHER"} if rare else set())
            tvd = 0.5 * sum(abs(p(fa, ta, k) - p(fb, tb, k)) for k in keys)
            cat_scores[c] = 1 - tvd
            detail[c] = {"tvd": round(tvd, 4)}
    # correlation fidelity over the copula's own latent space is not comparable to raw data, so use ordinal encodings
    def encode(rows, s, cats):
        if s["type"] in {"numeric", "date"}:
            return [_to_number(s, r[s["name"]]) if r.get(s["name"]) not in (None, "") else None for r in rows]
        return [cats.get(str(r[s["name"]]), cats.get("OTHER")) if r.get(s["name"]) not in (None, "") else None for r in rows]
    modeled = [s for s in schema if s["type"] in {"numeric", "date", "categorical"}]
    encs = {}
    for s in modeled:
        cats = {k: i for i, (k, _) in enumerate(model["columns"][s["name"]].get("categories", []))}
        encs[s["name"]] = (encode(real, s, cats), encode(synth, s, cats))

    def spear(xs):  # rank transform (ties averaged) so ordinal encodings and skewed numerics are comparable
        idx = sorted((x, i) for i, x in enumerate(xs) if x is not None)
        r = {}
        i = 0
        while i < len(idx):
            j = i
            while j + 1 < len(idx) and idx[j + 1][0] == idx[i][0]:
                j += 1
            for k in range(i, j + 1):
                r[idx[k][1]] = (i + j) / 2
            i = j + 1
        return [r.get(k) for k in range(len(xs))]
    diffs = []
    pairs = []
    for i, a in enumerate(modeled):
        for b in modeled[i + 1:]:
            def corr(which):
                x, y = spear(encs[a["name"]][which]), spear(encs[b["name"]][which])
                pr = [(u, v) for u, v in zip(x, y) if u is not None and v is not None]
                return pearson([u for u, _ in pr], [v for _, v in pr]) if len(pr) > 2 else 0.0
            cr, cs = corr(0), corr(1)
            diffs.append(abs(cr - cs))
            pairs.append({"pair": [a["name"], b["name"]], "real": round(cr, 3), "synthetic": round(cs, 3)})
    corr_score = 1 - (sum(diffs) / len(diffs) if diffs else 0.0)

    # privacy
    pii_cols = [s["name"] for s in schema if s["type"] == "pii"]
    real_pii = {str(r[c]) for c in pii_cols for r in real if r.get(c) not in (None, "")}
    leaked = sorted({str(r[c]) for c in pii_cols for r in synth} & real_pii)
    nonpii = [s["name"] for s in schema if s["type"] in {"numeric", "date", "categorical"}]
    real_keys = {tuple(str(r.get(c)) for c in nonpii) for r in real}
    exact = sum(1 for r in synth if tuple(str(r.get(c)) for c in nonpii) in real_keys) / max(1, len(synth))
    # distance-to-closest-record on normalized numeric columns
    numcols = [s for s in schema if s["type"] == "numeric"]
    dcr_ratio = None
    if numcols:
        sd = {}
        for s in numcols:
            v = [_num(r[s["name"]]) for r in real if _num(r.get(s["name"])) is not None]
            m = sum(v) / len(v)
            sd[s["name"]] = math.sqrt(sum((x - m) ** 2 for x in v) / len(v)) or 1.0
        def vec(r):
            return [(_num(r.get(s["name"])) or 0.0) / sd[s["name"]] for s in numcols]
        rv = [vec(r) for r in real][:300]
        sv = [vec(r) for r in synth][:150]
        dist = lambda a, b: math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))  # noqa: E731
        dcr_s = sorted(min(dist(a, b) for b in rv) for a in sv)
        nn_r = sorted(min(dist(rv[i], rv[j]) for j in range(len(rv)) if j != i) for i in range(min(150, len(rv))))
        med_s, med_r = dcr_s[len(dcr_s) // 2], nn_r[len(nn_r) // 2]
        dcr_ratio = round(med_s / med_r, 3) if med_r else None
    privacy_pass = not leaked and exact <= 0.01 and (dcr_ratio is None or dcr_ratio >= 0.5)

    num_avg = sum(num_scores.values()) / len(num_scores) if num_scores else 1.0
    cat_avg = sum(cat_scores.values()) / len(cat_scores) if cat_scores else 1.0
    fidelity = 100 * (0.4 * num_avg + 0.3 * cat_avg + 0.3 * corr_score)
    overall = fidelity if privacy_pass else min(fidelity, 50.0)
    return {
        "validation_score": round(overall, 2), "fidelity_score": round(fidelity, 2),
        "components": {"numeric_ks": round(num_avg, 4), "categorical_tvd": round(cat_avg, 4), "correlation": round(corr_score, 4)},
        "columns": detail, "correlations": pairs,
        "privacy": {"passed": privacy_pass, "pii_values_leaked": len(leaked), "exact_row_match_rate": round(exact, 4),
                    "dcr_ratio_median": dcr_ratio, "pii_columns": pii_cols},
        "formula": "fidelity = 100*(0.4*mean(1-KS) + 0.3*mean(1-TVD) + 0.3*(1-mean|corr_real-corr_synth|)); capped at 50 if privacy fails",
    }


def write_csv(rows: list[dict], path: Path) -> None:
    with Path(path).open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("input", type=Path)
    ap.add_argument("--rows", type=int, default=1000)
    ap.add_argument("--out", type=Path, default=Path("synthetic.csv"))
    ap.add_argument("--model-out", type=Path, default=Path("model.json"))
    ap.add_argument("--epsilon", type=float)
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args(argv)
    real = load_dataset(a.input)
    model = fit(real, epsilon=a.epsilon, seed=a.seed)
    synth = sample(model, a.rows, a.seed)
    a.model_out.write_text(json.dumps(model, indent=2))
    write_csv(synth, a.out)
    rep = validate(real, synth, model)
    print(json.dumps({"validation_score": rep["validation_score"], "privacy": rep["privacy"], "components": rep["components"]}, indent=2))
    return 0 if rep["privacy"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
