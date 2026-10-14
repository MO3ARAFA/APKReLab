"""Extract pricing / performance / missing-feature pain from 1-2 star reviews and rank build opportunities."""
from __future__ import annotations

import csv
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

CATEGORIES: dict[str, list[str]] = {
    "pricing": [r"expensive", r"overpriced", r"pric(?:e|ing|ey)", r"\bcosts?\b", r"per seat", r"hidden fee", r"paywall", r"\bbill(?:ed|ing)\b",
                r"charg(?:e|ed|es)", r"renewal", r"subscription", r"upgrade to", r"cheap(?:er)?\b", r"refund"],
    "performance": [r"\bslow", r"\blag(?:gy|s|ging)?\b", r"freez(?:e|es|ing)", r"crash(?:es|ed)?", r"time[sd]? out", r"sluggish",
                    r"loading", r"takes? \d+ seconds", r"bloated", r"hangs?"],
    "missing_feature": [r"\bwish\b", r"\blacks?\b", r"\bmissing\b", r"no way to", r"doesn'?t support", r"can'?t\b", r"cannot", r"\bneeds? (?:a|an)\b",
                        r"no (?:api|offline|export|mobile|integration)", r"doesn'?t have"],
    "support": [r"\bsupport\b", r"customer service", r"never replied", r"no response", r"\bticket\b", r"ignored"],
    "usability": [r"confusing", r"clunky", r"complicated", r"hard to", r"unintuitive"],
    "reliability": [r"\bbugg?y\b", r"\bbugs?\b", r"broken", r"data loss", r"lost\b", r"sync (?:error|keeps breaking)", r"drops? columns"],
}
SEVERITY_BY_RATING = {1: 2.0, 2: 1.0}
FEATURE_PATTERNS = [
    r"wish (?:it|they) (?:had|would have|could have|offered) (?:an? |the )?(.{3,50}?)(?:[.,;!?]|$| but | and | too)",
    r"\black(?:s|ing) (?:an? |the )?(.{3,50}?)(?:[.,;!?]|$| but | and | too)",
    r"\bmissing (?:an? |the )?(.{3,50}?)(?:[.,;!?]|$| but | and | too)",
    r"no way to (.{3,50}?)(?:[.,;!?]|$| but | and | too)",
    r"doesn'?t (?:support|have|offer) (?:an? |the )?(.{3,50}?)(?:[.,;!?]|$| but | and | too)",
    r"\bneeds? (?:an? |the )(.{3,50}?)(?:[.,;!?]|$| but | and | too)",
    r"\bno ((?:api|offline|mobile|export|integration|autosave)[^.,;!?]{0,40}?)(?:[.,;!?]|$| but | and | too)",
    r"can'?t (.{3,40}?)(?:[.,;!?]|$| but | and | too)",
]
STOP = {"a", "an", "the", "to", "of", "for", "my", "on", "in", "and", "with", "too", "it", "is"}
PRICE_RE = re.compile(r"\$\s?(\d{1,5})(?:\s?(?:/|per)\s?(month|mo|seat|year|yr))?", re.I)


@dataclass
class Review:
    rating: int
    text: str
    id: str = ""


def load_reviews(path: Path) -> list[Review]:
    path = Path(path)
    if path.suffix == ".json":
        rows = json.loads(path.read_text())
    elif path.suffix == ".csv":
        with path.open(newline="") as fh:
            rows = list(csv.DictReader(fh))
    else:
        raise ValueError(f"unsupported review file type: {path.suffix}")
    out = []
    for i, r in enumerate(rows):
        try:
            rating = int(float(r.get("rating", r.get("stars", 0))))
        except (TypeError, ValueError):
            continue
        text = str(r.get("text") or r.get("review") or r.get("body") or "").strip()
        if text:
            out.append(Review(rating, text, str(r.get("id", i))))
    return out


def sentences(text: str) -> list[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s.strip()]


def classify(sentence: str) -> list[str]:
    s = sentence.lower()
    return [cat for cat, pats in CATEGORIES.items() if any(re.search(p, s) for p in pats)]


def normalize_phrase(p: str) -> str:
    toks = [t for t in re.findall(r"[a-z0-9']+", p.lower()) if t not in STOP]
    return " ".join(toks[:6])


def extract_features(text: str) -> list[str]:
    found = []
    for s in sentences(text):
        for pat in FEATURE_PATTERNS:
            for m in re.finditer(pat, s, re.I):
                ph = normalize_phrase(m.group(1))
                if len(ph) >= 3:
                    found.append(ph)
    return found


def _jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if a | b else 0.0


def cluster_phrases(counter: Counter) -> list[tuple[str, int, list[str]]]:
    """Greedy token-overlap clustering so 'offline mode' and 'an offline access' merge."""
    clusters: list[dict] = []
    for ph, n in counter.most_common():
        toks = set(ph.split())
        for c in clusters:
            if _jaccard(toks, c["tokens"]) >= 0.34 or (toks & c["tokens"] and {"offline", "mobile", "api", "export", "webhook", "browser"} & toks & c["tokens"]):
                c["count"] += n
                c["variants"].append(ph)
                c["tokens"] |= toks
                break
        else:
            clusters.append({"label": ph, "count": n, "variants": [ph], "tokens": set(toks)})
    return sorted(((c["label"], c["count"], c["variants"]) for c in clusters), key=lambda x: -x[1])


def analyze(reviews: list[Review]) -> dict:
    low = [r for r in reviews if r.rating <= 2]
    cat_weight: Counter = Counter()
    cat_mentions: Counter = Counter()
    cat_quotes: dict[str, list[str]] = defaultdict(list)
    feat_counter: Counter = Counter()
    prices: list[int] = []
    for r in low:
        w = SEVERITY_BY_RATING.get(r.rating, 1.0)
        seen = set()
        for s in sentences(r.text):
            for cat in classify(s):
                cat_weight[cat] += w
                if cat not in seen:
                    cat_mentions[cat] += 1
                    seen.add(cat)
                if len(cat_quotes[cat]) < 3 and s not in cat_quotes[cat]:
                    cat_quotes[cat].append(s)
        for ph in set(extract_features(r.text)):
            feat_counter[ph] += w
        for m in PRICE_RE.finditer(r.text):
            prices.append(int(m.group(1)))
    features = cluster_phrases(feat_counter)
    total = max(1, len(low))
    opportunities = [
        {"rank": i + 1, "feature": label, "weighted_mentions": round(n, 1), "variants": v[:4],
         "share_of_low_reviews": round(min(1.0, n / (2 * total)), 3)}
        for i, (label, n, v) in enumerate(features[:10])
    ]
    return {
        "reviews_total": len(reviews), "reviews_analyzed": len(low),
        "categories": {c: {"reviews_mentioning": cat_mentions[c], "weighted_score": round(cat_weight[c], 1),
                           "share": round(cat_mentions[c] / total, 3), "example_quotes": cat_quotes[c]}
                       for c, _ in cat_weight.most_common()},
        "pricing": {"price_points_mentioned": sorted(prices),
                    "median_price": sorted(prices)[len(prices) // 2] if prices else None},
        "missing_feature_opportunities": opportunities,
        "top_pain": cat_weight.most_common(1)[0][0] if cat_weight else None,
    }


def brief_markdown(report: dict, product: str, pitch: str) -> str:
    lines = [f"# Gap Analysis: {product}", "", f"Analyzed **{report['reviews_analyzed']}** low-star reviews "
             f"(of {report['reviews_total']}).", "", pitch, "", "## Pain by category", "",
             "| Category | Reviews | Share | Weighted |", "|---|---|---|---|"]
    for c, d in report["categories"].items():
        lines.append(f"| {c} | {d['reviews_mentioning']} | {d['share']:.0%} | {d['weighted_score']} |")
    p = report["pricing"]
    if p["price_points_mentioned"]:
        lines += ["", f"Price points users complain about: {p['price_points_mentioned']} (median ${p['median_price']})."]
    lines += ["", "## Build priorities (missing features, ranked)", ""]
    for o in report["missing_feature_opportunities"]:
        lines.append(f"{o['rank']}. **{o['feature']}** - {o['weighted_mentions']} weighted mentions (variants: {', '.join(o['variants'])})")
    lines += ["", "## Evidence", ""]
    for c, d in report["categories"].items():
        for q in d["example_quotes"][:2]:
            lines.append(f"- *{c}*: \"{q}\"")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("reviews", type=Path)
    ap.add_argument("--out", type=Path, default=Path("pain_report.json"))
    a = ap.parse_args(argv)
    rep = analyze(load_reviews(a.reviews))
    a.out.write_text(json.dumps(rep, indent=2))
    print(json.dumps(rep["categories"], indent=2)[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
