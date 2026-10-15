"""Prospect pool, targets.csv I/O and validation shared by the AI CEO, PM-03 and the web UI.

Truthfulness rules:
  * a leader's name is stored as a greeting only when `greeting_verified` is true AND a source URL is recorded;
    everything else greets with the neutral "there";
  * prospects suggested by an LLM are treated as unverified leads: URL shape is validated, private/IP hosts are rejected,
    they are fetched before use, and they always greet with "there".
"""
from __future__ import annotations

import csv
import ipaddress
import json
import os
import re
import urllib.parse
from pathlib import Path

POOL_PATH = Path(__file__).with_name("prospect_pool.json")
MAX_TARGETS = 200
_FORMULA = re.compile(r"^[=+\-@\t\r]")
_BAD_SUFFIX = (".local", ".internal", ".localhost", ".lan", ".home", ".corp")


def norm_url(u: str) -> str:
    return u.strip().lower().rstrip("/")


def clean_row(url: str, ceo: str = "there", company: str = "") -> dict:
    """Validate and normalise one target. Raises ValueError with a user-facing message."""
    url = url.strip()
    if url and "://" not in url:
        url = "https://" + url
    p = urllib.parse.urlparse(url)
    if p.scheme not in {"http", "https"} or not p.hostname or "." not in p.hostname:
        raise ValueError("url must be a public http(s) address, e.g. https://example.com")
    if p.username or p.password:
        raise ValueError("credentials in URLs are not allowed")
    if len(url) > 300:
        raise ValueError("url too long")
    ceo = " ".join(ceo.split()) or "there"
    company = " ".join(company.split())
    for name, v, limit in (("ceo", ceo, 60), ("company", company, 80)):
        if len(v) > limit:
            raise ValueError(f"{name} too long (max {limit})")
        if _FORMULA.match(v):
            raise ValueError(f"{name} must not start with = + - @ (spreadsheet formula injection)")
    return {"url": url, "ceo": ceo, "company": company}


def read_targets(path: Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return [{"url": (r.get("url") or "").strip(), "ceo": (r.get("ceo") or "there").strip(),
                 "company": (r.get("company") or "").strip()} for r in csv.DictReader(fh) if (r.get("url") or "").strip()]


def write_targets(path: Path, rows: list[dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["url", "ceo", "company"])
        for r in rows:
            w.writerow([r["url"], r["ceo"], r["company"]])
    os.replace(tmp, path)


def load_pool(path: Path = POOL_PATH) -> list[dict]:
    pool = json.loads(Path(path).read_text())
    for p in pool:  # fail loudly if the data ever violates the truthfulness rule
        if p["greeting_verified"] and not p.get("greeting_source"):
            raise ValueError(f"{p['company']}: verified greeting needs a source")
        if not p["greeting_verified"] and p["greeting"] != "there":
            raise ValueError(f"{p['company']}: unverified greeting must be 'there'")
    return pool


def row_from_pool(p: dict) -> dict:
    return {"url": p["url"], "ceo": p["greeting"] if p["greeting_verified"] else "there", "company": p["company"]}


def select_next(pool: list[dict], audited: set[str], n: int, exclude: set[str] = frozenset()) -> list[dict]:
    """The first n pool entries (pool order = priority) that have not been audited."""
    return [p for p in pool if norm_url(p["url"]) not in audited and norm_url(p["url"]) not in exclude][:n]


def pool_status(pool: list[dict], audited: set[str]) -> dict:
    done = sum(1 for p in pool if norm_url(p["url"]) in audited)
    return {"pool": len(pool), "audited_in_pool": done, "remaining": len(pool) - done}


def _public_host(host: str) -> bool:
    host = host.lower()
    try:
        ipaddress.ip_address(host)
        return False  # IP literals are never prospects
    except ValueError:
        pass
    return host != "localhost" and not host.endswith(_BAD_SUFFIX)


def parse_discovered(text: str, exclude: set[str], limit: int) -> list[dict]:
    """Validate an LLM's prospect suggestions (JSON array of {company,url}). Anything doubtful is dropped."""
    m = re.search(r"\[.*\]", text, re.S)
    if not m:
        return []
    try:
        items = json.loads(m.group(0))
    except json.JSONDecodeError:
        return []
    out, seen = [], set(exclude)
    for it in items if isinstance(items, list) else []:
        if not isinstance(it, dict) or not isinstance(it.get("url"), str):
            continue
        try:
            row = clean_row(it["url"], "there", str(it.get("company") or "")[:80])
        except ValueError:
            continue
        host = urllib.parse.urlparse(row["url"]).hostname or ""
        if not row["url"].startswith("https://") or not _public_host(host) or norm_url(row["url"]) in seen:
            continue
        seen.add(norm_url(row["url"]))
        out.append(row)
        if len(out) >= limit:
            break
    return out
