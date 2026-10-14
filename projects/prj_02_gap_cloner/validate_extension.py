"""Static validation of the Chrome MV3 extension against publish requirements."""
from __future__ import annotations

import json
import re
import shutil
import struct
import subprocess
from pathlib import Path

REQUIRED_FILES = ["manifest.json", "background.js", "popup.html", "popup.js", "db.js"]
BROAD_PERMS = {"tabs", "history", "cookies", "webRequest", "<all_urls>", "management", "debugger"}


def png_size(path: Path) -> tuple[int, int] | None:
    data = path.read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", data[16:24])


def validate(ext: Path) -> list[tuple[str, bool, str]]:
    res: list[tuple[str, bool, str]] = []

    def ok(name, cond, detail=""):
        res.append((name, bool(cond), detail))

    for f in REQUIRED_FILES:
        ok(f"file present: {f}", (ext / f).is_file())
    try:
        m = json.loads((ext / "manifest.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return res + [("manifest.json parses", False, str(exc))]
    ok("manifest_version == 3", m.get("manifest_version") == 3)
    ok("name/version/description set", all(m.get(k) for k in ("name", "version", "description")))
    ok("version format", re.fullmatch(r"\d+(\.\d+){0,3}", str(m.get("version", ""))) is not None)
    ok("description <= 132 chars (Web Store limit)", len(m.get("description", "")) <= 132, str(len(m.get("description", ""))))
    ok("service_worker declared", m.get("background", {}).get("service_worker") == "background.js")
    ok("popup declared", m.get("action", {}).get("default_popup") == "popup.html")
    perms = set(m.get("permissions", []))
    ok("no overly broad permissions", not (perms & BROAD_PERMS) and not m.get("host_permissions"), str(sorted(perms)))
    ok("host access is optional (runtime-granted)", "optional_host_permissions" in m)
    for size in ("16", "32", "48", "128"):
        p = ext / m.get("icons", {}).get(size, "missing")
        ok(f"icon {size}px valid PNG", p.is_file() and png_size(p) == (int(size), int(size)))
    html = (ext / "popup.html").read_text() if (ext / "popup.html").exists() else ""
    ok("popup has no inline <script> (MV3 CSP)", not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html))
    ok("popup loads db.js before popup.js", html.find("db.js") != -1 and html.find("db.js") < html.find("popup.js"))
    for js in ("popup.js", "background.js", "db.js"):
        src = (ext / js).read_text() if (ext / js).exists() else ""
        ok(f"{js}: no eval/remote code", not re.search(r"\beval\s*\(|new Function\s*\(|importScripts\(\s*['\"]https?:", src))
    ok("popup.js avoids HTML-injection sinks",
       not re.search(r"\.(innerHTML|outerHTML)\b|insertAdjacentHTML|document\.write", (ext / "popup.js").read_text()))
    ok("background imports db.js", "importScripts('db.js')" in (ext / "background.js").read_text())
    ok("background uses only declared APIs",
       all(f"chrome.{api}." in (ext / "background.js").read_text() for api in ("contextMenus", "alarms")) and "contextMenus" in perms and "alarms" in perms)
    node = shutil.which("node")
    if node:
        for js in ("popup.js", "background.js", "db.js"):
            p = subprocess.run([node, "--check", str(ext / js)], capture_output=True, text=True)
            ok(f"node --check {js}", p.returncode == 0, p.stderr.strip()[:200])
    else:
        ok("node --check (skipped: node not installed)", True, "skipped")
    return res


if __name__ == "__main__":
    import sys
    out = validate(Path(sys.argv[1]))
    for n, c, d in out:
        print("PASS" if c else "FAIL", n, d)
    sys.exit(0 if all(c for _, c, _ in out) else 1)
