"""Helpers shared by project pipelines."""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path


def check(name: str, passed: bool, detail: str = "") -> dict:
    return {"name": name, "passed": bool(passed), "detail": detail}


def run_pytest(test_path: Path, cwd: Path, timeout: int = 180) -> tuple[int, int, str]:
    """Run pytest in a subprocess and read results from JUnit XML (immune to -q/-v config and output format).

    Returns (passed, total_run, tail_of_output). Skipped tests count in neither number.
    A crash before any result is written yields (0, 0, output) which callers treat as failure.
    """
    with tempfile.TemporaryDirectory() as td:
        xml_path = Path(td) / "junit.xml"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", str(test_path), "-p", "no:cacheprovider", "-o", "addopts=",
             f"--junitxml={xml_path}"],
            cwd=cwd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout + proc.stderr
        tail = "\n".join(out.strip().splitlines()[-8:])
        try:
            root = ET.parse(xml_path).getroot()
        except (ET.ParseError, FileNotFoundError):
            if re.search(r"No module named ['\"]?pytest", out):
                return 0, 0, "pytest is not installed - run: pip install pytest"
            return 0, 0, tail
        suite = root if root.tag == "testsuite" else root.find("testsuite")
        tests, fails = int(suite.get("tests", 0)), int(suite.get("failures", 0)) + int(suite.get("errors", 0))
        skipped = int(suite.get("skipped", 0))
        total = tests - skipped
        return total - fails, total, tail
