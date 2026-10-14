import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE.parents[1]))

from projects.prj_04_zeroday_hunter import auto_patcher as ap  # noqa: E402

SAMPLE = (HERE / "sample_app" / "app.py").read_text()


@pytest.fixture(scope="module")
def result():
    return ap.generate_patch(SAMPLE, "app.py")


def rules(res):
    return [(f.rule, f.function) for f in res["findings"]]


def test_expected_findings(result):
    r = rules(result)
    for item in [("idor", "get_order"), ("missing-authentication", "get_order"), ("sql-injection", "search_users"),
                 ("sql-injection", "get_user"), ("missing-authorization", "delete_user"), ("command-injection", "ping"),
                 ("business-logic", "checkout"), ("mass-assignment", "register"), ("path-traversal", "download"),
                 ("open-redirect", "go")]:
        assert item in r, item


def test_no_false_positives_on_safe_routes(result):
    flagged = {f.function for f in result["findings"]}
    assert "health" not in flagged and "get_my_order" not in flagged  # has login_required + ownership check


def test_no_duplicate_findings(result):
    keys = [(f.rule, f.function, f.line) for f in result["findings"]]
    assert len(keys) == len(set(keys))


def test_graph_connects_source_to_sink(result):
    g = result["graph"]
    kinds = {n["id"]: n["kind"] for n in g.nodes.values()}
    sinks = [n for n, k in kinds.items() if k == "sink"]
    assert sinks and all(any(e["to"] == s for e in g.edges) for s in sinks)
    assert "digraph" in g.to_dot()


def test_patch_applies_with_git(result):
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "app.py").write_text(result["normalized"])
        (Path(td) / "p.diff").write_text(result["diff"])
        subprocess.run(["git", "init", "-q"], cwd=td, check=True)
        subprocess.run(["git", "apply", "p.diff"], cwd=td, check=True)
        assert (Path(td) / "app.py").read_text() == result["patched"]


def test_patch_is_idempotent(result):
    again = ap.generate_patch(result["patched"], "app.py")
    assert again["diff"] == ""
    assert not [f for f in again["findings"] if f.fixable]


def test_manual_findings_not_patched(result):
    assert {f.rule for f in result["skipped"]} >= {"business-logic", "mass-assignment", "path-traversal"}
    assert "price" in result["patched"]  # untouched, only reported


def test_idor_uses_model_owner_field():
    src = ("from flask import Flask\napp = Flask(__name__)\n"
           "class Doc(db.Model):\n    id = db.Column(db.Integer)\n    owner_id = db.Column(db.Integer)\n"
           "@app.route('/docs/<int:doc_id>')\n@login_required\ndef doc(doc_id):\n    d = Doc.query.get(doc_id)\n    return d.title\n")
    res = ap.generate_patch(src)
    assert "d.owner_id != current_user.id" in res["patched"]


def _run_find(src, payload):
    ns = {}
    exec(compile(src, "x", "exec"), ns)
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER, name TEXT)")
    db.executemany("INSERT INTO users VALUES (?, ?)", [(1, "alice"), (2, "bob")])
    return ns["find"](db, payload)


@pytest.mark.parametrize("body", [
    'return db.execute(f"SELECT name FROM users WHERE name = \'{name}\'").fetchall()',
    'return db.execute("SELECT name FROM users WHERE name = \'" + name + "\'").fetchall()',
    'return db.execute("SELECT name FROM users WHERE name = \'%s\'" % name).fetchall()',
    'return db.execute("SELECT name FROM users WHERE name = \'{}\'".format(name)).fetchall()',
])
def test_sqli_variants_neutralised(body):
    src = f"def find(db, name):\n    {body}\n"
    res = ap.generate_patch(src)
    assert len(_run_find(res["normalized"], "' OR '1'='1")) == 2  # vulnerable before
    assert _run_find(res["patched"], "' OR '1'='1") == []         # safe after
    assert _run_find(res["patched"], "alice") == [("alice",)]     # behavior preserved


def test_identifier_interpolation_not_blindly_patched():
    src = "def find(db, table):\n    return db.execute(f'SELECT * FROM {table}').fetchall()\n"
    res = ap.generate_patch(src)
    assert res["diff"] == "" or "?" not in res["patched"]


def test_sqlalchemy_text_uses_named_binds():
    src = ("def find(session, name):\n    return session.execute(text(f\"SELECT * FROM u WHERE n = '{name}'\"))\n")
    res = ap.generate_patch(src)
    assert ":p0" in res["patched"] and "{'p0': name}" in res["patched"]


def test_psycopg_style_placeholder():
    src = "import psycopg2\ndef find(cur, name):\n    cur.execute(f\"SELECT * FROM u WHERE n = '{name}'\")\n"
    assert "%s" in ap.generate_patch(src)["patched"]


def test_command_injection_to_argv():
    src = "import os\nfrom flask import request\ndef ping():\n    host = request.args['h']\n    os.system(f'ping -c 1 {host}')\n"
    res = ap.generate_patch(src)
    assert "subprocess.run(['ping', '-c', '1', str(host)], check=False)" in res["patched"]
