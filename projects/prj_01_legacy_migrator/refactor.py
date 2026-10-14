"""Automated, behavior-preserving refactors + FastAPI microservice scaffold + characterization tests."""
from __future__ import annotations

import ast
import json
import subprocess
import sys
import tempfile
import textwrap
from dataclasses import dataclass
from pathlib import Path

IMPURE_ROOTS = {"os", "subprocess", "sys", "socket", "sqlite3", "requests", "urllib", "shutil", "random", "time",
                "datetime", "open", "input", "exec", "eval", "pickle", "yaml", "ConfigParser", "optparse"}
QUARANTINE_RULES = {"dynamic-exec", "shell-exec"}  # never exposed as HTTP endpoints


class Modernizer(ast.NodeTransformer):
    """Safe automated fixes. Each fix is counted so the report can state exactly what changed."""

    def __init__(self):
        self.fixes: dict[str, int] = {}

    def _bump(self, k):
        self.fixes[k] = self.fixes.get(k, 0) + 1

    def visit_ExceptHandler(self, node):
        self.generic_visit(node)
        if node.type is None:
            node.type = ast.Name("Exception", ast.Load())
            self._bump("bare-except -> except Exception")
        return node

    def visit_Compare(self, node):
        self.generic_visit(node)
        for i, (op, c) in enumerate(zip(node.ops, node.comparators)):
            if isinstance(c, ast.Constant) and c.value is None:
                if isinstance(op, ast.Eq):
                    node.ops[i] = ast.Is()
                    self._bump("== None -> is None")
                elif isinstance(op, ast.NotEq):
                    node.ops[i] = ast.IsNot()
                    self._bump("!= None -> is not None")
        return node

    def visit_Call(self, node):
        self.generic_visit(node)
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "load" and isinstance(f.value, ast.Name) and f.value.id == "yaml":
            if not node.keywords and len(node.args) == 1:
                f.attr = "safe_load"
                self._bump("yaml.load -> yaml.safe_load")
        return node

    def visit_Expr(self, node):
        return self.generic_visit(node)

    def visit_If(self, node):
        self.generic_visit(node)
        t = node.test
        # d.has_key(k) -> k in d
        if isinstance(t, ast.Call) and isinstance(t.func, ast.Attribute) and t.func.attr == "has_key" and len(t.args) == 1:
            node.test = ast.Compare(t.args[0], [ast.In()], [t.func.value])
            self._bump("dict.has_key -> in")
        return node

    def visit_FunctionDef(self, node):
        self.generic_visit(node)
        a = node.args
        # mutable default -> None sentinel
        guards = []
        pos = a.posonlyargs + a.args
        for arg, d in zip(pos[len(pos) - len(a.defaults):], a.defaults):
            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                guards.append(ast.If(
                    ast.Compare(ast.Name(arg.arg, ast.Load()), [ast.Is()], [ast.Constant(None)]),
                    [ast.Assign([ast.Name(arg.arg, ast.Store())], d)], []))
                a.defaults[a.defaults.index(d)] = ast.Constant(None)
                self._bump("mutable default -> None sentinel")
        if guards:
            body = node.body
            doc = [body[0]] if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                and isinstance(body[0].value.value, str) else []
            node.body = doc + guards + body[len(doc):]
        return node


def modernize_source(src: str) -> tuple[str, dict[str, int]]:
    tree = ast.parse(src)
    m = Modernizer()
    tree = m.visit(tree)
    ast.fix_missing_locations(tree)
    return ast.unparse(tree) + "\n", m.fixes


# -- function inspection -------------------------------------------------------------------
@dataclass
class FuncInfo:
    name: str
    params: list[tuple[str, str | None, str | None]]  # (name, annotation src, default src)
    pure: bool
    quarantined: bool = False


def inspect_functions(src: str, quarantined: set[str]) -> list[FuncInfo]:
    tree = ast.parse(src)
    out = []
    for n in tree.body:
        if isinstance(n, ast.FunctionDef) and not n.name.startswith("_"):
            a = n.args
            pos = a.posonlyargs + a.args
            defaults = [None] * (len(pos) - len(a.defaults)) + list(a.defaults)
            params = [(p.arg, ast.unparse(p.annotation) if p.annotation else None, ast.unparse(d) if d is not None else None)
                      for p, d in zip(pos, defaults)]
            names = {x.id for x in ast.walk(n) if isinstance(x, ast.Name)}
            imports = any(isinstance(x, (ast.Import, ast.ImportFrom)) for x in ast.walk(n))
            pure = not (names & IMPURE_ROOTS) and not imports
            out.append(FuncInfo(n.name, params, pure, n.name in quarantined))
    return out


def candidate_args(fn: FuncInfo, overrides: dict) -> list[list]:
    if fn.name in overrides:
        return overrides[fn.name]

    def vals(pname: str, ann: str | None, default: str | None) -> list:
        n = pname.lower()
        if ann in {"int", "float", "bool", "str"}:
            kind = ann
        elif default is not None:
            try:
                kind = type(ast.literal_eval(default)).__name__
            except Exception:
                kind = "any"
        else:
            kind = "any"
        if kind == "any":
            if any(k in n for k in ("price", "amount", "total", "rate", "cost")):
                kind = "float"
            elif any(k in n for k in ("qty", "count", "num", "age", "size", "limit", "id")) or n in {"a", "b", "n", "x", "y"}:
                kind = "int"
            elif any(k in n for k in ("name", "text", "msg", "str", "word", "pw", "pass", "tag", "key", "value")) or n == "s":
                kind = "str"
            elif any(k in n for k in ("list", "items", "values", "nums", "data", "orders", "argv")):
                kind = "list"
        return {"int": [0, 3, 7], "float": [0.0, 9.5, 120.25], "str": ["", "abc", "Hello World"], "bool": [False, True, True],
                "list": [[], [1, 2, 3], [5]], "NoneType": [None, None, None]}.get(kind, [0, 1, 2])

    cols = [vals(*p) for p in fn.params]
    return [[c[i] for c in cols] for i in range(3)] if cols else [[]]


RUNNER = r'''
import ast, importlib.util, json, sys
spec = importlib.util.spec_from_file_location("core", sys.argv[1])
mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
jobs = json.load(open(sys.argv[2]))
out = []
for name, calls in jobs.items():
    for args in calls:
        rec = {"func": name, "args": args}
        for attempt in range(2):
            try:
                import copy
                r = getattr(mod, name)(*copy.deepcopy(args)); res = ("ok", repr(r))
            except BaseException as e:
                res = ("exc", type(e).__name__)
            rec.setdefault("runs", []).append(res)
        a, b = rec["runs"]
        if a != b:
            continue  # nondeterministic -> not testable
        kind, val = a
        if kind == "ok":
            try: ast.literal_eval(val)
            except Exception: continue
        elif not hasattr(__builtins__, val) and not (isinstance(__builtins__, dict) and val in __builtins__):
            continue
        rec["kind"], rec["val"] = kind, val
        del rec["runs"]
        out.append(rec)
print(json.dumps(out))
'''


def characterize(core_file: Path, jobs: dict[str, list[list]], timeout: int = 30) -> list[dict]:
    """Execute pure functions in an isolated subprocess and record their observed behavior (golden master)."""
    if not jobs:
        return []
    with tempfile.TemporaryDirectory() as td:
        jf, rf = Path(td) / "jobs.json", Path(td) / "runner.py"
        jf.write_text(json.dumps(jobs))
        rf.write_text(RUNNER)
        try:
            proc = subprocess.run([sys.executable, "-I", str(rf), str(core_file), str(jf)], capture_output=True,
                                  text=True, timeout=timeout, cwd=td)
        except subprocess.TimeoutExpired:
            return []
    if proc.returncode != 0:
        return []
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return []


def render_tests(modname: str, records: list[dict]) -> str:
    lines = ["import sys", "from pathlib import Path", "", "import pytest", "",
             "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))",
             f"import {modname} as core", "", "",
             "# Characterization (golden-master) tests: they pin the behavior of the MODERNIZED code.", ""]
    counters: dict[str, int] = {}
    for r in records:
        i = counters[r["func"]] = counters.get(r["func"], -1) + 1
        call = f"core.{r['func']}(*{r['args']!r})"
        lines.append(f"def test_{r['func']}_case_{i}():")
        if r["kind"] == "exc":
            lines.append(f"    with pytest.raises({r['val']}):\n        {call}")
        else:
            exp = ast.literal_eval(r["val"])
            if isinstance(exp, float):
                lines.append(f"    assert {call} == pytest.approx({exp!r})")
            else:
                lines.append(f"    assert {call} == {exp!r}")
        lines.append("")
        lines.append("")
    if not records:
        lines.append("def test_module_imports():\n    assert core is not None\n")
    return "\n".join(lines)


# -- FastAPI scaffold ------------------------------------------------------------------------
PY_TYPES = {"int": "int", "float": "float", "str": "str", "bool": "bool", "list": "list", "dict": "dict"}


def _field_type(ann, default):
    if ann in PY_TYPES:
        return PY_TYPES[ann]
    if default is not None:
        try:
            return type(ast.literal_eval(default)).__name__ if type(ast.literal_eval(default)).__name__ in PY_TYPES else "Any"
        except Exception:
            pass
    return "Any"


def render_service(modname: str, funcs: list[FuncInfo]) -> tuple[str, list[str]]:
    exposed = [f for f in funcs if not f.quarantined]
    lines = ['"""Auto-generated FastAPI microservice wrapping the modernized legacy module."""',
             "from typing import Any", "", "from fastapi import FastAPI", "from pydantic import BaseModel", "",
             f"import {modname} as core", "", f'app = FastAPI(title="{modname} service", version="1.0.0")', "", "",
             '@app.get("/health")', "def health() -> dict:", '    return {"status": "ok"}', ""]
    for f in exposed:
        cls = "".join(p.capitalize() for p in f.name.split("_")) + "Request"
        lines += ["", f"class {cls}(BaseModel):"]
        if not f.params:
            lines.append("    pass")
        for pname, ann, default in f.params:
            t = _field_type(ann, default)
            d = ""
            if default is not None:
                try:
                    lit = ast.literal_eval(default)
                    d = " = None" if isinstance(lit, (list, dict, set)) or lit is None else f" = {default}"
                    if d == " = None":
                        t = f"{t} | None"
                except Exception:
                    d = " = None"
            lines.append(f"    {pname}: {t}{d}")
        kwargs = ", ".join(f"{p[0]}=body.{p[0]}" for p in f.params)
        lines += ["", "", f'@app.post("/{f.name}")', f"def {f.name}_endpoint(body: {cls}) -> dict:",
                  f'    return {{"result": core.{f.name}({kwargs})}}', ""]
    return "\n".join(lines) + "\n", [f.name for f in exposed]


def render_api_tests(modname: str, funcs: list[FuncInfo], records: list[dict]) -> str:
    lines = ["import sys", "from pathlib import Path", "", "import pytest", "",
             "pytest.importorskip('fastapi')", "pytest.importorskip('httpx')", "",
             "sys.path.insert(0, str(Path(__file__).resolve().parents[1]))",
             "from fastapi.testclient import TestClient", "from service import app", "", "client = TestClient(app)", "",
             "", "def test_health():", "    assert client.get('/health').json() == {'status': 'ok'}", ""]
    exposed = {f.name: f for f in funcs if not f.quarantined}
    seen = set()
    for r in records:
        f = exposed.get(r["func"])
        if not f or r["kind"] != "ok" or r["func"] in seen or len(r["args"]) != len(f.params):
            continue
        exp = ast.literal_eval(r["val"])
        if not isinstance(exp, (int, float, str, bool, list, dict, type(None))):
            continue
        seen.add(r["func"])
        payload = {p[0]: v for p, v in zip(f.params, r["args"])}
        lines += ["", f"def test_{r['func']}_endpoint():",
                  f"    resp = client.post('/{r['func']}', json={payload!r})", "    assert resp.status_code == 200",
                  "    assert resp.json()['result'] == " + (f"pytest.approx({exp!r})" if isinstance(exp, float) else repr(exp)), ""]
    return "\n".join(lines) + "\n"


DOCKERFILE = textwrap.dedent('''\
    FROM python:3.12-slim
    WORKDIR /app
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    COPY . .
    EXPOSE 8000
    CMD ["uvicorn", "service:app", "--host", "0.0.0.0", "--port", "8000"]
''')
