"""Self-healing security scanner: builds a data-flow graph, finds injection / IDOR / auth / business-logic flaws
and emits a `git apply`-able unified diff that fixes the ones that can be fixed safely.

Scope & honesty: intra-procedural taint analysis for Flask-style Python. Findings the tool cannot fix safely are
reported as `fixable: false` with a manual fix hint instead of being "patched" with guesses.
"""
from __future__ import annotations

import ast
import difflib
import re
from dataclasses import asdict, dataclass, field

AUTH_DECORATORS = {"login_required", "jwt_required", "auth_required", "require_auth", "admin_required", "roles_required",
                   "permission_required", "fresh_login_required", "token_required"}
PUBLIC_ROUTES = {"/", "/health", "/login", "/register", "/signup", "/logout", "/healthz", "/ping_public"}
SENSITIVE_FIELD = re.compile(r"(price|amount|total|discount|cost|balance|credit|role|is_admin|admin|fee)", re.I)
OWNER_FIELDS = ("user_id", "owner_id", "customer_id", "account_id", "created_by")
CURRENT_USER_NAMES = {"current_user", "session", "g"}
CWE = {"sql-injection": "CWE-89", "command-injection": "CWE-78", "idor": "CWE-639", "missing-authentication": "CWE-306",
       "missing-authorization": "CWE-862", "mass-assignment": "CWE-915", "business-logic": "CWE-840",
       "path-traversal": "CWE-22", "open-redirect": "CWE-601", "code-injection": "CWE-95"}


@dataclass
class Finding:
    rule: str
    severity: str
    line: int
    function: str
    message: str
    fixable: bool
    fix_hint: str
    path: list[str] = field(default_factory=list)
    node_key: tuple = ()

    def to_dict(self):
        d = asdict(self)
        d["cwe"] = CWE.get(self.rule, "")
        d.pop("node_key")
        return d


def dotted(n: ast.AST) -> str:
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
    return ".".join(reversed(parts))


def normalize(src: str) -> str:
    return ast.unparse(ast.parse(src)) + "\n"


def route_info(fn: ast.FunctionDef) -> tuple[str | None, list[str]]:
    for d in fn.decorator_list:
        if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "route" and d.args \
                and isinstance(d.args[0], ast.Constant):
            methods = []
            for k in d.keywords:
                if k.arg == "methods" and isinstance(k.value, (ast.List, ast.Tuple)):
                    methods = [e.value for e in k.value.elts if isinstance(e, ast.Constant)]
            return d.args[0].value, methods or ["GET"]
    return None, []


def path_params(path: str) -> list[str]:
    return re.findall(r"<(?:\w+:)?(\w+)>", path or "")


def is_request_source(n: ast.AST) -> bool:
    return dotted(n.func if isinstance(n, ast.Call) else n).split(".")[0] == "request" and \
        dotted(n.func if isinstance(n, ast.Call) else n).count(".") >= 1


class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []

    def node(self, nid: str, kind: str, label: str, line: int, fn: str):
        self.nodes.setdefault(nid, {"id": nid, "kind": kind, "label": label, "line": line, "function": fn})
        return nid

    def edge(self, a: str, b: str, kind: str = "flows"):
        e = {"from": a, "to": b, "kind": kind}
        if e not in self.edges:
            self.edges.append(e)

    def to_dict(self):
        return {"nodes": list(self.nodes.values()), "edges": self.edges}

    def to_dot(self) -> str:
        color = {"source": "lightcoral", "var": "lightyellow", "sink": "lightblue", "guard": "palegreen"}
        out = ["digraph dataflow {", "  rankdir=LR; node [shape=box, style=filled];"]
        for n in self.nodes.values():
            label = f"{n['label']}\\n(L{n['line']})".replace('"', "'")
            out.append(f'  "{n["id"]}" [label="{label}", fillcolor={color.get(n["kind"], "white")}];')
        for e in self.edges:
            out.append(f'  "{e["from"]}" -> "{e["to"]}";')
        return "\n".join(out + ["}"]) + "\n"


class FunctionAnalyzer:
    def __init__(self, fn: ast.FunctionDef, graph: Graph, models: dict[str, set[str]]):
        self.fn, self.g, self.models = fn, graph, models
        self.var_node: dict[str, str] = {}
        self.findings: list[Finding] = []
        self.fetch_assigns: list[tuple[ast.Assign, str, str]] = []  # (stmt, var, param)
        self.path, self.methods = route_info(fn)
        self.params = path_params(self.path or "")
        self.deco = {dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1] for d in fn.decorator_list}
        self.sources_for_names: dict[str, str] = {}

    def nid(self, kind, label, line):
        return f"{self.fn.name}:{kind}:{label}:{line}"

    # taint feeders of an expression -> node ids
    def feeders(self, expr: ast.AST) -> set[str]:
        out: set[str] = set()
        for n in ast.walk(expr):
            if isinstance(n, ast.Name) and n.id in self.var_node:
                out.add(self.var_node[n.id])
            elif isinstance(n, (ast.Attribute, ast.Call)) and is_request_source(n):
                label = dotted(n.func if isinstance(n, ast.Call) else n)
                line = getattr(n, "lineno", self.fn.lineno)
                out.add(self.g.node(self.nid("source", label, line), "source", label, line, self.fn.name))
        return out

    def run(self) -> list[Finding]:
        fn = self.fn
        for p in self.params:  # route params are attacker-controlled
            self.var_node[p] = self.g.node(self.nid("source", f"route:{p}", fn.lineno), "source", f"route param {p}", fn.lineno, fn.name)
        for _ in range(2):  # two passes cover simple reorderings/loops
            for stmt in ast.walk(fn):
                if isinstance(stmt, ast.Assign):
                    self._assign(stmt)
        for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
            self._sink(call)
        self._authz()
        self._business_logic()
        return self.findings

    def _assign(self, stmt: ast.Assign):
        feeds = self.feeders(stmt.value)
        for t in stmt.targets:
            names = [t] if isinstance(t, ast.Name) else [e for e in getattr(t, "elts", []) if isinstance(e, ast.Name)]
            for n in names:
                if feeds:
                    vid = self.g.node(self.nid("var", n.id, stmt.lineno), "var", n.id, stmt.lineno, self.fn.name)
                    for f in feeds:
                        self.g.edge(f, vid)
                    self.var_node[n.id] = vid
        # ORM fetch-by-id pattern: x = Model.query.get(param) / get_or_404 / filter_by(id=param).first()
        if isinstance(stmt.value, ast.Call) and isinstance(stmt.targets[0], ast.Name):
            d = dotted(stmt.value.func)
            args_names = {n.id for a in stmt.value.args for n in ast.walk(a) if isinstance(n, ast.Name)} | \
                {n.id for k in stmt.value.keywords for n in ast.walk(k.value) if isinstance(n, ast.Name)}
            inner = ast.unparse(stmt.value)
            if (".query." in d or ".query." in inner) and any(x in inner for x in ("get(", "get_or_404(", "filter_by(", "first_or_404(")):
                for p in self.params:
                    if p in args_names and not any(x[0] is stmt for x in self.fetch_assigns):
                        self.fetch_assigns.append((stmt, stmt.targets[0].id, p))

    def _sink(self, call: ast.Call):
        d = dotted(call.func)
        feeds = set()
        for a in list(call.args) + [k.value for k in call.keywords]:
            feeds |= self.feeders(a)
        is_exec = isinstance(call.func, ast.Attribute) and call.func.attr in {"execute", "executemany"} and bool(call.args)
        if not feeds and not is_exec:
            return
        line = call.lineno

        def sink(kind: str, rule: str, sev: str, msg: str, fixable: bool, hint: str):
            sid = self.g.node(self.nid("sink", kind, line), "sink", kind, line, self.fn.name)
            for f in feeds:
                self.g.edge(f, sid)
            labels = sorted({self.g.nodes[f]["label"] for f in feeds})
            self.findings.append(Finding(rule, sev, line, self.fn.name, msg, fixable, hint, labels, (call.lineno, call.col_offset)))

        if isinstance(call.func, ast.Attribute) and call.func.attr in {"execute", "executemany"} and call.args:
            q = call.args[0]
            inner = q.args[0] if isinstance(q, ast.Call) and dotted(q.func) == "text" and q.args else q
            dynamic = isinstance(inner, ast.JoinedStr) or (isinstance(inner, ast.BinOp) and isinstance(inner.op, (ast.Add, ast.Mod))) \
                or (isinstance(inner, ast.Call) and isinstance(inner.func, ast.Attribute) and inner.func.attr == "format")
            parts = _flatten(inner) if dynamic else None
            if dynamic and parts and any(k == "expr" for k, _ in parts):
                ok = parametrize_query(call, "?") is not None
                if feeds:
                    sink("db.execute", "sql-injection", "critical", "Untrusted input interpolated into an SQL string.", ok,
                         "Use parameterized queries: execute(sql, params).")
                else:  # provenance unknown (e.g. function argument): still unsafe construction
                    sink("db.execute", "sql-injection", "medium", "SQL string built by interpolation/concatenation (input provenance unknown).", ok,
                         "Use parameterized queries: execute(sql, params).")
        elif d in {"os.system", "os.popen"}:
            ok = _cmd_to_argv(call) is not None
            sink(d, "command-injection", "critical", f"Untrusted input reaches {d}.", ok,
                 "Use subprocess.run([...argv], shell=False) with a validated argument list.")
        elif d.startswith("subprocess.") and any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value for k in call.keywords):
            sink(d, "command-injection", "critical", "Untrusted input reaches subprocess with shell=True.", False, "Pass an argv list and shell=False.")
        elif d in {"eval", "exec"}:
            sink(d, "code-injection", "critical", f"Untrusted input reaches {d}().", False, "Remove dynamic evaluation; parse data with json/ast.literal_eval.")
        elif d == "open":
            sink("open", "path-traversal", "high", "Untrusted input used as a file path.", False, "Resolve with werkzeug.utils.safe_join against a fixed base directory.")
        elif d in {"redirect", "flask.redirect"}:
            sink("redirect", "open-redirect", "medium", "Untrusted input used as redirect target.", False, "Allow-list internal paths or validate with url_has_allowed_host.")
        # mass assignment: Model(**request...)
        for k in call.keywords:
            if k.arg is None and any(is_request_source(n) for n in ast.walk(k.value)) and d[:1].isupper():
                sink(d, "mass-assignment", "high", f"{d}(**request data) lets clients set any field (e.g. is_admin).", False,
                     "Copy only an explicit allow-list of fields from the request.")

    def _refs_current_user(self, n: ast.AST) -> bool:
        return any(isinstance(x, ast.Name) and x.id in CURRENT_USER_NAMES for x in ast.walk(n)) or \
            "g.user" in ast.unparse(n)

    def _authz(self):
        fn, path = self.fn, self.path
        if not path:
            return
        authed = bool(self.deco & AUTH_DECORATORS) or any(self._refs_current_user(n) for n in ast.walk(fn) if isinstance(n, (ast.Compare, ast.If)))
        touches_data = any(isinstance(n, ast.Call) and (".query" in ast.unparse(n.func) or (isinstance(n.func, ast.Attribute) and n.func.attr in {"execute", "add", "delete"}))
                           for n in ast.walk(fn))
        if path not in PUBLIC_ROUTES and not authed and (touches_data or self.params or "/admin" in path):
            self.findings.append(Finding("missing-authentication", "high", fn.lineno, fn.name,
                                         f"Route {path} touches data without any authentication check.", True,
                                         "Add @login_required.", node_key=("auth", fn.lineno)))
        if "/admin" in path and "admin_required" not in self.deco and not any(
                "is_admin" in ast.unparse(n) or "role" in ast.unparse(n) for n in ast.walk(fn) if isinstance(n, (ast.If, ast.Compare))):
            self.findings.append(Finding("missing-authorization", "critical", fn.lineno, fn.name,
                                         f"Admin route {path} has no role/admin check; any user can call it.", True,
                                         "Check current_user.is_admin before acting.", node_key=("admin", fn.lineno)))
        # IDOR
        for stmt, var, param in self.fetch_assigns:
            owner_checked = False
            for n in ast.walk(fn):
                if isinstance(n, (ast.Compare, ast.If)) and self._refs_current_user(n) and var in {x.id for x in ast.walk(n) if isinstance(x, ast.Name)}:
                    owner_checked = True
            inner = ast.unparse(stmt.value)
            if "current_user" in inner or any(f"{o}=current_user" in inner for o in OWNER_FIELDS):
                owner_checked = True
            if not owner_checked:
                self.findings.append(Finding("idor", "high", stmt.lineno, fn.name,
                                             f"Object fetched by client-supplied '{param}' with no ownership check (IDOR).", True,
                                             "Verify the object belongs to current_user before returning it.", [f"route param {param}", var],
                                             ("idor", stmt.lineno)))

    def _business_logic(self):
        fn = self.fn
        compared = {x.id for n in ast.walk(fn) if isinstance(n, ast.Compare) for x in ast.walk(n) if isinstance(x, ast.Name)}
        for stmt in ast.walk(fn):
            if not isinstance(stmt, ast.Assign) or not isinstance(stmt.targets[0], ast.Name):
                continue
            val = ast.unparse(stmt.value)
            tgt = stmt.targets[0].id
            from_client = any(is_request_source(n) for n in ast.walk(stmt.value)) or any(
                isinstance(n, ast.Name) and n.id in self.var_node and self.g.nodes[self.var_node[n.id]]["label"].startswith("request") for n in ast.walk(stmt.value))
            # data["price"] where data came from request
            if not from_client:
                for n in ast.walk(stmt.value):
                    if isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and n.value.id in self.var_node:
                        from_client = True
            if from_client and (SENSITIVE_FIELD.search(tgt) or SENSITIVE_FIELD.search(val)):
                self.findings.append(Finding("business-logic", "high", stmt.lineno, fn.name,
                                             f"Client-controlled value '{tgt}' ({val}) used for a security/financial decision.", False,
                                             "Derive prices/roles/discounts server-side from trusted records; never from the request body.",
                                             [tgt]))
            elif from_client and re.search(r"qty|quantity|count|units", tgt, re.I) and tgt not in compared:
                self.findings.append(Finding("business-logic", "medium", stmt.lineno, fn.name,
                                             f"'{tgt}' from the client is never bounds-checked (negative/zero/huge quantities).", False,
                                             "Validate 0 < qty <= max before use.", [tgt]))


# -- parametrization -------------------------------------------------------------------------
IDENT_CONTEXT = re.compile(r"(from|into|table|join|update|order by|group by|select)\s*$", re.I)


def _flatten(e: ast.AST):
    """Yield ('const', str) / ('expr', node) parts of a string-building expression, or None if unsupported."""
    if isinstance(e, ast.JoinedStr):
        parts = []
        for v in e.values:
            if isinstance(v, ast.Constant):
                parts.append(("const", v.value))
            elif isinstance(v, ast.FormattedValue) and not v.format_spec:
                parts.append(("expr", v.value))
            else:
                return None
        return parts
    if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Add):
        l, r = _flatten(e.left), _flatten(e.right)
        return None if l is None or r is None else l + r
    if isinstance(e, ast.Constant) and isinstance(e.value, str):
        return [("const", e.value)]
    if isinstance(e, ast.BinOp) and isinstance(e.op, ast.Mod) and isinstance(e.left, ast.Constant) and isinstance(e.left.value, str):
        args = e.right.elts if isinstance(e.right, ast.Tuple) else [e.right]
        pieces = re.split(r"%s", e.left.value)
        if len(pieces) - 1 != len(args) or re.search(r"%[^s%]", e.left.value.replace("%%", "")):
            return None
        parts = []
        for i, p in enumerate(pieces):
            parts.append(("const", p))
            if i < len(args):
                parts.append(("expr", args[i]))
        return parts
    if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "format" and isinstance(e.func.value, ast.Constant) \
            and isinstance(e.func.value.value, str) and not e.keywords:
        pieces = re.split(r"\{\}", e.func.value.value)
        if len(pieces) - 1 != len(e.args) or re.search(r"\{[^}]", e.func.value.value):
            return None
        parts = []
        for i, p in enumerate(pieces):
            parts.append(("const", p))
            if i < len(e.args):
                parts.append(("expr", e.args[i]))
        return parts
    if isinstance(e, ast.Call) and isinstance(e.func, ast.Name) and e.func.id == "str" and len(e.args) == 1:
        return [("expr", e.args[0])]
    return [("expr", e)]


def parametrize_query(call: ast.Call, style: str):
    """Return (new_sql, [param exprs]) or None. Does not mutate unless apply via apply_parametrize."""
    if not call.args or len(call.args) > 1:
        return None
    q = call.args[0]
    text_wrapped = isinstance(q, ast.Call) and dotted(q.func) == "text" and len(q.args) == 1
    inner = q.args[0] if text_wrapped else q
    parts = _flatten(inner)
    if parts is None:
        return None
    # merge adjacent constants; unwrap str(x)
    merged: list = []
    for kind, v in parts:
        if kind == "expr" and isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "str" and len(v.args) == 1:
            v = v.args[0]
        if kind == "const" and merged and merged[-1][0] == "const":
            merged[-1] = ("const", merged[-1][1] + v)
        else:
            merged.append((kind, v))
    sql, params, n = "", [], 0
    for i, (kind, v) in enumerate(merged):
        if kind == "const":
            sql += v
            continue
        prev = sql
        nxt = merged[i + 1][1] if i + 1 < len(merged) and merged[i + 1][0] == "const" else ""
        if IDENT_CONTEXT.search(prev):
            return None  # identifier interpolation cannot be parameterized
        m = re.search(r"(['\"])(%?)$", prev)
        expr = v
        if m and re.match(rf"^(%?){re.escape(m.group(1))}", nxt):
            after = re.match(rf"^(%?){re.escape(m.group(1))}", nxt)
            sql = prev[: m.start()]
            merged[i + 1] = ("const", nxt[after.end():])
            pre_w, post_w = m.group(2), after.group(1)
            if pre_w or post_w:
                pieces = ([ast.Constant(pre_w)] if pre_w else []) + [ast.Call(ast.Name("str", ast.Load()), [v], [])] + \
                         ([ast.Constant(post_w)] if post_w else [])
                expr = pieces[0]
                for p in pieces[1:]:
                    expr = ast.BinOp(expr, ast.Add(), p)
        elif re.search(r"['\"]$", prev):
            return None  # unbalanced quoting: bail out
        ph = f":p{n}" if style == "named" else style
        sql += ph
        params.append(expr)
        n += 1
    if not params:
        return None
    return sql, params, text_wrapped


def apply_parametrize(call: ast.Call, style: str) -> bool:
    q = call.args[0]
    named = isinstance(q, ast.Call) and dotted(q.func) == "text"  # SQLAlchemy text() uses :name binds
    res = parametrize_query(call, "named" if named else style)
    if res is None:
        return False
    sql, params, text_wrapped = res
    if text_wrapped:
        new_q = ast.Call(ast.Name("text", ast.Load()), [ast.Constant(sql)], [])
        call.args = [new_q, ast.Dict([ast.Constant(f"p{i}") for i in range(len(params))], params)]
    else:
        call.args = [ast.Constant(sql), ast.Tuple(params, ast.Load())]
    return True


def _cmd_to_argv(call: ast.Call):
    if len(call.args) != 1 or not isinstance(call.args[0], ast.JoinedStr):
        return None
    toks: list = []
    cur: list = []
    for v in call.args[0].values:
        if isinstance(v, ast.Constant):
            chunks = re.split(r"(\s+)", v.value)
            for c in chunks:
                if c == "":
                    continue
                if c.isspace():
                    if cur:
                        toks.append(cur)
                        cur = []
                else:
                    cur.append(("c", c))
        elif isinstance(v, ast.FormattedValue) and not v.format_spec:
            cur.append(("e", v.value))
        else:
            return None
    if cur:
        toks.append(cur)
    argv = []
    for t in toks:
        if len(t) == 1 and t[0][0] == "c":
            argv.append(ast.Constant(t[0][1]))
        elif len(t) == 1:
            argv.append(ast.Call(ast.Name("str", ast.Load()), [t[0][1]], []))
        else:
            return None  # mixed literal/expr token: ambiguous
    return argv or None


# -- patcher ---------------------------------------------------------------------------------
def _detect_style(tree: ast.Module) -> str:
    mods = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
           {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    return "%s" if mods & {"psycopg2", "pymysql", "MySQLdb", "mysql"} else "?"


def _models(tree: ast.Module) -> dict[str, set[str]]:
    out = {}
    for c in tree.body:
        if isinstance(c, ast.ClassDef):
            out[c.name] = {t.id for s in c.body if isinstance(s, ast.Assign) for t in s.targets if isinstance(t, ast.Name)}
    return out


def analyze_source(src: str):
    """Returns (normalized_source, findings, graph)."""
    norm = normalize(src)
    tree = ast.parse(norm)
    graph, findings = Graph(), []
    models = _models(tree)
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        findings += FunctionAnalyzer(fn, graph, models).run()
    return norm, findings, graph


def _ensure_import(tree: ast.Module, module: str, names: list[str]):
    have = {a.name for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == module for a in n.names}
    missing = [n for n in names if n not in have]
    if not missing:
        return
    existing = next((n for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == module), None)
    if existing:
        existing.names += [ast.alias(n) for n in missing]
        return
    idx = 0
    for i, n in enumerate(tree.body):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            idx = i + 1
    tree.body.insert(idx, ast.ImportFrom(module, [ast.alias(n) for n in missing], 0))


def _ensure_plain_import(tree: ast.Module, name: str):
    if any(isinstance(n, ast.Import) and any(a.name == name for a in n.names) for n in tree.body):
        return
    idx = 0
    for i, n in enumerate(tree.body):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            idx = i + 1
    tree.body.insert(idx, ast.Import([ast.alias(name)]))


def _body_containing(tree: ast.AST, stmt: ast.stmt):
    for n in ast.walk(tree):
        for fld in ("body", "orelse", "finalbody"):
            lst = getattr(n, fld, None)
            if isinstance(lst, list) and any(x is stmt for x in lst):
                return lst
    return None


def _owner_field(models: dict[str, set[str]], stmt: ast.Assign) -> str:
    for m, cols in models.items():
        if m in ast.unparse(stmt.value):
            for o in OWNER_FIELDS:
                if o in cols:
                    return o
    return "user_id"


def generate_patch(src: str, filename: str = "app.py") -> dict:
    norm, findings, graph = analyze_source(src)
    tree = ast.parse(norm)
    style = _detect_style(tree)
    models = _models(tree)
    calls = {(n.lineno, n.col_offset): n for n in ast.walk(tree) if isinstance(n, ast.Call)}
    funcs = {n.lineno: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    stmts = {n.lineno: n for n in ast.walk(tree) if isinstance(n, ast.Assign)}
    applied, skipped = [], []
    need_login = need_current_user = need_abort = need_subprocess = False
    for f in findings:
        if not f.fixable:
            skipped.append(f)
            continue
        ok = False
        if f.rule == "sql-injection":
            ok = apply_parametrize(calls[f.node_key], style)
        elif f.rule == "command-injection":
            call = calls[f.node_key]
            argv = _cmd_to_argv(call)
            if argv is not None:
                call.func = ast.Attribute(ast.Name("subprocess", ast.Load()), "run", ast.Load())
                call.args = [ast.List(argv, ast.Load())]
                call.keywords = [ast.keyword("check", ast.Constant(False))]
                need_subprocess = ok = True
        elif f.rule == "missing-authentication":
            fn = funcs[f.node_key[1]]
            if not any(dotted(d) == "login_required" for d in fn.decorator_list):
                fn.decorator_list.append(ast.Name("login_required", ast.Load()))
            need_login = ok = True
        elif f.rule == "missing-authorization":
            fn = funcs[f.node_key[1]]
            guard = ast.parse('if not getattr(current_user, "is_admin", False):\n    abort(403)').body[0]
            at = 1 if fn.body and isinstance(fn.body[0], ast.Expr) and isinstance(getattr(fn.body[0], "value", None), ast.Constant) else 0
            fn.body.insert(at, guard)
            need_current_user = need_abort = ok = True
        elif f.rule == "idor":
            stmt = stmts[f.node_key[1]]
            var = stmt.targets[0].id
            owner = _owner_field(models, stmt)
            guard = ast.parse(f"if {var} is None or {var}.{owner} != current_user.id:\n    abort(404)").body[0]
            body = _body_containing(tree, stmt)
            body.insert(next(i for i, x in enumerate(body) if x is stmt) + 1, guard)
            need_current_user = need_abort = ok = True
        (applied if ok else skipped).append(f)
    if need_login or need_current_user:
        _ensure_import(tree, "flask_login", [n for n, c in (("current_user", need_current_user), ("login_required", need_login)) if c])
    if need_abort:
        _ensure_import(tree, "flask", ["abort"])
    if need_subprocess:
        _ensure_plain_import(tree, "subprocess")
    ast.fix_missing_locations(tree)
    patched = ast.unparse(tree) + "\n"
    diff = "".join(difflib.unified_diff(norm.splitlines(True), patched.splitlines(True), f"a/{filename}", f"b/{filename}", n=3))
    if diff:
        diff = f"diff --git a/{filename} b/{filename}\n" + diff
    return {"normalized": norm, "patched": patched, "diff": diff, "findings": findings, "applied": applied,
            "skipped": skipped, "graph": graph}
