"""AST-based (Python) and pattern-based (PHP/JS) legacy-code analyzer."""
from __future__ import annotations

import ast
import re
from dataclasses import asdict, dataclass
from pathlib import Path

SEV_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "vendor", "build", "dist"}

DEPRECATED_MODULES = {
    "imp": "use importlib", "optparse": "use argparse", "distutils": "use setuptools/packaging",
    "asyncore": "use asyncio", "asynchat": "use asyncio", "smtpd": "use aiosmtpd", "cgi": "use a web framework",
    "cgitb": "use logging/tracebacks", "pipes": "use subprocess/shlex", "telnetlib": "use a maintained client",
    "urllib2": "Python 2 module; use httpx/urllib.request", "urlparse": "Python 2; use urllib.parse",
    "ConfigParser": "Python 2; use configparser", "Queue": "Python 2; use queue", "md5": "use hashlib",
    "sha": "use hashlib", "sets": "use builtin set", "commands": "use subprocess", "StringIO": "use io.StringIO",
    "cPickle": "use pickle (and avoid untrusted data)",
}
SECRET_NAME = re.compile(r"(password|passwd|secret|api_?key|token|private_?key)", re.I)


@dataclass
class Finding:
    file: str
    line: int
    rule: str
    severity: str
    category: str  # deprecated | security | maintainability | compatibility
    message: str
    language: str

    def to_dict(self) -> dict:
        return asdict(self)


def _dotted(node: ast.AST) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def complexity(fn: ast.AST) -> int:
    c = 1
    for n in ast.walk(fn):
        if isinstance(n, (ast.If, ast.For, ast.While, ast.AsyncFor, ast.ExceptHandler, ast.With, ast.IfExp,
                          ast.Assert, ast.comprehension)):
            c += 1
        elif isinstance(n, ast.BoolOp):
            c += len(n.values) - 1
    return c


def _max_depth(node: ast.AST, depth: int = 0) -> int:
    best = depth
    for ch in ast.iter_child_nodes(node):
        inc = isinstance(ch, (ast.If, ast.For, ast.While, ast.Try, ast.With))
        best = max(best, _max_depth(ch, depth + inc))
    return best


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, rel: str):
        self.rel = rel
        self.out: list[Finding] = []

    def add(self, node, rule, sev, cat, msg):
        self.out.append(Finding(self.rel, getattr(node, "lineno", 0), rule, sev, cat, msg, "python"))

    def visit_Import(self, node):
        for a in node.names:
            self._mod(node, a.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self._mod(node, node.module)
        self.generic_visit(node)

    def _mod(self, node, name):
        root = name.split(".")[0]
        if root in DEPRECATED_MODULES:
            self.add(node, "deprecated-module", "medium", "deprecated", f"Deprecated/removed module '{root}': {DEPRECATED_MODULES[root]}")

    def visit_Assign(self, node):
        if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) and len(node.value.value) >= 4:
            for t in node.targets:
                if isinstance(t, ast.Name) and SECRET_NAME.search(t.id):
                    self.add(node, "hardcoded-secret", "critical", "security", f"Hard-coded credential in '{t.id}'; move to environment/secret manager")
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):
        if node.type is None:
            self.add(node, "bare-except", "low", "maintainability", "Bare 'except:' swallows KeyboardInterrupt/SystemExit")
        self.generic_visit(node)

    def visit_Compare(self, node):
        for op, c in zip(node.ops, node.comparators):
            if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(c, ast.Constant) and c.value is None:
                self.add(node, "none-comparison", "low", "maintainability", "Compare to None with 'is'/'is not'")
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self._function(node)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def _function(self, node):
        for d in node.args.defaults + [d for d in node.args.kw_defaults if d]:
            if isinstance(d, (ast.List, ast.Dict, ast.Set)):
                self.add(node, "mutable-default", "medium", "maintainability", f"'{node.name}' has a mutable default argument (shared state between calls)")
        length = (node.end_lineno or node.lineno) - node.lineno + 1
        cx, depth = complexity(node), _max_depth(node)
        nargs = len(node.args.args) + len(node.args.kwonlyargs)
        reasons = []
        if length > 40:
            reasons.append(f"{length} lines")
        if cx > 10:
            reasons.append(f"cyclomatic complexity {cx}")
        if depth > 4:
            reasons.append(f"nesting depth {depth}")
        if nargs > 6:
            reasons.append(f"{nargs} parameters")
        if reasons:
            self.add(node, "monolithic-function", "high" if cx > 15 or length > 80 else "medium", "maintainability",
                     f"Monolithic function '{node.name}' ({', '.join(reasons)}); split into focused units")

    def visit_Call(self, node):
        name = _dotted(node.func)
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        if name in {"eval", "exec"}:
            self.add(node, "dynamic-exec", "critical", "security", f"'{name}' executes arbitrary code")
        elif name in {"os.system", "os.popen", "commands.getoutput"}:
            self.add(node, "shell-exec", "critical", "security", f"'{name}' invokes a shell; use subprocess with an argument list")
        elif name.startswith("subprocess.") and isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True:
            self.add(node, "shell-exec", "high", "security", "subprocess with shell=True enables command injection")
        elif name in {"yaml.load", "yaml.load_all"} and "Loader" not in kw and len(node.args) < 2:
            self.add(node, "unsafe-yaml", "high", "security", "yaml.load without a Loader can construct arbitrary objects; use yaml.safe_load")
        elif name in {"pickle.load", "pickle.loads", "cPickle.loads", "marshal.loads"}:
            self.add(node, "unsafe-deserialization", "high", "security", f"'{name}' on untrusted data allows code execution")
        elif name in {"hashlib.md5", "hashlib.sha1"}:
            self.add(node, "weak-hash", "high", "security", f"'{name}' is unsuitable for passwords/integrity; use argon2/bcrypt or sha256+")
        elif name == "tempfile.mktemp":
            self.add(node, "insecure-tempfile", "medium", "security", "tempfile.mktemp is racy; use NamedTemporaryFile/mkstemp")
        elif name.startswith("requests.") and isinstance(kw.get("verify"), ast.Constant) and kw["verify"].value is False:
            self.add(node, "tls-verify-off", "high", "security", "TLS verification disabled")
        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany", "executescript"} and node.args:
            q = node.args[0]
            dynamic = isinstance(q, ast.JoinedStr) or (isinstance(q, ast.BinOp) and isinstance(q.op, (ast.Add, ast.Mod))) \
                or (isinstance(q, ast.Call) and isinstance(q.func, ast.Attribute) and q.func.attr == "format")
            if dynamic:
                self.add(node, "sql-injection", "critical", "security", "SQL built via string interpolation/concatenation; use parameterized queries")
        if isinstance(node.func, ast.Attribute) and node.func.attr == "has_key":
            self.add(node, "py2-has-key", "medium", "compatibility", "dict.has_key() was removed in Python 3; use 'in'")
        self.generic_visit(node)


PY2_PRINT = re.compile(r"^\s*print\s+[\"'\w]", re.M)

PHP_RULES = [
    (r"\bmysql_(query|connect|fetch_\w+|escape_string)\s*\(", "deprecated-mysql-ext", "high", "deprecated", "mysql_* extension removed in PHP 7; use PDO/mysqli prepared statements"),
    (r"\beval\s*\(", "dynamic-exec", "critical", "security", "eval() executes arbitrary code"),
    (r"\$_(GET|POST|REQUEST|COOKIE)\b[^;\n]*\b(SELECT|INSERT|UPDATE|DELETE)\b|\b(SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*\$_(GET|POST|REQUEST|COOKIE)\b",
     "sql-injection", "critical", "security", "User input concatenated into SQL; use prepared statements"),
    (r"\bextract\s*\(\s*\$_(GET|POST|REQUEST)", "variable-injection", "critical", "security", "extract() on request data overwrites variables"),
    (r"\bunserialize\s*\(\s*\$_", "unsafe-deserialization", "critical", "security", "unserialize() on user input enables object injection"),
    (r"\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST)", "file-inclusion", "critical", "security", "File inclusion from user input (LFI/RFI)"),
    (r"\bmd5\s*\(", "weak-hash", "high", "security", "md5() unsuitable for passwords; use password_hash()"),
    (r"\berror_reporting\s*\(\s*0\s*\)", "errors-suppressed", "low", "maintainability", "Error reporting disabled hides failures; log instead"),
    (r"echo\s+[^;\n]*\$_(GET|POST|REQUEST)", "reflected-xss", "high", "security", "Unescaped user input echoed; use htmlspecialchars()"),
]
JS_RULES = [
    (r"\beval\s*\(", "dynamic-exec", "critical", "security", "eval() executes arbitrary code"),
    (r"document\.write\s*\(", "document-write", "medium", "security", "document.write enables XSS and blocks parsing"),
    (r"\.innerHTML\s*=", "inner-html", "high", "security", "innerHTML assignment is an XSS sink; use textContent/sanitizer"),
    (r"\bnew\s+Buffer\s*\(", "deprecated-buffer", "medium", "deprecated", "new Buffer() is deprecated; use Buffer.from/alloc"),
    (r"require\(\s*['\"]request['\"]\s*\)", "deprecated-library", "medium", "deprecated", "'request' is deprecated; use fetch/undici/axios"),
    (r"^\s*var\s+", "var-keyword", "low", "maintainability", "Use let/const instead of var"),
    (r"(api_?key|secret|token|password)\w*\s*=\s*['\"][A-Za-z0-9_\-/+=]{8,}['\"]", "hardcoded-secret", "critical", "security", "Hard-coded credential"),
]


def _regex_scan(text: str, rel: str, rules, lang: str) -> list[Finding]:
    out = []
    for pat, rule, sev, cat, msg in rules:
        for m in re.finditer(pat, text, re.I | re.M):
            line = text.count("\n", 0, m.start()) + 1
            out.append(Finding(rel, line, rule, sev, cat, msg, lang))
    return out


def analyze_file(path: Path, root: Path) -> list[Finding]:
    rel = str(path.relative_to(root))
    text = path.read_text(errors="replace")
    if path.suffix == ".py":
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            sev = "high"
            msg = f"Not valid Python 3 (line {exc.lineno}): likely Python 2 syntax"
            if PY2_PRINT.search(text):
                msg = "Python 2 print statement; file cannot be parsed by Python 3"
            fs = [Finding(rel, exc.lineno or 1, "py2-syntax", sev, "compatibility", msg, "python")]
            for m in re.finditer(r"^\s*(?:import|from)\s+(\w+)", text, re.M):
                if m.group(1) in DEPRECATED_MODULES:
                    fs.append(Finding(rel, text.count("\n", 0, m.start()) + 1, "deprecated-module", "medium", "deprecated",
                                      f"Deprecated/removed module '{m.group(1)}': {DEPRECATED_MODULES[m.group(1)]}", "python"))
            return fs
        v = _PyVisitor(rel)
        v.visit(tree)
        return v.out
    if path.suffix == ".php":
        return _regex_scan(text, rel, PHP_RULES, "php")
    if path.suffix in {".js", ".mjs"}:
        return _regex_scan(text, rel, JS_RULES, "javascript")
    return []


def scan_repo(root: Path) -> list[Finding]:
    root = Path(root)
    findings: list[Finding] = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in {".py", ".php", ".js", ".mjs"} and not (set(p.relative_to(root).parts) & SKIP_DIRS):
            findings.extend(analyze_file(p, root))
    return findings


def risk_score(findings: list[Finding]) -> int:
    """0 (clean) .. 100 (severe), saturating."""
    raw = sum(SEV_WEIGHT[f.severity] for f in findings)
    return min(100, round(100 * (1 - 0.97 ** raw))) if raw else 0
