#!/usr/bin/env python3
"""Builds assets/secret_formats.json (vendor token formats) and the test samples from gitleaks (MIT license, https://github.com/gitleaks/gitleaks).

usage: gen_secret_formats.py <gitleaks checkout> <out secret_formats.json> <out samples.json>
- rules: config/gitleaks.toml (final regexes, keywords, entropy, secretGroup, stopwords)
- samples: LITERAL true / false positives written in cmd/generate/config/rules/*.go (the generated ones, built with secrets.NewSecret, are skipped)
"""
import json, re, sys, os, glob, tomllib

# rules that are not "a vendor token format": generic key=value heuristics (our own entropy detector with positive evidence covers those), private keys / JWT (own rules),
# and shell-command shapes
DENY = {"generic-api-key", "curl-auth-header", "curl-auth-user", "jwt", "jwt-base64", "private-key", "pkcs12-file", "hashicorp-tf-password", "sidekiq-sensitive-url",
        "kubernetes-secret-yaml", "etsy-access-token", "flickr-access-token", "gcp-api-key", "aws-access-token"}   # last four: noisy shapes / already in secrets-known-formats

def go_literals(block):
    """(value, partial) for every Go string literal in the block; partial = glued to something else with '+'."""
    out = []; i = 0; n = len(block)
    while i < n:
        c = block[i]
        if c == '"':
            j = i + 1; buf = []
            while j < n and block[j] != '"':
                if block[j] == "\\" and j + 1 < n:
                    e = block[j + 1]
                    if e == "x" and j + 3 < n: buf.append(chr(int(block[j + 2:j + 4], 16))); j += 4; continue
                    buf.append({"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "'": "'"}.get(e, e)); j += 2; continue
                buf.append(block[j]); j += 1
            out.append(("".join(buf), i, j + 1)); i = j + 1
        elif c == "`":
            j = block.find("`", i + 1)
            if j < 0: break
            out.append((block[i + 1:j], i, j + 1)); i = j + 1
        elif block.startswith("//", i):
            i = block.find("\n", i) if block.find("\n", i) >= 0 else n
        else:
            i += 1
    res = []
    for v, a, b in out:
        before = block[:a].rstrip(); after = block[b:].lstrip()
        res.append((v, before.endswith("+") or after.startswith("+")))
    return res

def mask_calls(txt, names=("secrets.NewSecret(", "fmt.Sprintf(", "utils.AlphaNumeric(", "utils.Hex(", "utils.Numeric(")):
    """Blank out balanced calls: their literals are generator patterns or format strings, not samples."""
    out = list(txt); i = 0
    while i < len(txt):
        hit = next((nm for nm in names if txt.startswith(nm, i)), None)
        if not hit: i += 1; continue
        depth = 0; j = i + len(hit) - 1
        while j < len(txt):
            if txt[j] == "(": depth += 1
            elif txt[j] == ")":
                depth -= 1
                if depth == 0: break
            elif txt[j] in "\"`":
                q = txt[j]; k = txt.find(q, j + 1)
                while q == '"' and k > 0 and txt[k - 1] == "\\": k = txt.find(q, k + 1)
                j = k if k > 0 else len(txt)
            j += 1
        for k in range(i, min(j + 1, len(txt))): out[k] = " "
        i = j + 1
    return "".join(out)

def samples_from_go(path):
    src = open(path, encoding="utf-8").read(); out = {}
    for m in re.finditer(r'RuleID:\s*"([^"]+)"', src):
        rid = m.group(1)
        tail = src[m.end():]
        end = re.search(r"return utils\.Validate", tail)
        body = tail[:end.start()] if end else tail
        tp_at = body.find("tps"); fp_at = body.find("fps")
        if tp_at < 0: continue
        tps_txt = body[tp_at:fp_at] if fp_at > tp_at else body[tp_at:]
        fps_txt = body[fp_at:] if fp_at > tp_at else ""
        tps = []
        # GenerateSampleSecrets("name", "VALUE"): the value is the 2nd argument; the test wraps it in a few source shapes (kind "gen": name, value)
        for gm in re.finditer(r'GenerateSampleSecrets\(\s*"([^"]*)"\s*,\s*("(?:[^"\\]|\\.)*"|`[^`]*`)\s*([+)])', tps_txt):
            if gm.group(3) == ")": tps.append(("gen", gm.group(1) + "\u0000" + go_literals(gm.group(2))[0][0]))
        stripped = mask_calls(re.sub(r'GenerateSampleSecrets\([^\n]*', "", tps_txt))
        for v, partial in go_literals(stripped):
            if not partial and len(v) >= 12 and "%s" not in v and "gitleaks" not in v[:8]: tps.append(("line", v))
        fps = [v for v, partial in go_literals(mask_calls(fps_txt)) if not partial and len(v) >= 8 and "%s" not in v]
        out[rid] = {"tps": tps, "fps": fps}
    return out

def main():
    gl, out_json, out_samples = sys.argv[1:4]
    cfg = tomllib.load(open(os.path.join(gl, "config/gitleaks.toml"), "rb"))
    glob_stop = []
    for al in cfg.get("allowlists", []) or []:
        glob_stop += al.get("stopwords", []) or []
    rules = []; skipped = []
    for r in cfg["rules"]:
        rid = r["id"]
        if rid in DENY or not r.get("regex"): skipped.append(rid); continue
        if r.get("path"): skipped.append(rid); continue          # applies to a file NAME (nuget.config ...): no meaning for a string in an APK
        stop = []; allow_rx = []
        for al in r.get("allowlists", []) or []:
            stop += al.get("stopwords", []) or []
            allow_rx += al.get("regexes", []) or []
        rules.append({"id": rid, "desc": r.get("description", ""), "regex": r["regex"], "entropy": float(r.get("entropy", 0) or 0),
                      "keywords": [k.lower() for k in r.get("keywords", []) or []], "group": int(r.get("secretGroup", 0) or 0),
                      "stop": stop, "allow": allow_rx})
    json.dump({"source": "gitleaks (MIT) config/gitleaks.toml", "stopwords": glob_stop, "rules": rules}, open(out_json, "w"), separators=(",", ":"))
    samples = {}
    for f in glob.glob(os.path.join(gl, "cmd/generate/config/rules/*.go")):
        samples.update(samples_from_go(f))
    keep = {rid: s for rid, s in samples.items() if any(r["id"] == rid for r in rules) and (s["tps"] or s["fps"])}
    json.dump(keep, open(out_samples, "w"), separators=(",", ":"))
    print("rules", len(rules), "skipped", len(skipped), "| rules with literal samples", len(keep), "| literal TPs", sum(len(s["tps"]) for s in keep.values()),
          "literal FPs", sum(len(s["fps"]) for s in keep.values()), "| bytes", os.path.getsize(out_json))
main()
