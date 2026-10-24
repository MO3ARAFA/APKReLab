#!/usr/bin/env python3
"""Replays the app's AI triage (MainActivity.triageWithAi, prompt copied verbatim) on the findings that have a HAND VERDICT in tools/benchmark/heldout_real/*.md and compares.
usage: ANTHROPIC_API_KEY=... eval.py <dump dir with <app>.jsonl from SandboxScanReach -Dtriage> <verdict_rows.json> <model> <runs> <out.json>
Only open-source apps are sent (their code is public). The key is read from the environment and never written anywhere."""
import json, os, re, sys, glob, urllib.request, urllib.error, concurrent.futures as cf, collections, time

dump_dir, rows_path, model, runs, out_path = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
KEY = os.environ["ANTHROPIC_API_KEY"]

NAMES = {"andotp": "andotp", "aps": "password store|android password store|aps", "breezy": "breezy", "catima": "catima", "davx5": "davx5", "fairemail": "fairemail", "jellyfin": "jellyfin",
         "kiwix": "kiwix", "libretube": "libretube", "markor": "markor", "mihon": "mihon", "monerujo": "monerujo", "ncnotes": "nextcloud note", "netguard": "netguard", "opentracks": "opentracks",
         "orbot": "orbot", "readyou": "read you", "seal": "seal", "session": "session", "shizuku": "shizuku", "tusky": "tusky"}
def app_key(name):
    n = name.lower()
    for k, pat in NAMES.items():
        if re.search(pat, n): return k
    return None

REACH_APPROX = ("Static call graph: APPROXIMATE path. No exact method-by-method path was found, but classes on the way call each other (class-level links skip fragments, lambdas and interface calls), "
                "so an exported component probably reaches this code. Not proven: check the path by hand.\n")
REACH_NO = ("Static call graph: no path from any exported component to this method was found within 6 calls (explicit launches and custom-action implicit Intents are followed; calls through "
            "interfaces, reflection or lambdas can be missed, so it may still be reachable; it may also be internal-only code).")
def reach_text(f):
    r = f["reach"]
    if r == "YES": return "Static call graph: reachable from an exported component.\n" + f["chain"]
    if r == "YES~": return REACH_APPROX + f["chain"]
    if r == "NO": return REACH_NO
    return "Static call graph: not available."

def prompt_of(f):
    return ("You are a senior Android application-security engineer triaging a static-analysis (SAST) finding. The code is smali from an app the user owns or is allowed to analyze.\n"
        f"Finding: {f['title']} [{f['severity']}] {f['cwe']}\nWhy flagged: {f['detail']}\nClass: {f['location']}\n\n" + reach_text(f) + "\n\n" + "Code (the enclosing method):\n" + f["code"] + "\n\n"
        "Decide whether this is a real, exploitable weakness. Consider: is the data attacker-controlled, is this library/boilerplate code, is the dangerous call actually used, are there mitigations in the code shown.\n"
        "Use TRUE_POSITIVE only if (a) the weakness is intrinsic (for example a hostname verifier that always returns true, a hardcoded key, cleartext traffic) or (b) the dangerous input demonstrably comes from an attacker-controlled source shown in the code or in the call chain. If the dangerous value is only a method parameter and you cannot show where it comes from, answer NEEDS_REVIEW. The confidence number must reflect what you could verify from the code shown (do not go above 70 when you could not see the source of the input).\n"
        "Return JSON only, no prose, no markdown fences: {\"verdict\":\"TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW\",\"confidence\":0,\"reason\":\"\",\"fix\":\"\"}\n"
        "Write reason and fix in plain English (one or two short sentences each); keep identifiers in English. When unsure use NEEDS_REVIEW instead of guessing.")

def call(prompt):
    body = json.dumps({"model": model, "max_tokens": 1500, "messages": [{"role": "user", "content": prompt}]}).encode()
    for attempt in range(4):
        req = urllib.request.Request("https://api.anthropic.com/v1/messages", body, {"x-api-key": KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                j = json.load(r); return "".join(b.get("text", "") for b in j["content"] if b["type"] == "text"), j["usage"]
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 529): time.sleep(3 * (attempt + 1)); continue
            return "HTTPERR %d %s" % (e.code, e.read()[:200].decode("utf-8", "replace")), {}
        except Exception as e:
            time.sleep(2)
    return "ERR", {}

def verdict_of(ans):
    m = re.search(r'"verdict"\s*:\s*"([A-Za-z_ ]+)"', ans)
    if not m: return "NOJSON"
    v = m.group(1).upper()
    return "FP" if "FALSE" in v else "TP" if "TRUE" in v else "REVIEW"

# ---- match the hand verdicts to dumped findings: the identifiers named in the hand-written card text against the finding's class, plus the words of its title
STOP = set("the and for with from this that into card notes reported not reads used uses used when only high entropy string near credential name scope cleartext".split())
def idents(text):
    return {t for t in re.findall(r"[A-Za-z_][A-Za-z0-9_$]{3,}", text) if t.lower() not in STOP}
dumps = {}
for p in glob.glob(os.path.join(dump_dir, "*.jsonl")):
    dumps[os.path.basename(p)[:-6]] = [json.loads(l) for l in open(p) if l.strip()]
rows = json.load(open(rows_path)); matched = []; unmatched = []
for r in rows:
    k = app_key(r["app"])
    if not k or k not in dumps: unmatched.append((r, "no dump for " + r["app"])); continue
    card = r["card"]; ids = idents(card); words = {w for w in re.findall(r"[a-z]{4,}", card.lower()) if w not in STOP}
    best = None; bscore = 0
    for f in dumps[k]:
        loc = f["location"]; simple = loc.split(".")[-1].split("$")[0]
        sc = 0
        for t in ids:
            tt = t.split("$")[0]
            if tt and (tt == simple or tt in loc.replace("$", ".").split(".")): sc += 3
        tl = f["title"].lower(); sc += sum(1 for w in words if w in tl)
        if sc > bscore: best, bscore = f, sc
    if best is None or bscore < 4: unmatched.append((r, "no confident match (best score %d)" % bscore)); continue
    matched.append((r, best))
print("hand-verdict rows", len(rows), "| matched to a dumped finding", len(matched), "| unmatched", len(unmatched))
truth = lambda v: "REAL" if re.match(r"^(TP|TRUE OBS)", v) else "NOT" if v.startswith("FP") else "DESIGN" if v.startswith("BY-DESIGN") else "OTHER"

def work(i):
    r, f = matched[i]; p = prompt_of(f); out = []
    for _ in range(runs): out.append(call(p))
    return i, out
res = {}
with cf.ThreadPoolExecutor(4) as ex:
    for i, out in ex.map(work, range(len(matched))): res[i] = out
tok = collections.Counter(); table = []
for i, (r, f) in enumerate(matched):
    vs = [verdict_of(a) for a, u in res[i]]
    for a, u in res[i]: tok["in"] += u.get("input_tokens", 0); tok["out"] += u.get("output_tokens", 0)
    table.append(dict(app=r["app"], card=r["card"][:80], matched=f["title"][:60] + " | " + f["location"][-48:], hand=r["verdict"][:24], truth=truth(r["verdict"]), ai=vs, reason=(res[i][0][0][:260] if res[i] else "")))
json.dump(dict(model=model, runs=runs, tokens=tok, table=table, unmatched=[(u[0]["app"], u[0]["card"][:70], u[1]) for u in unmatched]), open(out_path, "w"), indent=1)
print("tokens", dict(tok))
for t in ("REAL", "NOT", "DESIGN"):
    sub = [x for x in table if x["truth"] == t]; c = collections.Counter(v for x in sub for v in x["ai"])
    print(f"hand verdict {t:6s}: {len(sub):3d} cards x {runs} runs -> AI TP {c['TP']}, REVIEW {c['REVIEW']}, FP {c['FP']}, errors {sum(c[k] for k in c if k not in ('TP','FP','REVIEW'))}")
flips = sum(1 for x in table if len(set(x["ai"])) > 1); print("cards whose AI verdict differed between runs:", flips, "of", len(table))
