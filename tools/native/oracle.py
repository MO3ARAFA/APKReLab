#!/usr/bin/env python3
"""Compares ElfAnalyzer (via ElfDump.kt) with `readelf -W -h -l -d --dyn-syms` on every library in a directory.
usage: oracle.py <dir with .so files> <elfdump output tsv>"""
import subprocess, sys, os, re, collections
d, tsv = sys.argv[1], sys.argv[2]
mine = {}
for line in open(tsv):
    f = line.rstrip("\n").split("\t")
    mine[f[0]] = f

def readelf(path):
    out = subprocess.run(["readelf", "-W", "-h", "-l", "-d", "--dyn-syms", path], capture_output=True, text=True, errors="replace").stdout
    r = {"class": None, "type": None, "stack": None, "relro": False, "needed": [], "soname": "-", "bindnow": False, "textrel": False, "rpath": "-", "runpath": "-",
         "undef": [], "ndyn": 0, "exports": 0, "minalign": None}
    aligns = []
    sect = None
    for l in out.splitlines():
        if "Class:" in l: r["class"] = "64" if "ELF64" in l else "32"
        m = re.search(r"Type:\s+(\w+)", l)
        if m and r["type"] is None: r["type"] = m.group(1)
        if l.strip().startswith("GNU_STACK"):
            fl = re.split(r"\s+", l.strip())
            r["stack"] = fl[-3] if len(fl) >= 3 else ""      # flags are 'RW' or 'RWE' (before Align)
            r["stack_line"] = l
        if l.strip().startswith("GNU_RELRO"): r["relro"] = True
        if l.strip().startswith("LOAD"):
            aligns.append(int(re.split(r"\s+", l.strip())[-1], 16))
        m = re.search(r"\(NEEDED\).*\[(.*)\]", l)
        if m: r["needed"].append(m.group(1))
        m = re.search(r"\(SONAME\).*\[(.*)\]", l)
        if m: r["soname"] = m.group(1)
        m = re.search(r"\(RPATH\).*\[(.*)\]", l)
        if m: r["rpath"] = m.group(1)
        m = re.search(r"\(RUNPATH\).*\[(.*)\]", l)
        if m: r["runpath"] = m.group(1)
        if "(BIND_NOW)" in l: r["bindnow"] = True
        if re.search(r"\(FLAGS\).*\bBIND_NOW\b", l): r["bindnow"] = True
        if re.search(r"\(FLAGS_1\).*\bNOW\b", l): r["bindnow"] = True
        if "(TEXTREL)" in l or re.search(r"\(FLAGS\).*\bTEXTREL\b", l): r["textrel"] = True
        m = re.match(r"\s*Symbol table '\.dynsym' contains (\d+) entries", l)
        if m: sect = "dyn"; r["ndyn"] = int(m.group(1)); continue
        m = re.match(r"\s+\d+:\s+[0-9a-f]+\s+(?:\d+|0x[0-9a-f]+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s*(.*)$", l)   # readelf prints a big size in hex
        if m and sect == "dyn":
            typ, bind, vis, ndx, name = m.groups()
            name = name.strip().split("@")[0]
            if name:
                if ndx == "UND": r["undef"].append(name)
                elif bind != "LOCAL": r["exports"] += 1
    r["minalign"] = hex(min(aligns)) if aligns else "0x0"
    return r

bad = collections.Counter(); n = 0; notelf = 0; examples = collections.defaultdict(list)
for fn in sorted(os.listdir(d)):
    if not fn.endswith(".so"): continue
    n += 1
    f = mine.get(fn)
    r = readelf(os.path.join(d, fn))
    if f and f[1] == "NOT-ELF":
        if r["class"] is None: notelf += 1; continue            # readelf rejects it too (a zip stored as lib*.so)
        bad["parse-failed"] += 1; examples["parse-failed"].append(fn); continue
    if not f: bad["missing"] += 1; continue
    # f = name, class, type, gnuStack, stackExec, relroSeg, bindNow, textrel, soname, needed, dynsymCount, imports, exports, minAlign, rpath, runpath
    chk = {
        "class": (f[1], r["class"]),
        "stack-exec": (f[4] == "true", (r["stack"] or "").find("E") >= 0),
        "relro-segment": (f[5] == "true", r["relro"]),
        "bind-now": (f[6] == "true", r["bindnow"]),
        "textrel": (f[7] == "true", r["textrel"]),
        "soname": (f[8], r["soname"]),
        "needed": (sorted(filter(None, f[9].split(","))), sorted(r["needed"])),
        "dynsym-count": (int(f[10]), r["ndyn"]),
        "imports": (sorted(filter(None, f[11].split(","))), sorted(r["undef"])),
        "exports": (int(f[12]), r["exports"]),
        "min-load-align": (f[13], r["minalign"]),
        "rpath": (f[14], r["rpath"]), "runpath": (f[15], r["runpath"]),
    }
    for k, (a, b) in chk.items():
        if a != b:
            bad[k] += 1
            if len(examples[k]) < 3: examples[k].append(f"{fn}: mine={str(a)[:80]} readelf={str(b)[:80]}")
print("libraries:", n, "| not ELF for both (a zip stored as .so):", notelf, "| ELF compared:", n - notelf, "x 13 fields =", (n - notelf) * 13, "comparisons")
print("mismatching fields:", dict(bad) if bad else "none")
for k, v in examples.items(): print(" ", k, v)
