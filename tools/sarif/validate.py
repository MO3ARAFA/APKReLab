#!/usr/bin/env python3
"""Validates SARIF files against the official SARIF 2.1.0 JSON schema and checks what GitHub code scanning needs beyond it.
usage: validate.py <schema.json> <file.sarif.json> ...   (schema: https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json; pip install jsonschema)"""
import json, sys, jsonschema, collections
v = jsonschema.Draft4Validator(json.load(open(sys.argv[1])))
tot = collections.Counter()
for f in sys.argv[2:]:
    d = json.load(open(f)); errs = list(v.iter_errors(d)); r = d["runs"][0]
    rules = r["tool"]["driver"]["rules"]; res = r["results"]
    fp = collections.Counter(x["partialFingerprints"]["apkrelab/v1"] for x in res)
    n = len(res)
    row = dict(results=n, rules=len(rules), schema_errors=len(errs), duplicate_fingerprints=sum(c - 1 for c in fp.values() if c > 1),
               rules_without_security_severity=sum(1 for x in rules if "security-severity" not in x.get("properties", {})),
               results_without_region=sum(1 for x in res if "region" not in x["locations"][0]["physicalLocation"]),
               results_with_masvs=sum(1 for x in res if x["properties"].get("masvs")))
    tot.update(row); print(f.split("/")[-1].ljust(24), row, [e.message[:80] for e in errs[:1]])
print("TOTAL", dict(tot))
