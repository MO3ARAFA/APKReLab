#!/bin/bash
# 2.0.0 step 1: download every APK of cases.json from f-droid.org (main repo or its archive) into $1 and check the SHA-256 the F-Droid index gives.
# A file whose hash differs is deleted and reported. No other source is used.
set -u; D=${1:?usage: fetch.sh <dir>}; mkdir -p "$D"
python3 -I -c "import json,os
for c in json.load(open(os.path.join('$(dirname "$0")','cases.json'))):
  for k in ('before','after'):
    a=c[k]; print(a['repo'], a['apkName'], a['sha256'])" | sort -u | while read -r repo name sha; do
  f="$D/$name"; base=https://f-droid.org/repo; [ "$repo" = archive ] && base=https://f-droid.org/archive
  [ -f "$f" ] && [ "$(sha256sum "$f" | cut -c1-64)" = "$sha" ] && { echo "ok (cached) $name"; continue; }
  curl -sS --retry 3 -o "$f" "$base/$name" || { echo "DOWNLOAD FAILED $name"; rm -f "$f"; continue; }
  if [ "$(sha256sum "$f" | cut -c1-64)" = "$sha" ]; then echo "ok $name"; else echo "HASH MISMATCH $name (deleted)"; rm -f "$f"; fi
done
