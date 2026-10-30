#!/bin/bash
# 1.2.0: release self-check. Scans the benchmark APKs with the current sources (SandboxScan = the app's Kotlin pipeline without the UI) and scores the reports
# with tools/sandbox/self_check.py (recall per app with card evidence, judged true positives against the last release, flow set new / lost).
#   BENCH_APKS=<dir with <package>.apk>  KOUT=<compiled Kotlin classes>  IRK=<compiled ir classes>  SS=<compiled SandboxScan>  tools/sandbox/self_check.sh [--write-baseline]
# KOUT / IRK: the ones ~/tc/ktest.sh builds (KW=<dir>: $KW/kout, $KW/irk); SS: kotlinc -Xfriend-paths=$KOUT -cp $KOUT:$IRK:... tools/sandbox/SandboxScan.kt -d $SS.
# Work files go to a private temporary directory (removed at the end). Exit code 1 = a judged true positive was lost or an app could not be scanned.
set -u
R=$(cd "$(dirname "$0")/../.." && pwd)
: "${BENCH_APKS:?set BENCH_APKS to the directory holding the benchmark APKs (<package>.apk)}"
: "${KOUT:?}" "${IRK:?}" "${SS:?}"
LIBS=${LIBS:-$HOME/tc/libs}; STD=${STD:-$HOME/tc/kotlinc/lib/kotlin-stdlib.jar}; JSON=${JSON:-$HOME/tc/deb/x/usr/share/java/json-android.jar}; STUBS=${STUBS:-$HOME/tc/stubs_out}
W=$(mktemp -d "${TMPDIR:-/tmp}/selfcheck.XXXXXX"); trap 'rm -rf "$W"' EXIT
mkdir -p "$W/reports"
for pkg in $(python3 -c "import json;print(' '.join(a['package'] for a in json.load(open('$R/tools/benchmark/self_check_apps.json'))))"); do
  apk="$BENCH_APKS/$pkg.apk"
  [ -f "$apk" ] || { echo "missing $apk"; continue; }
  mkdir -p "$W/$pkg/dex" && unzip -q -o "$apk" 'classes*.dex' -d "$W/$pkg/dex"
  for d in "$W/$pkg"/dex/classes*.dex; do java -cp "$(ls $LIBS/*.jar | tr '\n' ':')" com.android.tools.smali.baksmali.Main d "$d" -o "$W/$pkg/smali" >/dev/null 2>&1; done
  java -Xmx2g -cp "$SS:$KOUT:$IRK:$STUBS:$STD:$JSON" SandboxScanKt "$W/$pkg/smali" "$apk" "$W/reports/$pkg.md" > "$W/$pkg.log" 2>&1 || echo "scan failed: $pkg (see the log in the run's output above)"
done
python3 "$R/tools/sandbox/self_check.py" --reports "$W/reports" "$@"
