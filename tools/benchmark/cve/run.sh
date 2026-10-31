#!/bin/bash
# 2.0.0 step 1: scan every APK of cases.json once with SandboxScan and write <out>/<id>_before.md / <id>_after.md.
#   KW=<dir with kout, irk, ss>  run.sh <apk dir> <out dir>      (an APK already scanned in <out>/apk/ is not scanned again)
set -u; A=${1:?apk dir}; O=${2:?out dir}; : "${KW:?}"
TC=$HOME/tc; LIBS=$TC/libs; STD=$TC/kotlinc/lib/kotlin-stdlib.jar; JSON=$TC/deb/x/usr/share/java/json-android.jar
W=$(mktemp -d "${TMPDIR:-/tmp}/cverun.XXXXXX"); trap 'rm -rf "$W"' EXIT; mkdir -p "$O/apk" "$O/log"
R=$(cd "$(dirname "$0")" && pwd)
python3 -I -c "import json
for c in json.load(open('$R/cases.json')):
  for k in ('before','after'): print(c['id'], k, c[k]['apkName'])" | while read -r id k name; do
  rep="$O/apk/${name%.apk}.md"
  if [ ! -s "$rep" ] && [ -f "$A/$name" ]; then
    rm -rf "$W/s"; mkdir -p "$W/s/dex"; unzip -q -o "$A/$name" 'classes*.dex' -d "$W/s/dex"
    for d in "$W"/s/dex/classes*.dex; do java -cp "$(ls $LIBS/*.jar | tr '\n' ':')" com.android.tools.smali.baksmali.Main d "$d" -o "$W/s/smali" >/dev/null 2>&1; done
    s=$(date +%s)
    timeout 2400 java -Xmx3200m -cp "$KW/ss:$KW/kout:$KW/irk:$TC/stubs_out:$STD:$JSON" SandboxScanKt "$W/s/smali" "$A/$name" "$rep" > "$O/log/${name%.apk}.log" 2>&1 || echo "scan failed: $name"
    echo "scanned $name in $(( $(date +%s) - s )) s"
  fi
  [ -s "$rep" ] && cp "$rep" "$O/${id}_$k.md"
done
