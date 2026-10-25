#!/bin/bash
# 1.0.0: rebuilds the R8 ground truth of ir/IrMergeTagsTest (FX_* classes): javac + R8 8.13.25 (tools/bin/r8.jar) + baksmali 3.0.9.
# usage: build.sh <out-dir> [neg]   - "neg" drops the //POS-BEGIN .. //POS-END block (the caller's session id is never written: only the merge false positive is left)
# Needs: an android.jar (platform 36: ANDROID_JAR=...), and the baksmali jars in BAKSMALI_CP (smali-baksmali, smali-dexlib2, smali-util, guava, jcommander).
set -e
HERE=$(cd "$(dirname "$0")" && pwd); OUT=$1; mkdir -p "$OUT/src/fx" "$OUT/classes" "$OUT/dex"
if [ "$2" = neg ]; then sed '/\/\/POS-BEGIN/,/\/\/POS-END/d' "$HERE/MainActivity.java" > "$OUT/src/fx/MainActivity.java"; else cp "$HERE/MainActivity.java" "$OUT/src/fx/"; fi
javac -nowarn -source 11 -target 11 -cp "$ANDROID_JAR" -d "$OUT/classes" "$OUT/src/fx/MainActivity.java"
(cd "$OUT/classes" && jar cf ../in.jar fx)
java -cp "$HERE/../../bin/r8.jar" com.android.tools.r8.R8 --release --min-api 26 --lib "$ANDROID_JAR" --pg-conf "$HERE/rules.pro" --output "$OUT/dex" "$OUT/in.jar"
java -cp "$BAKSMALI_CP" com.android.tools.smali.baksmali.Main d "$OUT/dex/classes.dex" -o "$OUT/smali"
grep -l "synthetic" "$OUT"/smali/fx/*.smali
