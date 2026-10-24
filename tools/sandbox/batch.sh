#!/bin/sh
# usage: batch.sh <tag> <snapdir> app1 app2 ...   (skips apps whose report already exists; status lines go to /tmp/batch.<tag>.status)
TAG=$1; SNAP=$2; shift 2
cd /home/claude/tc
STD=/home/claude/tc/kotlinc/lib/kotlin-stdlib.jar; JSON=/home/claude/tc/jsonx/usr/share/java/json-android.jar
for a in "$@"; do
  out=/home/claude/apps/$a-$TAG.md
  if [ -s "$out" ]; then echo "$a SKIP(exists)" >> /tmp/batch.$TAG.status; continue; fi
  echo "$a START $(date +%H:%M:%S)" >> /tmp/batch.$TAG.status
  timeout 1500 java -Xmx3200m -cp $SNAP/ss2:$SNAP/kout:$SNAP/irk:stubs_out:$STD:$JSON SandboxScanReachKt /home/claude/apps/dec_$a /home/claude/apps/$a.apk $out > /tmp/$a.$TAG.log 2>&1
  echo "$a DONE rc=$? $(date +%H:%M:%S)" >> /tmp/batch.$TAG.status
done
echo "BATCH-END $*" >> /tmp/batch.$TAG.status
