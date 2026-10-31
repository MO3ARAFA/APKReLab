#!/bin/sh
# Fails when the tracked tree holds an app binary or a file over 1024 KB
# (the rules of .githooks/pre-commit, applied to the whole tree; CI runs it first).
# usage: tools/ci/hygiene_check.sh [repo-dir]   (default: the repository that holds this script)
cd "${1:-$(dirname "$0")/../..}" || exit 2
max=1048576
out=$(mktemp) || exit 2
git ls-files | while IFS= read -r f; do
  case "$f" in
    *.apk|*.apks|*.xapk|*.apkm|*.aab|*.dex|*.odex|*.vdex|*.oat|*.so|*.APK|*.DEX|*.SO)
      echo "hygiene: app binary in the tree: $f" ;;
  esac
  if [ -f "$f" ]; then
    size=$(wc -c < "$f" | tr -d ' ')
    if [ "$size" -gt "$max" ]; then echo "hygiene: $f is $size bytes (> 1024 KB)"; fi
  fi
done > "$out"
if [ -s "$out" ]; then cat "$out"; rm -f "$out"; exit 1; fi
rm -f "$out"
echo "hygiene: OK ($(git ls-files | wc -l | tr -d ' ') tracked files, no app binary, none over 1024 KB)"
