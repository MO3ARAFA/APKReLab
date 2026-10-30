#!/usr/bin/env bash
# Runs the `ir` unit tests (plain Java, no Gradle, no Android SDK) with javac and the JUnit stub of tools/sandbox.
# Termux: pkg install openjdk-21   (or 17) ;  proot Ubuntu: apt install openjdk-21-jdk-headless
# Verified on Linux x86-64 with JDK 21 (285 tests); NOT yet run on the phone: the first run there is the test.
set -euo pipefail
cd "$(dirname "$0")/../.."
OUT="${OUT:-$(mktemp -d)}"
JAVAC=(javac); command -v javac >/dev/null || JAVAC=(java -m jdk.compiler/com.sun.tools.javac.Main)   # a JRE with the compiler module but no javac launcher
"${JAVAC[@]}" -nowarn -d "$OUT" tools/sandbox/junit-stub/org/junit/*.java tools/sandbox/junit-stub/RunAll.java \
  $(find app/src/main/java/dev/apkrelab/ir -name '*.java') $(find app/src/test/java -name '*.java')
java -Xmx512m -cp "$OUT" RunAll "$OUT"
