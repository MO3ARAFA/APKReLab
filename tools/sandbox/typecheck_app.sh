#!/usr/bin/env bash
# 0.102.0: a real type check of the WHOLE app (MainActivity.kt, Ui.kt ... included) without Gradle: kotlinc against Robolectric's android-all-16 jar and the real
# library jars. Only the generated `R` class is unresolved (6 messages at 0.102.0); anything else is a real compile error. It is NOT a Gradle build (no resources, no
# D8, no lint) and nothing runs. Setup (about 300 MB of jars in ~/tc/libs and ~/tc/android-all.jar, from Maven Central / dl.google.com):
#   android-all  org/robolectric/android-all/16-robolectric-13921718   smali 3.0.9 (smali, smali-baksmali, smali-dexlib2, smali-util) from dl.google.com/dl/android/maven2/com/android/tools/smali
#   io/github/reandroid/ARSCLib 1.4.0, io/github/skylot/jadx-core 1.5.0, com/android/tools/build/apksig 8.5.2 (dl.google.com), guava-33 (android), jcommander 1.82,
#   json-android.jar (Debian libandroid-json-org-java), and ~/tc/irk = javac output of app/src/main/java/dev/apkrelab/ir
# full type check of app/src/main (Kotlin + the one Java file) against android-all 16 + the real libraries; prints the error list
export PATH=$HOME/tc/kotlinc/bin:$PATH
TC=$HOME/tc; R=${1:-/home/user/APKReLab}
CP=$TC/android-all.jar:$TC/deb/x/usr/share/java/json-android.jar:$TC/irk:$(ls $TC/libs/*.jar | tr '\n' ':')
rm -rf $TC/irk && mkdir -p $TC/irk && javac -nowarn -d $TC/irk $(find $R/app/src/main/java/dev/apkrelab/ir -name '*.java') 2>&1 | grep -v "Picked up\|^Note"   # 0.104.0: always the CURRENT ir classes (a stale copy gave false errors)
rm -rf $TC/pc/outT; mkdir -p $TC/pc/outT
kotlinc -nowarn -J-Xmx3g -cp "$CP" -d $TC/pc/outT $(find $R/app/src/main -name '*.kt') $R/app/src/main/java/dev/apkrelab/ManifestPatcher.java 2>&1 | grep "error:" | sed "s#$R/##"
