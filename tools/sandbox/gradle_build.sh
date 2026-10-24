#!/bin/bash
# 0.108.0: a real Gradle build of APKReLab on a Linux PC / container (the owner builds with Code on the Go; this is for verification).
# usage: tools/sandbox/gradle_build.sh [gradle tasks]   (default: :app:assembleDebug :app:testDebugUnitTest :app:lintDebug)
# Downloads once into ~/android-build: Gradle 9.8.2 (sha256 checked), Android command-line tools, platform 36, build-tools 36.1.0.
# Builds a COPY of the working tree in ~/apkbuild (private/, .git and build outputs are not copied).
set -e
B=$HOME/android-build; R=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p $B && cd $B
if [ ! -x gradle-9.8.2/bin/gradle ]; then
  curl -sSL -o gradle.zip https://services.gradle.org/distributions/gradle-9.8.2-bin.zip
  echo "$(curl -sSL https://services.gradle.org/distributions/gradle-9.8.2-bin.zip.sha256)  gradle.zip" | sha256sum -c -
  unzip -q gradle.zip
fi
export ANDROID_HOME=$B/sdk GRADLE_USER_HOME=$B/gh
if [ ! -d sdk/platforms/android-36 ]; then
  CLT=$(curl -s https://dl.google.com/android/repository/repository2-3.xml | grep -o 'commandlinetools-linux-[0-9]*_latest.zip' | sort -u -V | tail -1)
  curl -sSL -o clt.zip https://dl.google.com/android/repository/$CLT
  mkdir -p sdk/cmdline-tools && unzip -q -o clt.zip -d sdk/cmdline-tools && mv sdk/cmdline-tools/cmdline-tools sdk/cmdline-tools/latest
  yes | sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=$ANDROID_HOME --licenses > /dev/null 2>&1 || true
  yes | sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=$ANDROID_HOME "platforms/android-36" "build-tools/36.1.0" "platform-tools" > /dev/null
fi
# Maven Central may answer 429 to a busy IP: Google's mirror of it first (build-local, the project is unchanged)
mkdir -p $GRADLE_USER_HOME/init.d
cat > $GRADLE_USER_HOME/init.d/mirror.gradle <<'G'
def mirror = 'https://maven-central.storage-download.googleapis.com/maven2/'
def front = { repos -> def r = repos.maven { name = 'gcsCentralMirror'; url = mirror }; repos.remove(r); repos.addFirst(r) }
settingsEvaluated { s -> front(s.pluginManagement.repositories); front(s.dependencyResolutionManagement.repositories) }
allprojects { buildscript { front(repositories) } }
G
mkdir -p $HOME/apkbuild
(cd "$R" && tar --exclude=./private --exclude=./.git --exclude="*/build" --exclude=./.gradle --exclude=./tools/bin -cf - .) | (cd $HOME/apkbuild && tar -xf -)
cd $HOME/apkbuild
TASKS=${@:-":app:assembleDebug :app:testDebugUnitTest :app:lintDebug"}
$B/gradle-9.8.2/bin/gradle --no-daemon $TASKS
echo "APK: $HOME/apkbuild/app/build/outputs/apk/debug/app-debug.apk"
