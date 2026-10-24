plugins {
    id("com.android.application")
}

android {
    namespace = "dev.apkrelab"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.apkrelab"
        minSdk = 26
        targetSdk = 36
        versionCode = 211
        versionName = "0.103.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources.excludes += setOf("META-INF/*.kotlin_module", "META-INF/LICENSE*", "META-INF/NOTICE*", "META-INF/DEPENDENCIES", "META-INF/INDEX.LIST", "META-INF/versions/**", "META-INF/maven/**", "META-INF/AL2.0", "META-INF/LGPL2.1")
    }
}

dependencies {
    // Online: from Maven Central. If it fails offline, put ARSCLib.jar in app/libs/ and use the line below instead.
    implementation("io.github.reandroid:ARSCLib:1.4.0")
    // Google fork of smali/baksmali (namespace com.android.tools.smali, = smali 2.5.2 code base)
    implementation("com.android.tools.smali:smali-baksmali:3.0.9")
    // 0.10.1: smali assembler (same version as baksmali) + APK signer (stable apksig release)
    implementation("com.android.tools.smali:smali:3.0.9")
    implementation("com.android.tools.build:apksig:8.5.2")
    // 0.37.0: Java view (decompiles ONE class at a time, reached by reflection from JavaView.kt). If Gradle cannot resolve these two lines,
    // comment them out: the app still builds and the Java view button just says that jadx is not part of the build.
    implementation("io.github.skylot:jadx-core:1.5.0")
    implementation("io.github.skylot:jadx-dex-input:1.5.0")
    // implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.jar"))))
    // 0.50.1: JVM unit tests (app/src/test): ./gradlew testDebugUnitTest
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20231013")
}
