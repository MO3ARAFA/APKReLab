package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** 0.88.0: library versions read from constants compiled into the library classes (real shapes taken from the 37-APK corpus). */
class VersionProbesTest {
    private val gson = ".class public final Lcom/google/gson/internal/GsonBuildConfig;\n.super Ljava/lang/Object;\n.field public static final VERSION:Ljava/lang/String; = \"2.8.6\"\n"

    @Test fun gsonBuildConfigVersion() {
        assertEquals("2.8.6", VersionProbes.fieldString(gson, "VERSION"))
        assertNull(VersionProbes.fieldString(gson.replace("2.8.6", "\${version}"), "VERSION"))          // an unsubstituted placeholder is not a version
        assertNull(VersionProbes.fieldString(gson.replace("2.8.6", "internal"), "VERSION"))
    }

    private val kotlinOld = """
        .method static constructor <clinit>()V
            .locals 4
            new-instance v0, Lkotlin/KotlinVersion;
            const/4 v1, 0x1
            const/4 v2, 0x3
            const/16 v3, 0x48
            invoke-direct {v0, v1, v2, v3}, Lkotlin/KotlinVersion;-><init>(III)V
            sput-object v0, Lkotlin/KotlinVersion;->CURRENT:Lkotlin/KotlinVersion;
            return-void
        .end method
    """.trimIndent()

    @Test fun kotlinVersionFromTheThreeConstants() {                                                    // InsecureShop: Kotlin 1.3.72
        assertEquals("1.3.72", VersionProbes.kotlinVersion(kotlinOld))
        val newer = kotlinOld.replace("0x1\n", "0x2\n").replace("0x3\n", "0x0\n").replace("0x48", "0x15")
        assertEquals("2.0.21", VersionProbes.kotlinVersion(newer))
    }

    @Test fun kotlinVersionIsNotInventedFromRegisters() {                                               // the (II)V constructor passes registers on: nothing to read
        val passThrough = ".method public constructor <init>(II)V\n    .locals 1\n    const/4 v0, 0x0\n    invoke-direct {p0, p1, p2, v0}, Lkotlin/KotlinVersion;-><init>(III)V\n    return-void\n.end method\n"
        assertNull(VersionProbes.kotlinVersion(passThrough))
    }

    @Test fun resolveTurnsTheCarrierClassesIntoLibraries() {
        val types = setOf("Lcom/google/gson/internal/GsonBuildConfig;", "Lkotlin/KotlinVersion;", "Lcom/other/Thing;", "Lio/sentry/BuildConfig;")
        val path = listOf(DetectedLib("io.sentry", "sentry-android", "?", "io/sentry/**", "package path"))
        val texts = mapOf("Lcom/google/gson/internal/GsonBuildConfig;" to gson, "Lkotlin/KotlinVersion;" to kotlinOld,
            "Lio/sentry/BuildConfig;" to ".field public static final VERSION_NAME:Ljava/lang/String; = \"6.28.0\"\n")
        assertEquals(setOf("Lcom/google/gson/internal/GsonBuildConfig;", "Lkotlin/KotlinVersion;", "Lio/sentry/BuildConfig;"), VersionProbes.wanted(types, path).toSet())
        val r = VersionProbes.resolve(types, path) { texts[it] }.associate { it.group + ":" + it.artifact to it.version }
        assertEquals(mapOf("com.google.code.gson:gson" to "2.8.6", "org.jetbrains.kotlin:kotlin-stdlib" to "1.3.72", "io.sentry:sentry-android" to "6.28.0"), r)
    }

    @Test fun aggregatesAndSubPackageBuildConfigsAreNotReadAsALibraryVersion() {                       // found on the 37 APKs: "androidx-libraries 1.0", "jitpack-libraries 1.6.0"
        val types = setOf("Lcom/google/firebase/installations/BuildConfig;", "Landroidx/core/BuildConfig;")
        val path = listOf(DetectedLib("com.google.firebase", "firebase-common", "?", "com/google/firebase/**", "package path"),
            DetectedLib("androidx", "androidx-libraries", "?", "androidx/**", "package path"))
        assertEquals(emptyList<String>(), VersionProbes.wanted(types, path))                            // sub-package BuildConfig / aggregate
        val withRoot = types + "Lcom/google/firebase/BuildConfig;"
        assertEquals(listOf("Lcom/google/firebase/BuildConfig;"), VersionProbes.wanted(withRoot, path))
    }

    @Test fun anAppsOwnBuildConfigIsNeverReadAsALibraryVersion() {                                      // only BuildConfig classes under a DETECTED library package are looked at
        val types = setOf("Lcom/myapp/BuildConfig;", "Lio/sentry/Sentry;")
        val path = listOf(DetectedLib("io.sentry", "sentry-android", "?", "io/sentry/**", "package path"))
        assertEquals(emptyList<String>(), VersionProbes.wanted(types, path))
        assertEquals(emptyList<DetectedLib>(), VersionProbes.resolve(types, path) { ".field public static final VERSION_NAME:Ljava/lang/String; = \"9.9.9\"\n" })
    }
}
