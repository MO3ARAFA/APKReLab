package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** 1.1.0: firebase-common's version from its component registrar (shape of Axis Pay 3.0.1's R8 build: the factory renamed, the two constants kept). */
class VersionProbes110Test {
    private fun registrar(value: String) = """
        .class public Lcom/google/firebase/FirebaseCommonRegistrar;
        .super Ljava/lang/Object;
        .method public final getComponents()Ljava/util/List;
            .locals 3
            const-string v2, "fire-android"
            invoke-static {v2, v1}, Lqx8;->a(Ljava/lang/String;Ljava/lang/String;)Ldo0;
            move-result-object v1
            const-string v1, "fire-core"
            $value
            invoke-static {v1, v2}, Lqx8;->a(Ljava/lang/String;Ljava/lang/String;)Ldo0;
            move-result-object v1
            return-object v0
        .end method
    """.trimIndent()

    @Test fun theRegistrarConstantIsTheVersion() {
        assertEquals("21.0.0", VersionProbes.registrarVersion(registrar("const-string v2, \"21.0.0\""), "fire-core"))
        val types = setOf("Lcom/google/firebase/FirebaseCommonRegistrar;")
        val path = listOf(DetectedLib("com.google.firebase", "firebase-common", "?", "com/google/firebase/**", "package path"))
        val r = VersionProbes.resolve(types, path) { registrar("const-string v2, \"21.0.0\"") }
        assertEquals(listOf("com.google.firebase:firebase-common 21.0.0"), r.map { it.group + ":" + it.artifact + " " + it.version })
    }

    @Test fun aValueThatIsNotAConstantIsNotRead() {
        // twins: the value from a field, a non-version text, and another key
        assertNull(VersionProbes.registrarVersion(registrar("sget-object v2, Lx/Y;->v:Ljava/lang/String;"), "fire-core"))
        assertNull(VersionProbes.registrarVersion(registrar("const-string v2, \"unknown\""), "fire-core"))
        assertNull(VersionProbes.registrarVersion(registrar("const-string v2, \"21.0.0\""), "fire-android"))     // its value is a register from a call (the SDK level)
    }
}
