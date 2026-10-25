package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.1.0: native methods matched to the library that implements them (static JNI name, or JNI_OnLoad of the library the class loads). */
class NativeBridge110Test {
    private fun reset() { NativeBridge.clear(); NativeBridge.clearApk() }

    private fun cls(type: String, natives: List<String>, load: String? = null): String {
        val sb = StringBuilder(".class public $type\n.super Ljava/lang/Object;\n")
        for (n in natives) sb.append(".method public static native ").append(n).append("\n.end method\n")
        if (load != null) sb.append(".method static constructor <clinit>()V\n    .locals 1\n    const-string v0, \"$load\"\n\n    .line 9\n    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n    return-void\n.end method\n")
        return sb.toString()
    }

    private fun lib(name: String, exports: List<String>) = ElfAnalyzer.parse(ElfTestBuilder.build(exports = exports))!!.let {
        NativeBridge.LibFacts(name, it.jniExports.toHashSet(), it.jniOnLoad, it.dangerous)
    }

    @Test fun jniNameMangling() {
        assertEquals("Java_com_x_My_1Class_00024Inner_run", NativeBridge.shortName(NativeBridge.Decl("Lcom/x/My_Class\$Inner;", "run", "()V")))
        assertEquals("Java_vs_C_d__I", NativeBridge.longName(NativeBridge.Decl("Lvs/C;", "d", "(I)Ljava/lang/String;")))
        assertEquals("Java_a_B_f__Ljava_lang_String_2_3B", NativeBridge.longName(NativeBridge.Decl("La/B;", "f", "(Ljava/lang/String;[B)I")))
    }

    @Test fun theElfReaderKeepsJniNamesAndJniOnLoad() {
        val info = ElfAnalyzer.parse(ElfTestBuilder.build(exports = listOf("Java_vs_C_d", "JNI_OnLoad", "helper")))!!
        assertEquals(listOf("Java_vs_C_d"), info.jniExports)
        assertTrue(info.jniOnLoad)
        assertTrue(!ElfAnalyzer.parse(ElfTestBuilder.build(exports = listOf("helper")))!!.jniOnLoad)          // twin
    }

    @Test fun staticDynamicAndUnknownBindings() {
        reset()
        NativeBridge.observe("Lvs/C;", cls("Lvs/C;", listOf("d(I)Ljava/lang/String;")))
        NativeBridge.observe("Lcom/x/Crypto;", cls("Lcom/x/Crypto;", listOf("seal([B)[B"), load = "guard"))
        NativeBridge.observe("Lcom/x/Other;", cls("Lcom/x/Other;", listOf("ping()V")))
        val libs = listOf(lib("libvs.so", listOf("Java_vs_C_d__I")), lib("libguard.so", listOf("JNI_OnLoad")), lib("libplain.so", listOf("helper")))
        val b = NativeBridge.bindings(libs).associateBy { it.decl.name }
        assertEquals(NativeBridge.Kind.STATIC, b["d"]!!.kind); assertEquals(listOf("libvs.so"), b["d"]!!.libs)            // the overloaded (long) JNI name
        assertEquals(NativeBridge.Kind.DYNAMIC, b["seal"]!!.kind); assertEquals(listOf("libguard.so"), b["seal"]!!.libs)    // its own loadLibrary + JNI_OnLoad
        assertEquals(NativeBridge.Kind.DYNAMIC_CANDIDATES, b["ping"]!!.kind); assertEquals(listOf("libguard.so"), b["ping"]!!.libs)   // twin: loads nothing, no export
        // twin: the library a class loads has no JNI_OnLoad -> not claimed as its binding
        val noOnLoad = NativeBridge.bindings(listOf(lib("libguard.so", listOf("helper")))).single { it.decl.name == "seal" }
        assertEquals(NativeBridge.Kind.DYNAMIC_CANDIDATES, noOnLoad.kind); assertTrue(noOnLoad.libs.isEmpty())
        // twin: no library at all (a split APK not imported)
        assertTrue(NativeBridge.bindings(emptyList()).all { it.kind == NativeBridge.Kind.NO_LIBRARY })
    }

    @Test fun soLoaderCountsAsLoading() {
        reset()
        NativeBridge.observe("Lcom/x/Rn;", cls("Lcom/x/Rn;", listOf("init()V")).replace(".class public Lcom/x/Rn;", ".class public Lcom/x/Rn;") +
            ".method static boot()V\n    .locals 1\n    const-string v0, \"rnx\"\n    invoke-static {v0}, Lcom/facebook/soloader/SoLoader;->loadLibrary(Ljava/lang/String;)Z\n    return-void\n.end method\n")
        val b = NativeBridge.bindings(listOf(lib("librnx.so", listOf("JNI_OnLoad")), lib("libother.so", listOf("JNI_OnLoad")))).single()
        assertEquals(NativeBridge.Kind.DYNAMIC, b.kind); assertEquals(listOf("librnx.so"), b.libs)
    }

    @Test fun sectionAndBriefNameTheLibrary() {
        reset()
        NativeBridge.observe("Lcom/x/Crypto;", cls("Lcom/x/Crypto;", listOf("seal([B)[B"), load = "guard"))
        NativeBridge.libs = listOf(lib("libguard.so", listOf("JNI_OnLoad")).let { NativeBridge.LibFacts(it.name, it.jniExports, it.jniOnLoad, listOf("strcpy")) })
        val md = NativeBridge.section("com.x")
        assertTrue(md, md.contains("| `com.x.Crypto.seal([B)` | registered at run time by libguard.so") && md.contains("| strcpy |"))
        assertTrue(NativeBridge.brief("com.x").contains("com.x.Crypto.seal -> registered at run time by libguard.so"))
        assertTrue(NativeBridge.forClass("Lcom/x/Crypto;").startsWith("native seal([B)[B: registered at run time by libguard.so"))
    }
}
