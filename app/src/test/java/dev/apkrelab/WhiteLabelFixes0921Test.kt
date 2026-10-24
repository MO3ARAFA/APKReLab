package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.92.1: findings from the WE Wallet device report (a white-label app obfuscated by a commercial tool). Every fix has a twin that must not change. */
class WhiteLabelFixes0921Test {
    private fun readable(prefix: String, n: Int) = (1..n).map { "L$prefix/Class$it;" }
    private fun renamed(n: Int) = (1..n).map { "L_find${it}Thing;" }                 // DexGuard: default package, names of methods

    @Test fun theComponentsDecideTheCodePackageOfAWhiteLabelApp() {
        // manifest package com.TE.WEWallet; 99 components and the readable code under com.emeint; 60 generated R classes under the manifest package; most classes renamed
        val types = readable("com/emeint/android/mwallet2/view", 100) + renamed(8000) + (1..60).map { "Lcom/TE/WEWallet/R\$id$it;" } + listOf("Lcom/TE/WEWallet/R;", "Lcom/TE/WEWallet/BuildConfig;")
        val comps = (1..99).map { "Lcom/emeint/android/mwallet2/view/activities/A$it;" } + (1..6).map { "Lcom/TE/WEWallet/Brand$it;" }
        assertEquals("com.emeint", SecurityScanner.codePackage(types, "com.TE.WEWallet", comps))
        // the same without the components keeps the old answer (the manifest package when its prefix looks big): the components are the new evidence
        val old = SecurityScanner.codePackage(types + (1..30).map { "Lcom/TE/WEWallet/ui/B$it;" }, "com.TE.WEWallet")
        assertEquals("com.TE.WEWallet", old)
    }

    @Test fun anOrdinaryAppAndALibraryComponentAreNotAffected() {
        val types = readable("com/myapp/ui", 300) + readable("com/squareup/leakcanary", 40)
        // the app's components are in its own package: the manifest package stays
        assertEquals("com.myapp", SecurityScanner.codePackage(types, "com.myapp", (1..8).map { "Lcom/myapp/ui/Act$it;" }))
        // a library's activity (LeakCanary) among the components does not move the code package
        assertEquals("com.myapp", SecurityScanner.codePackage(types, "com.myapp", (1..8).map { "Lcom/myapp/ui/Act$it;" } + listOf("Lleakcanary/internal/activity/LeakActivity;")))
        // fewer than 3 components outside the manifest package: no move
        assertEquals("com.myapp", SecurityScanner.codePackage(types, "com.myapp", listOf("Lcom/other/lib/X;", "Lcom/other/lib/Y;")))
    }

    @Test fun generatedRClassesDoNotMakeTheManifestPackageLookLikeTheCode() {
        val types = readable("org/qosp/notes", 300) + (1..40).map { "Lio/github/quillpad/R\$layout$it;" }
        assertEquals("org.qosp", SecurityScanner.codePackage(types, "io.github.quillpad"))           // Quillpad-like: the code is elsewhere
    }

    @Test fun manifestComponentNamesBecomeSmaliTypes() {
        val xml = "<manifest package=\"com.TE.WEWallet\"><application><activity android:name=\"com.emeint.android.mwallet2.view.Main\"/><service android:name=\".Svc\"/><receiver android:name=\"Rcv\"/></application></manifest>"
        assertEquals(listOf("Lcom/emeint/android/mwallet2/view/Main;", "Lcom/TE/WEWallet/Svc;", "Lcom/TE/WEWallet/Rcv;"), ManifestContext(xml).componentTypes("com.TE.WEWallet"))
    }

    @Test fun sqlcipherAndOrmliteAreLibrariesAndEveryPackageTheScaScannerKnowsIsToo() {
        assertEquals(SecurityScanner.Scope.LIB, SecurityScanner.scopeOf("Lnet/sqlcipher/CursorWindow;", "com.emeint"))
        assertEquals(SecurityScanner.Scope.LIB, SecurityScanner.scopeOf("Lcom/j256/ormlite/field/types/SerializableType;", "com.emeint"))
        for (p in ScaScanner.packagePrefixes()) assertTrue("the SCA scanner knows $p but the scope classifier does not", SecurityScanner.scopeOf("L" + p + "Foo;", "com.myapp") == SecurityScanner.Scope.LIB)
        assertEquals(SecurityScanner.Scope.OTHER, SecurityScanner.scopeOf("Lcom/emeint/android/mwallet2/view/Main;", "com.TE.WEWallet"))    // the white-label app's own code is not a library
    }

    @Test fun sbomAndTableLeaveOutGroupsOfLibrariesWithAMadeUpArtifact() {
        val inv = listOf(DetectedLib("androidx", "androidx-libraries", "?", "androidx/**", "package path"), DetectedLib("com.github", "jitpack-libraries", "?", "p", "package path"),
            DetectedLib("com.google.code.gson", "gson", "2.8.8", "x", "code constant"))
        assertTrue(LibraryScanner.isAggregate(inv[0])); assertFalse(LibraryScanner.isAggregate(inv[2]))
        val md = ReportBuilder.scaSection(inv)
        assertFalse(md.contains("| androidx:androidx-libraries")); assertTrue(md.contains("gson")); assertTrue(md.contains("Also present, not listed as components")); assertTrue(md, md.contains("androidx (Jetpack)")); assertFalse(md.contains("androidx:androidx-libraries"))
    }

    @Test fun valuesThatAreNotCredentialsAreNotReportedWhateverTheFieldIsCalled() {
        assertTrue(SecurityScanner.looksLikeName("type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey"))     // Tink type URL
        assertTrue(SecurityScanner.looksLikeName("(?i)^.*(confirm|retype)[ _-]?(password|pwd).*\$"))                       // a regular expression
        assertTrue(SecurityScanner.looksLikeName("id_token,signed_request,graph_domain"))                                  // Facebook response types
        // twins: real-looking secrets stay
        assertFalse(SecurityScanner.looksLikeName("kQ3vN8zL1xW5cR9tY2bH7mD4pS6fG0aJ"))
        assertFalse(SecurityScanner.looksLikeName("Zq8vT2LmX9pR4wK7nB1cY6hJ3fD5sG0aE"))
        assertFalse(SecurityScanner.looksLikeName("api.example.com/v1/KkQ3vN8zL1xW5cR9tY2bH7mD4pS6fG0aJq8vT2LmX9pR4wK7nB1c/a/b/c/d/e"))   // a deep path with a token in it
    }

    @Test fun componentsInTheSamePrefixButOutsideTheFullManifestPackageGiveTheTwoSegmentPrefix() {              // Shizuku: found by running the 37 real apps before and after
        val types = readable("moe/shizuku/manager/ui", 200) + readable("rikka/shizuku", 60)
        val comps = (1..6).map { "Lmoe/shizuku/manager/ui/Act$it;" }
        assertEquals("moe.shizuku", SecurityScanner.codePackage(types, "moe.shizuku.privileged.api", comps))
        // components under the full manifest package: the manifest package, as before
        val own = readable("com/myapp/feature", 200)
        assertEquals("com.myapp", SecurityScanner.codePackage(own, "com.myapp", (1..5).map { "Lcom/myapp/feature/A$it;" }))
    }

    @Test fun aRepackagedBouncyCastleLargerThanTheReadableAppCodeIsNotTheCodePackage() {              // the real wallet APK: org.bouncycastle2 (894 classes) beat com.emeint (829); com.TE had no class at all
        val types = readable("org/bouncycastle2/crypto", 894) + readable("com/emeint/android/mwallet2/view", 829) + renamed(8000) + readable("com/sleepbot/datetimepicker", 20)
        assertEquals("com.emeint", SecurityScanner.codePackage(types, "com.TE.WEWallet"))                // even without the components rule
        assertEquals(SecurityScanner.Scope.LIB, SecurityScanner.scopeOf("Lorg/bouncycastle2/crypto/Foo;", "com.emeint"))
        assertEquals(SecurityScanner.Scope.LIB, SecurityScanner.scopeOf("Lcom/sleepbot/datetimepicker/time/Foo;", "com.emeint"))
        assertEquals(SecurityScanner.Scope.APP, SecurityScanner.scopeOf("Lcom/emeint/android/mwallet2/view/Foo;", "com.emeint"))
    }
}

