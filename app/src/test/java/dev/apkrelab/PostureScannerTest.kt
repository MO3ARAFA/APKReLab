package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.91.0: the posture signals, each with the twin that must not count, and the app / library scope of a hit. */
class PostureScannerTest {
    private val pkg = "com.myapp"
    private fun cls(type: String, body: String, header: String = ".class public $type\n.super Ljava/lang/Object;\n") = header + body + "\n"
    private fun m(body: String) = ".method public static t()V\n    .locals 3\n$body    return-void\n.end method\n"
    private fun observe(type: String, text: String) = PostureScanner.observe(type, text, pkg)
    private fun row(id: String) = PostureScanner.rows().first { it.sig.id == id }
    private fun fresh() = PostureScanner.clear()

    @Test fun rootPathsInAppCodeAreAppAndTheSameCheckInAnSdkIsLibraryOnly() {
        fresh()
        val body = m("    const-string v0, \"/system/xbin/su\"\n")
        observe("Lcom/myapp/Guard;", cls("Lcom/myapp/Guard;", body))
        observe("Lcom/google/firebase/Ads;", cls("Lcom/google/firebase/Ads;", body))
        val r = row("root-paths")
        assertEquals(listOf("Lcom/myapp/Guard;"), r.app); assertEquals(listOf("Lcom/google/firebase/Ads;"), r.lib)
        fresh(); observe("Lcom/google/firebase/Ads;", cls("Lcom/google/firebase/Ads;", body))
        assertTrue(row("root-paths").app.isEmpty()); assertEquals(1, row("root-paths").lib.size)                   // "library only": no false feeling of protection
        assertTrue(PostureScanner.section().contains("library only (1)"))
    }

    @Test fun rootBeerIsACallFromTheAppNotTheLibraryItself() {
        fresh()
        observe("Lcom/myapp/Check;", cls("Lcom/myapp/Check;", m("    invoke-virtual {v0}, Lcom/scottyab/rootbeer/RootBeer;->isRooted()Z\n")))
        assertEquals(1, row("root-lib").app.size)
        fresh()
        observe("Lcom/scottyab/rootbeer/RootBeer;", cls("Lcom/scottyab/rootbeer/RootBeer;", m("    invoke-virtual {v0}, Lcom/scottyab/rootbeer/RootBeer;->isRooted()Z\n"), ".class public Lcom/scottyab/rootbeer/RootBeer;\n.super Ljava/lang/Object;\n"))
        assertTrue(row("root-lib").app.isEmpty() && row("root-lib").lib.isEmpty())
    }

    @Test fun debuggerFlagSecureAndEmulatorSignals() {
        fresh()
        observe("Lcom/myapp/A;", cls("Lcom/myapp/A;", m("    invoke-static {}, Landroid/os/Debug;->isDebuggerConnected()Z\n")))
        assertEquals(1, row("debugger").app.size)
        observe("Lcom/myapp/B;", cls("Lcom/myapp/B;", ".method public onCreate()V\n    .locals 2\n    invoke-virtual {p0}, Lcom/myapp/B;->getWindow()Landroid/view/Window;\n    const/16 v1, 0x2000\n    invoke-virtual {v0, v1}, Landroid/view/Window;->addFlags(I)V\n    return-void\n.end method\n"))
        assertEquals(listOf("Lcom/myapp/B;"), row("flag-secure").app)
        observe("Lcom/myapp/C;", cls("Lcom/myapp/C;", ".method public onCreate()V\n    .locals 2\n    const/16 v1, 0x80\n    invoke-virtual {v0, v1}, Landroid/view/Window;->addFlags(I)V\n    return-void\n.end method\n"))       // keep screen on
        observe("Lcom/myapp/D;", cls("Lcom/myapp/D;", ".method public a()V\n    .locals 1\n    const/16 v1, 0x2000\n    return-void\n.end method\n.method public b()V\n    .locals 1\n    invoke-virtual {v0, v1}, Landroid/view/Window;->addFlags(I)V\n    return-void\n.end method\n"))   // another method
        assertEquals(1, row("flag-secure").app.size)
        observe("Lcom/myapp/E;", cls("Lcom/myapp/E;", m("    sget-object v0, Landroid/os/Build;->FINGERPRINT:Ljava/lang/String;\n    const-string v1, \"generic\"\n    const-string v2, \"goldfish\"\n    const-string v1, \"ranchu\"\n")))
        assertEquals(1, row("emulator").app.size)
        observe("Lcom/myapp/F;", cls("Lcom/myapp/F;", m("    sget-object v0, Landroid/os/Build;->MODEL:Ljava/lang/String;\n    const-string v1, \"goldfish\"\n")))              // one token is not a detector
        assertEquals(1, row("emulator").app.size)
    }

    @Test fun pinningInCodeIsTheBuilderCallNotTheLibraryInternals() {
        fresh()
        observe("Lcom/myapp/Net;", cls("Lcom/myapp/Net;", m("    invoke-virtual {v0, v1, v2}, Lokhttp3/CertificatePinner\$Builder;->add(Ljava/lang/String;[Ljava/lang/String;)Lokhttp3/CertificatePinner\$Builder;\n")))
        observe("Lcom/myapp/Other;", cls("Lcom/myapp/Other;", m("    invoke-virtual {v0, v1, v2}, Lokhttp3/CertificatePinner;->check(Ljava/lang/String;Ljava/util/List;)V\n")))
        assertEquals(listOf("Lcom/myapp/Net;"), row("pin-okhttp").app)
        val pinTm = ".class public Lcom/myapp/Tm;\n.super Ljava/lang/Object;\n.implements Ljavax/net/ssl/X509TrustManager;\n.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V\n    .locals 3\n    invoke-virtual {v0}, Ljava/security/cert/X509Certificate;->getPublicKey()Ljava/security/PublicKey;\n    return-void\n.end method\n"
        val trustAll = ".class public Lcom/myapp/All;\n.super Ljava/lang/Object;\n.implements Ljavax/net/ssl/X509TrustManager;\n.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V\n    .locals 0\n    return-void\n.end method\n"
        observe("Lcom/myapp/Tm;", pinTm); observe("Lcom/myapp/All;", trustAll)
        assertEquals(listOf("Lcom/myapp/Tm;"), row("pin-custom").app)
    }

    @Test fun signatureInstallerAndAttestationSignals() {
        fresh()
        observe("Lcom/myapp/S;", cls("Lcom/myapp/S;", m("    invoke-virtual {v0}, Landroid/content/pm/Signature;->toByteArray()[B\n    invoke-virtual {v1, v2}, Landroid/content/pm/PackageManager;->getInstallerPackageName(Ljava/lang/String;)Ljava/lang/String;\n")))
        assertEquals(1, row("signature").app.size); assertEquals(1, row("installer").app.size)
        observe("Lcom/myapp/P;", cls("Lcom/myapp/P;", m("    invoke-static {v0}, Lcom/google/android/play/core/integrity/IntegrityManagerFactory;->create(Landroid/content/Context;)V\n")))
        assertEquals(1, row("play-integrity").app.size)
        observe("Lcom/myapp/N;", cls("Lcom/myapp/N;", m("    invoke-static {v0}, Lcom/google/android/gms/safetynet/SafetyNet;->getClient(Landroid/content/Context;)V\n")))
        val f = PostureScanner.findings()
        assertEquals(SecurityScanner.Severity.LOW, f.first { it.ruleId == "posture-safetynet-retired" }.severity)
        assertEquals(SecurityScanner.Severity.INFO, f.first { it.ruleId == "posture-summary" }.severity)
        fresh(); observe("Lcom/myapp/X;", cls("Lcom/myapp/X;", m("    const-string v0, \"nothing\"\n")))
        assertTrue(PostureScanner.findings().none { it.ruleId == "posture-safetynet-retired" })                        // twin
    }

    @Test fun authenticationUpdateAndPrivacySignals() {                                                                      // 1.0.0: MASVS-AUTH, CODE-2, PRIVACY rows
        fresh()
        observe("Lcom/myapp/Bio;", cls("Lcom/myapp/Bio;", m("    invoke-virtual {v0, v1, v2}, Landroidx/biometric/BiometricPrompt;->authenticate(Landroidx/biometric/BiometricPrompt\$PromptInfo;Landroidx/biometric/BiometricPrompt\$CryptoObject;)V\n" +
            "    invoke-virtual {v0, v1}, Landroid/security/keystore/KeyGenParameterSpec\$Builder;->setUserAuthenticationRequired(Z)Landroid/security/keystore/KeyGenParameterSpec\$Builder;\n")))
        assertEquals(1, row("bio-crypto").app.size); assertEquals(1, row("key-userauth").app.size)
        assertTrue(row("bio-event").app.isEmpty())                                                                      // twin: a prompt bound to a key is not the event-only one
        observe("Lcom/myapp/Bio2;", cls("Lcom/myapp/Bio2;", m("    invoke-virtual {v0, v1}, Landroidx/biometric/BiometricPrompt;->authenticate(Landroidx/biometric/BiometricPrompt\$PromptInfo;)V\n")))
        assertEquals(listOf("Lcom/myapp/Bio2;"), row("bio-event").app)
        observe("Lcom/myapp/Both;", cls("Lcom/myapp/Both;", m("    invoke-virtual {v0, v1}, Landroidx/biometric/BiometricPrompt;->authenticate(Landroidx/biometric/BiometricPrompt\$PromptInfo;)V\n" +
            "    invoke-virtual {v0, v1, v2}, Landroidx/biometric/BiometricPrompt;->authenticate(Landroidx/biometric/BiometricPrompt\$PromptInfo;Landroidx/biometric/BiometricPrompt\$CryptoObject;)V\n")))
        assertEquals(listOf("Lcom/myapp/Bio2;"), row("bio-event").app)                                                // twin: a wrapper that binds a key when it has one
        observe("Lcom/myapp/Up;", cls("Lcom/myapp/Up;", m("    invoke-static {v0}, Lcom/google/android/play/core/appupdate/AppUpdateManagerFactory;->create(Landroid/content/Context;)Lcom/google/android/play/core/appupdate/AppUpdateManager;\n")))
        assertEquals(1, row("in-app-update").app.size)
        observe("Lcom/myapp/Login;", cls("Lcom/myapp/Login;", m("    invoke-virtual {v0, v1, v2}, Lnet/openid/appauth/AuthorizationService;->performAuthorizationRequest(Lnet/openid/appauth/AuthorizationRequest;Landroid/app/PendingIntent;)V\n")))
        assertEquals(1, row("auth-oauth").app.size)
        observe("Lcom/myapp/Consent;", cls("Lcom/myapp/Consent;", m("    invoke-static {v0, v1}, Lcom/google/android/ump/UserMessagingPlatform;->loadAndShowConsentFormIfRequired(Landroid/app/Activity;Lcom/google/android/ump/ConsentForm\$OnConsentFormDismissedListener;)V\n" +
            "    invoke-static {v0, v1}, Lcom/google/android/ump/UserMessagingPlatform;->showPrivacyOptionsForm(Landroid/app/Activity;Lcom/google/android/ump/ConsentForm\$OnConsentFormDismissedListener;)V\n")))
        assertEquals(1, row("consent-ump").app.size); assertEquals(1, row("privacy-options").app.size)
        // twins: naming a type is not using it (an import of the update manager, a consent-status getter)
        fresh()
        observe("Lcom/myapp/T;", cls("Lcom/myapp/T;", m("    check-cast v0, Lcom/google/android/play/core/appupdate/AppUpdateManager;\n    invoke-interface {v0}, Lcom/google/android/ump/ConsentInformation;->getConsentStatus()I\n")))
        assertTrue(row("in-app-update").app.isEmpty() && row("consent-ump").app.isEmpty() && row("privacy-options").app.isEmpty())
    }

    @Test fun obfuscationIsCountedOverTheAppClassesOnly() {
        fresh()
        val keep = ".class public Lcom/myapp/Main;\n.super Ljava/lang/Object;\n.source \"Main.kt\"\n.method public a()V\n    .locals 0\n    .line 1\n    return-void\n.end method\n"
        observe("Lcom/myapp/Main;", keep)
        observe("La/b;", ".class public La/b;\n.super Ljava/lang/Object;\n.method public a()V\n    .locals 0\n    return-void\n.end method\n")          // renamed: app-bound by the shape of its text is not needed here
        observe("Lcom/google/firebase/Lib;", keep.replace("Lcom/myapp/Main;", "Lcom/google/firebase/Lib;"))                    // library: not counted
        val line = PostureScanner.obfuscationLine()
        assertTrue(line, line.contains(" of 2 classes"))
        assertTrue(line, line.contains("1 of 2") || line.contains("(50%)"))
    }

    @Test fun nscPinSetStateIsShownInTheTable() {
        fresh(); assertTrue(PostureScanner.section().contains("not checked"))
        PostureScanner.nscPins = true; assertTrue(PostureScanner.section().contains("| present |"))
        PostureScanner.nscPins = false; assertTrue(PostureScanner.section().contains("a config exists, no pin-set"))
        fresh()
    }

    @Test fun friDayIsNotFridaAndARenamedSdkIsNotTheAppsProtection() {                      // both found on real apps
        fresh()
        observe("Lcom/myapp/Days;", cls("Lcom/myapp/Days;", m("    const-string v0, \"FRIDAY\"\n    const-string v1, \"Friday\"\n")))
        assertTrue(row("hooking").app.isEmpty())
        observe("Lcom/myapp/Probe;", cls("Lcom/myapp/Probe;", m("    const-string v0, \"frida-server\"\n")))
        assertEquals(1, row("hooking").app.size)
        fresh()
        val su = m("    const-string v0, \"/system/xbin/su\"\n")
        observe("La/h;", cls("La/h;", su))                                                    // renamed, no reference to com.myapp: an SDK or the app, unknown
        val r = row("root-paths")
        assertTrue(r.app.isEmpty()); assertEquals(listOf("La/h;"), r.obf)
        assertTrue(PostureScanner.section().contains("origin unknown: renamed or outside the app's package (1)"))
        observe("Lb/c;", cls("Lb/c;", su + m("    invoke-static {}, Lcom/myapp/Main;->a()V\n    invoke-static {}, Lcom/myapp/Foo;->b()V\n    invoke-static {}, Lcom/myapp/Bar;->c()V\n")))   // renamed AND bound to the app (3 references to its package)
        assertEquals(listOf("Lb/c;"), row("root-paths").app)
        fresh()
        observe("Lcom/scottyab/rootbeer/Const;", cls("Lcom/scottyab/rootbeer/Const;", su))      // RootBeer's own strings: a library
        assertEquals(1, row("root-paths").lib.size); assertTrue(row("root-paths").app.isEmpty())
    }

    @Test fun aReadableClassOutsideTheAppPackageIsNotCountedAsTheAppsProtection() {              // Monerujo: NetCipher's TorServiceUtils looked like root detection
        fresh()
        observe("Linfo/guardianproject/netcipher/proxy/TorServiceUtils;", cls("Linfo/guardianproject/netcipher/proxy/TorServiceUtils;", m("    const-string v0, \"/system/xbin/su\"\n")))
        assertTrue(row("root-paths").app.isEmpty()); assertEquals(1, row("root-paths").obf.size)
        observe("Lcom/myapp/ui/Guard;", cls("Lcom/myapp/ui/Guard;", m("    const-string v0, \"/system/xbin/su\"\n")))
        assertEquals(listOf("Lcom/myapp/ui/Guard;"), row("root-paths").app)
    }

    @Test fun stringEncryptionAndReflectionMarshallingAreReportedOnlyWhenWidespread() {                  // a wallet app obfuscated by a commercial tool: the decrypt method is in most classes
        PostureScanner.clear(); PostureScanner.clearApk()
        val enc = ".class public Lcom/x/A%d;\n.super Ljava/lang/Object;\n.method private static a([I[BZ[Ljava/lang/Object;)V\n    .locals 1\n    return-void\n.end method\n"
        val refl = ".class public Lcom/x/B%d;\n.super Ljava/lang/Object;\n.method public m()V\n    .locals 2\n    invoke-static/range {v1 .. v7}, LSpace;->ICustomTabsCallback(ICIIZLjava/lang/String;[Ljava/lang/Class;)Ljava/lang/Object;\n    return-void\n.end method\n"
        for (i in 1..25) { PostureScanner.observe("Lcom/x/A$i;", enc.format(i), "com.x"); PostureScanner.observe("Lcom/x/B$i;", refl.format(i), "com.x") }
        val md = PostureScanner.section()
        assertTrue(md, md.contains("String encryption / reflection marshalling")); assertTrue(md.contains("25 classes carry a string-decrypting method and 25"))
        PostureScanner.clear()
        for (i in 1..25) PostureScanner.observe("Lcom/x/C$i;", ".class public Lcom/x/C$i;\n.super Ljava/lang/Object;\n.method public m()V\n    .locals 1\n    return-void\n.end method\n", "com.x")
        assertFalse(PostureScanner.section().contains("String encryption"))                                  // twin: ordinary classes
        PostureScanner.clear(); PostureScanner.clearApk(); PostureScanner.nscDeclared = false
        assertTrue(PostureScanner.section().contains("no network security config declared"))
        PostureScanner.nscDeclared = true
        assertTrue(PostureScanner.section().contains("not checked: no network security config was read"))
    }

    private fun callsClass(target: String, n: Int): String {
        val sb = StringBuilder(".class public Lcom/x/Big;\n.super Ljava/lang/Object;\n.method public m()V\n    .locals 3\n")
        for (i in 1..n) sb.append("    invoke-static {v0}, ").append(target).append("(I)Ljava/lang/String;\n")
        return sb.append("    return-void\n.end method\n").toString()
    }

    @Test fun aStaticIntToStringMethodCalledThousandsOfTimesIsAStringDecryptor() {
        PostureScanner.clear()
        PostureScanner.observe("Lcom/x/Big;", callsClass("Lvs/C;->d", 2100), "com.x")
        val md = PostureScanner.section()
        assertTrue(md, md.contains("String decryption table: the static method vs.C.d(int) is called 2100 times"))
        assertTrue(md.contains("Java.use('vs.C')"))
        PostureScanner.clear()
        PostureScanner.observe("Lcom/x/Big;", callsClass("Ljava/lang/Integer;->toHexString", 2100), "com.x")      // twin: a framework method
        assertFalse(PostureScanner.section().contains("String decryption table"))
        PostureScanner.clear()
        PostureScanner.observe("Lcom/x/Big;", callsClass("Lvs/C;->d", 300), "com.x")                               // twin: an ordinary helper (the corpus maximum is 292)
        assertFalse(PostureScanner.section().contains("String decryption table"))
    }

    // 0.103.1 (two device reports of the same APK: "not checked" in one, "no network security config declared" in the other): a Deep scan must not wipe what the resource scan found
    @Test fun aDeepScanStartDoesNotWipeTheNetworkSecurityConfigFacts() {
        try {
            PostureScanner.nscDeclared = false; PostureScanner.nscPins = null
            PostureScanner.clear()                                                     // what every Deep scan does first
            assertEquals(false, PostureScanner.nscDeclared)
            assertTrue(PostureScanner.section().contains("no network security config declared"))
            PostureScanner.nscDeclared = true; PostureScanner.nscPins = false
            PostureScanner.clear()
            assertEquals(false, PostureScanner.nscPins); assertEquals(true, PostureScanner.nscDeclared)
            PostureScanner.clearApk()                                                   // loading another APK does reset them
            assertEquals(null, PostureScanner.nscPins); assertEquals(null, PostureScanner.nscDeclared)
            assertTrue(PostureScanner.section().contains("not checked"))
        } finally { PostureScanner.clearApk() }
    }

    // 0.105.0 (WE Wallet: DexGuard moved the app's own Mwallet2ApplicationClassResetPasswordMode to the root package; the posture table said "origin unknown")
    @Test fun aRootPackageClassNamedAfterTheAppsDeclaredClassIsTheApps() {
        fresh(); PostureScanner.clearApk()
        PostureScanner.setManifest("<manifest package=\"com.wallet.app\"><application android:name=\"com.wallet.app.Mwallet2ApplicationClass\"><activity android:name=\".ui.MainHomeScreenActivity\"/>" +
            "<service android:name=\"com.google.firebase.messaging.FirebaseMessagingService\"/></application></manifest>")
        val su = m("    const-string v0, \"/system/xbin/su\"\n")
        PostureScanner.observe("LMwallet2ApplicationClassResetPasswordMode;", cls("LMwallet2ApplicationClassResetPasswordMode;", su), "com.wallet.app")
        assertEquals(listOf("LMwallet2ApplicationClassResetPasswordMode;"), row("root-paths").app)
        // twins: a short shared prefix, a class in a package, a name taken from a LIBRARY component of the manifest: origin stays unknown
        fresh()
        PostureScanner.observe("LMwallet2ApXyzQ;", cls("LMwallet2ApXyzQ;", su), "com.wallet.app")                               // 13 chars, only 10 in common
        PostureScanner.observe("Lx/Mwallet2ApplicationClassX;", cls("Lx/Mwallet2ApplicationClassX;", su), "com.wallet.app")       // not the root package
        PostureScanner.observe("LFirebaseMessagingServiceImpl;", cls("LFirebaseMessagingServiceImpl;", su), "com.wallet.app")     // an SDK's declared name
        assertTrue(row("root-paths").app.isEmpty()); assertEquals(3, row("root-paths").obf.size)
        PostureScanner.observe("LMainHomeScreenActivityHelper;", cls("LMainHomeScreenActivityHelper;", su), "com.wallet.app")     // a relative (".ui.X") declared name
        assertEquals(listOf("LMainHomeScreenActivityHelper;"), row("root-paths").app)
        PostureScanner.clearApk(); assertTrue(row("root-paths").app.isEmpty())                                                   // the next APK forgets the names
        fresh()
    }

    // 0.108.0: root checks whose paths / package names are decrypted at run time (Axis Pay MainActivity)
    @Test fun encryptedRootChecksAreFoundByTheirProbes() {
        fresh()
        val probes = m("    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;\n    invoke-virtual {v1}, Ljava/io/File;->exists()Z\n" +
            "    invoke-virtual {v2, v3, v4}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;\n" +
            "    invoke-virtual {v5, v6}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;\n")
        observe("Lcom/myapp/MainActivity;", cls("Lcom/myapp/MainActivity;", probes))
        assertEquals(listOf("Lcom/myapp/MainActivity;"), row("root-structure").app)
        assertTrue(row("root-paths").app.isEmpty())                                                   // no plain su path: the string row stays empty
        // twins: a class with only two of the three probes
        fresh()
        observe("Lcom/myapp/Files;", cls("Lcom/myapp/Files;", probes.replace("Ljava/lang/Runtime;->exec(", "Ljava/lang/Runtime;->gc(")))
        observe("Lcom/myapp/Pkgs;", cls("Lcom/myapp/Pkgs;", probes.replace("Ljava/io/File;->exists()Z", "Ljava/io/File;->length()J")))
        assertTrue(row("root-structure").app.isEmpty())
        fresh()
    }
}
