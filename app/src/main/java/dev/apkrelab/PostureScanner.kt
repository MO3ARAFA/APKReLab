package dev.apkrelab

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * 0.91.0: the DEFENSE POSTURE of an app (what it does to resist tampering, instrumentation, a rooted or emulated device, screen capture and a man in the middle) as a table, kept apart
 * from the vulnerabilities: the absence of root detection in an open-source notes app is not a flaw, but a bank wants to see it. Signals are read per class by [observe] (called from
 * [SecurityScanner.scanSmali], i.e. over every class the deep scan visits) and every hit remembers WHERE it is: in the app's own code, or only in a library. A root check inside an
 * advertising SDK must not give an app the feeling that it is protected, so "only in libraries" is a status of its own.
 *
 * Static limits, printed with the table: checks done in native code, hidden by string encryption, or made on the server are not seen.
 */
object PostureScanner {

    class Sig(val id: String, val control: String, val masvs: String, val test: (String) -> Boolean)

    private fun has(t: String, vararg any: String) = any.any { t.contains(it) }
    private val constStr = Regex("const-string(?:/jumbo)?\\s+[vp]\\d+,\\s*\"((?:[^\"\\\\\\n]|\\\\.)*)\"")
    private fun strings(t: String): List<String> = constStr.findAll(t).map { it.groupValues[1] }.toList()

    private val suPaths = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "/system/sd/xbin/su", "/su/bin/su", "/system/xbin/daemonsu", "/system/app/Superuser.apk", "/system/bin/failsafe/su")
    private val rootPkgs = listOf("com.topjohnwu.magisk", "eu.chainfire.supersu", "com.koushikdutta.superuser", "com.noshufou.android.su", "com.thirdparty.superuser", "com.yellowes.su", "com.zachspong.temprootremovejb")
    private val emuTokens = listOf("goldfish", "ranchu", "generic_x86", "sdk_gphone", "google_sdk", "genymotion", "vbox86", "ro.kernel.qemu", "qemu", "android sdk built for x86", "emulator")
    // 0.91.0 (found on real apps: "FRIDAY" in a DayOfWeek enum matched "frida" in 10 of 37 apps): frida must stand alone or be one of its known component names
    private val hookRegex = Regex("(?<![a-z])frida(?![a-z])|frida-(?:server|agent|gadget|helper)|re\\.frida|linjector|xposedbridge|de[./]robv[./]android[./]xposed|lsposed|com[./]saurik[./]substrate|libsubstrate")

    /** A class implementing X509TrustManager that compares a key or a digest in checkServerTrusted: pinning done by hand. */
    private fun customPinning(t: String): Boolean {
        if (!t.contains(".implements Ljavax/net/ssl/X509TrustManager;") && !t.contains(".super Landroid/net/http/X509TrustManagerExtensions;")) return false
        val i = t.indexOf("checkServerTrusted"); if (i < 0) return false
        val body = t.substring(i, minOf(t.length, i + 6000))
        return has(body, "->getPublicKey()", "Ljava/security/MessageDigest;->digest", "->getEncoded()", "Ljava/util/Arrays;->equals")
    }

    /** setFlags / addFlags with 0x2000 (FLAG_SECURE) in one method, or SurfaceView.setSecure. */
    private fun flagSecure(t: String): Boolean {
        if (t.contains("Landroid/view/SurfaceView;->setSecure(Z)V")) return true
        var at = t.indexOf("\n.method ")
        while (at >= 0) {
            val end = t.indexOf("\n.end method", at).let { if (it < 0) t.length else it }
            val b = t.substring(at, end)
            if ((b.contains("Landroid/view/Window;->addFlags(I)V") || b.contains("Landroid/view/Window;->setFlags(II)V")) &&
                Regex("const(?:/16|/high16)?\\s+[vp]\\d+,\\s*(?:0x2000|8192)\\b").containsMatchIn(b)) return true
            at = t.indexOf("\n.method ", end)
        }
        return false
    }

    private fun bioCrypto(t: String) = has(t, "Landroidx/biometric/BiometricPrompt;->authenticate(Landroidx/biometric/BiometricPrompt\$PromptInfo;Landroidx/biometric/BiometricPrompt\$CryptoObject;)V",
        "Landroid/hardware/biometrics/BiometricPrompt;->authenticate(Landroid/hardware/biometrics/BiometricPrompt\$CryptoObject;")

    val signals: List<Sig> = listOf(
        Sig("pin-okhttp", "Certificate pinning: OkHttp CertificatePinner", "MASVS-NETWORK-2") { has(it, "Lokhttp3/CertificatePinner\$Builder;->add(", "Lokhttp3/CertificatePinner\$Builder;->add") },
        Sig("pin-trustkit", "Certificate pinning: TrustKit", "MASVS-NETWORK-2") { has(it, "Lcom/datatheorem/android/trustkit/") },
        Sig("pin-custom", "Certificate pinning: a custom TrustManager comparing a key or digest", "MASVS-NETWORK-2") { customPinning(it) },
        Sig("root-paths", "Root detection: su binaries / root manager packages", "MASVS-RESILIENCE-1") { t -> strings(t).any { s -> suPaths.any { s.contains(it) } || rootPkgs.any { s == it } } },
        // 0.108.0 (Axis Pay: MainActivity tests a list of files, a list of installed packages and runs a command, every path / package name decrypted at run time, so the
        // string-based row above saw nothing): the probes themselves, in one class. Measured: 1 class in 16 decoded apps (that one)
        Sig("root-structure", "Root detection: file + installed-package probes and a shell command in one class (found even when the names are encrypted)", "MASVS-RESILIENCE-1") {
            it.contains("Ljava/lang/Runtime;->exec(") && it.contains("Ljava/io/File;->exists()Z") && it.contains("Landroid/content/pm/PackageManager;->getPackageInfo(") &&
                (it.contains("Ljava/util/Iterator;->next()") || it.contains("aget-object")) },
        Sig("root-lib", "Root detection: RootBeer / JailMonkey call", "MASVS-RESILIENCE-1") { has(it, "Lcom/scottyab/rootbeer/RootBeer;->isRooted", "JailMonkey") && !it.contains(".class public Lcom/scottyab/rootbeer/") },
        Sig("debugger", "Anti-debugging: Debug.isDebuggerConnected / waitingForDebugger / TracerPid", "MASVS-RESILIENCE-4") {
            has(it, "Landroid/os/Debug;->isDebuggerConnected()Z", "Landroid/os/Debug;->waitingForDebugger()Z") || strings(it).any { s -> s.contains("TracerPid") } },
        Sig("emulator", "Emulator detection: Build properties compared with emulator names", "MASVS-RESILIENCE-1") { t ->
            t.contains("Landroid/os/Build;->") && strings(t).map { it.lowercase() }.let { ss -> emuTokens.count { tok -> ss.any { s -> s.contains(tok) } } >= 2 } },
        Sig("hooking", "Instrumentation detection: Frida / Xposed / Substrate", "MASVS-RESILIENCE-4") { t -> strings(t).any { s -> hookRegex.containsMatchIn(s.lowercase()) } },
        Sig("signature", "Tamper detection: the app's signing certificate is read", "MASVS-RESILIENCE-2") {
            has(it, "Landroid/content/pm/Signature;->toByteArray()", "->getApkContentsSigners()", "->getSigningCertificateHistory()", "Landroid/content/pm/PackageInfo;->signatures") },
        Sig("installer", "Installer verification: getInstallerPackageName / getInstallSourceInfo", "MASVS-RESILIENCE-2") { has(it, "->getInstallerPackageName(", "->getInstallSourceInfo(") },
        Sig("play-integrity", "Device / app attestation: Play Integrity API", "MASVS-RESILIENCE-1") { has(it, "Lcom/google/android/play/core/integrity/", "Lcom/google/android/play/integrity/") },
        Sig("safetynet", "Device attestation: SafetyNet (retired by Google)", "MASVS-RESILIENCE-1") { has(it, "Lcom/google/android/gms/safetynet/SafetyNet") },
        Sig("shell-const", "Shell commands with fixed arguments (usually root / emulator checks: su, which su, getprop; read the command)", "MASVS-RESILIENCE-1") { ConstantArgGuards.hasConstantShell(it) },
        Sig("flag-secure", "Screen capture protection: FLAG_SECURE / SurfaceView.setSecure", "MASVS-PLATFORM-3") { flagSecure(it) },
        // 1.0.0: the MASVS controls static analysis could not assess before (authentication, update enforcement, privacy). These rows say what the code USES, never that it is
        // used correctly: a login done in a WebView or on the server, or a consent screen of the app's own design, is not seen.
        Sig("auth-oauth", "Authentication: OAuth / OpenID Connect through AppAuth (a browser tab, not a WebView)", "MASVS-AUTH-1") { has(it, "Lnet/openid/appauth/AuthorizationService;->performAuthorizationRequest", "Lnet/openid/appauth/AuthorizationService;->getAuthorizationRequestIntent") },
        Sig("auth-credman", "Authentication: Credential Manager (passkeys / saved passwords)", "MASVS-AUTH-1") { has(it, "Landroidx/credentials/CredentialManager;->getCredential", "Landroidx/credentials/CredentialManager\$Companion;->create", "Landroid/credentials/CredentialManager;->getCredential") },
        Sig("auth-account", "Authentication: Android AccountManager tokens", "MASVS-AUTH-1") { has(it, "Landroid/accounts/AccountManager;->getAuthToken", "Landroid/accounts/AccountManager;->blockingGetAuthToken") },
        Sig("bio-crypto", "Local authentication: biometric prompt bound to a Keystore key (CryptoObject)", "MASVS-AUTH-2") { bioCrypto(it) },
        // a wrapper that calls both overloads (Flutter's local_auth helpers, measured in 2 corpus apps) binds a key when it has one: only a class that never does is listed here
        Sig("bio-event", "Local authentication: biometric prompt WITHOUT a key (the result is a callback a hooked app can fake; bind a CryptoObject for anything sensitive)", "MASVS-AUTH-2") {
            has(it, "Landroidx/biometric/BiometricPrompt;->authenticate(Landroidx/biometric/BiometricPrompt\$PromptInfo;)V",
                "Landroid/hardware/biometrics/BiometricPrompt;->authenticate(Landroid/os/CancellationSignal;") && !bioCrypto(it) },
        Sig("key-userauth", "Local authentication: a Keystore key that needs the user's authentication (setUserAuthenticationRequired)", "MASVS-AUTH-2") { has(it, "Landroid/security/keystore/KeyGenParameterSpec\$Builder;->setUserAuthenticationRequired(Z)") },
        Sig("key-bio-invalidate", "Local authentication: the key is invalidated when a new fingerprint is enrolled (setInvalidatedByBiometricEnrollment)", "MASVS-AUTH-2") { has(it, "Landroid/security/keystore/KeyGenParameterSpec\$Builder;->setInvalidatedByBiometricEnrollment(Z)") },
        Sig("step-up", "Sensitive operations: device-credential confirmation or Protected Confirmation before acting", "MASVS-AUTH-3") {
            has(it, "Landroid/app/KeyguardManager;->createConfirmDeviceCredentialIntent", "Landroid/security/ConfirmationPrompt", "Landroid/security/keystore/KeyGenParameterSpec\$Builder;->setUserConfirmationRequired(Z)") },
        Sig("in-app-update", "Update enforcement: Play In-App Updates", "MASVS-CODE-2") { has(it, "Lcom/google/android/play/core/appupdate/AppUpdateManager;->startUpdateFlow", "Lcom/google/android/play/core/appupdate/AppUpdateManagerFactory;->create") },
        Sig("consent-ump", "Privacy transparency: a consent dialog (Google User Messaging Platform)", "MASVS-PRIVACY-3") { has(it, "Lcom/google/android/ump/UserMessagingPlatform;->loadAndShowConsentFormIfRequired", "Lcom/google/android/ump/ConsentInformation;->requestConsentInfoUpdate", "Lcom/google/android/ump/UserMessagingPlatform;->loadConsentForm") },
        Sig("privacy-options", "Privacy control: the user can reopen the consent choices or turn analytics collection off", "MASVS-PRIVACY-4") {
            has(it, "Lcom/google/android/ump/UserMessagingPlatform;->showPrivacyOptionsForm", "Lcom/google/firebase/analytics/FirebaseAnalytics;->setConsent(", "Lcom/google/firebase/analytics/FirebaseAnalytics;->setAnalyticsCollectionEnabled(") },
        Sig("ad-privacy", "Privacy-preserving ads: Android Privacy Sandbox (AdServices Topics / Attribution)", "MASVS-PRIVACY-2") { has(it, "Landroid/adservices/topics/TopicsManager;->getTopics", "Landroid/adservices/measurement/MeasurementManager;->register", "Landroidx/privacysandbox/ads/adservices/") }
    )

    /** Where a hit is: the app's own code, renamed code whose origin cannot be told (an app or an SDK that R8 renamed), or a recognised library. */
    enum class Origin { APP, OBF, LIB }
    class Hit(val type: String, val origin: Origin) { val lib: Boolean get() = origin == Origin.LIB }
    private val hits = ConcurrentHashMap<String, MutableList<Hit>>()
    private val scopes = ConcurrentHashMap<SecurityScanner.Scope, AtomicInteger>()
    private val withSource = AtomicInteger(); private val withLines = AtomicInteger(); private val appClasses = AtomicInteger()
    private val strEnc = AtomicInteger(); private val reflMarshal = AtomicInteger()          // 0.96.0
    // 0.98.0 (a wallet app whose every string goes through one native method: 63,575 calls of `vs.C.d(int)`; the highest count of an app-defined static (int)->String method in 18
    // other real apps is 292): a string-table decryptor, in the app or in a protector. Framework methods (Integer.toHexString, String.valueOf ...) are not counted.
    private val decryptCalls = java.util.concurrent.ConcurrentHashMap<String, AtomicInteger>()
    private val decryptRe = Regex("invoke-static(?:/range)? \\{[^}]*\\}, (L[A-Za-z0-9_$/]+;->[A-Za-z0-9_$]+)\\(I\\)Ljava/lang/String;")
    private val frameworkPrefixes = listOf("Ljava/", "Ljavax/", "Landroid/", "Lkotlin/", "Ldalvik/")
    internal const val DECRYPTOR_MIN_CALLS = 2000
    // DexGuard-style string encryption (a static void m(int[], byte[], boolean, Object[]) that decrypts a string from a byte array) and reflection marshalling (a static (int, char, int, int, boolean, String, Class[]) -> Object lookup used instead of direct calls)
    private val strEncRe = Regex("^\\.method [^\\n]*\\bstatic\\b[^\\n]*\\(\\[I\\[BZ\\[Ljava/lang/Object;\\)V", RegexOption.MULTILINE)
    private val reflMarshalRe = Regex("invoke-static(?:/range)? \\{[^}]*\\}, L[A-Za-z0-9_$/]+;->[A-Za-z0-9_$]+\\(ICIIZLjava/lang/String;\\[Ljava/lang/Class;\\)Ljava/lang/Object;")
    @Volatile var nscPins: Boolean? = null
    @Volatile var nscDeclared: Boolean? = null   // 0.96.0: does the manifest declare a network security config at all

    /** 0.102.0: the app's dominant string decryptor as a smali method reference (`Lvs/C;->d(I)Ljava/lang/String;`), or null when no deep scan has seen DECRYPTOR_MIN_CALLS calls of one. */
    fun dominantDecryptor(): String? {
        val dec = decryptCalls.entries.maxByOrNull { it.value.get() } ?: return null
        return if (dec.value.get() >= DECRYPTOR_MIN_CALLS) dec.key + "(I)Ljava/lang/String;" else null
    }

    fun clear() { StringOverlay.current?.resetStats(); hits.clear(); scopes.clear(); withSource.set(0); withLines.set(0); appClasses.set(0); strEnc.set(0); reflMarshal.set(0); decryptCalls.clear() }

    /** 0.103.1: the network security config facts belong to the LOADED APK (the resource scan sets them once, in the background): reset them when an APK is loaded, NOT at the start of every Deep scan (that wiped them whenever the resource scan had finished first, and the report said "not checked" for the same APK). */
    fun clearApk() { nscPins = null; nscDeclared = null; declaredNames = emptySet(); sdkTypes = emptySet(); nativeHits.clear() }

    /** Called with the text of every class the FULL deep scan reads (not by a single-class review: that would count a class twice). */
    fun observe(classType: String, text: String, appPkg: String) {
        if (text.length < 40) return
        val scope = try { SecurityScanner.scopeOfText(classType, appPkg, text) } catch (_: Throwable) { SecurityScanner.Scope.OTHER }
        val isLib = scope == SecurityScanner.Scope.LIB
        // renamed code is the app's only when its text refers to the app's own package (isAppBoundObf, 0.82.0); otherwise it may be an SDK: the posture says "unknown origin"
        // 0.91.0: APP = a class under the app's own code package, or a renamed class that refers to it; a readable class OUTSIDE that package (NetCipher, a vendored SDK the library list
        // does not know) is "origin unknown" as well: Monerujo's "root detection" was NetCipher's TorServiceUtils
        val underApp = appPkg.isNotEmpty() && classType.startsWith("L" + appPkg.split('.').take(2).joinToString("/") + "/")
        val origin = when {
            isLib -> Origin.LIB
            scope == SecurityScanner.Scope.OBF -> if (try { SecurityScanner.isAppBoundObf(text, appPkg) } catch (_: Throwable) { false }) Origin.APP else Origin.OBF
            underApp || appPkg.isEmpty() -> Origin.APP
            else -> Origin.OBF
        }
        scopes.getOrPut(scope) { AtomicInteger() }.incrementAndGet()
        if (!isLib) {
            appClasses.incrementAndGet()
            if (text.contains("\n.source \"")) withSource.incrementAndGet()
            if (text.contains("\n    .line ")) withLines.incrementAndGet()
            if (strEncRe.containsMatchIn(text)) strEnc.incrementAndGet()
            if (reflMarshalRe.containsMatchIn(text)) reflMarshal.incrementAndGet()
            if (text.contains(")Ljava/lang/String;")) for (m in decryptRe.findAll(text)) { val t = m.groupValues[1]; if (frameworkPrefixes.none { t.startsWith(it) }) decryptCalls.computeIfAbsent(t) { AtomicInteger() }.incrementAndGet() }
        }
        for (s in signals) {
            val ok = try { s.test(text) } catch (_: Throwable) { false }
            if (!ok) continue
            val list = hits.getOrPut(s.id) { java.util.Collections.synchronizedList(ArrayList()) }
            if (list.size < 400) list.add(Hit(classType, origin))
        }
    }

    class Row(val sig: Sig, val app: List<String>, val obf: List<String>, val lib: List<String>)

    /**
     * 0.107.0: root / instrumentation / debugger checks done in a NATIVE library (the strings of its data sections; NativeScanner calls this for every .so it reads). A protected app
     * can do these checks in C, and the table said "not detected" when the Java side had none. Kept per APK (the deep scan's clear() does not drop them: the resource scan that reads
     * the libraries may finish first). A recognised third-party library counts as library, any other .so as origin unknown (an SDK or the app). Measured: 0 hits in the 27 corpus
     * apps with native libraries (39 APKs).
     */
    fun observeNative(libPath: String, str: String, thirdParty: Boolean) {
        val ids = ArrayList<String>(2)
        if (suPaths.any { str.contains(it) } || rootPkgs.any { str.contains(it) }) ids.add("root-paths")
        if (hookRegex.containsMatchIn(str.lowercase())) ids.add("hooking")
        if (str.contains("TracerPid")) ids.add("debugger")
        for (id in ids) {
            val list = nativeHits.getOrPut(id) { java.util.Collections.synchronizedList(ArrayList()) }
            val name = "$libPath (native)"
            if (list.none { it.type == name } && list.size < 50) list.add(Hit(name, if (thirdParty) Origin.LIB else Origin.OBF))
        }
    }
    private val nativeHits = ConcurrentHashMap<String, MutableList<Hit>>()

    fun rows(): List<Row> = signals.map { s ->
        val h = ((hits[s.id]?.toList() ?: emptyList()) + (nativeHits[s.id]?.toList() ?: emptyList())).map { if (it.origin == Origin.OBF && it.type in sdkTypes) Hit(it.type, Origin.LIB) else if (it.origin == Origin.OBF && boundByName(it.type)) Hit(it.type, Origin.APP) else it }
        Row(s, h.filter { it.origin == Origin.APP }.map { it.type }, h.filter { it.origin == Origin.OBF }.map { it.type }, h.filter { it.origin == Origin.LIB }.map { it.type })
    }

    /**
     * 0.105.0: simple names of the classes the app's manifest declares as its OWN (application, activities, services, receivers, providers that are not a known library's).
     * A protector (DexGuard) moves classes to the root package and keeps their names: WE Wallet's `Mwallet2ApplicationClassResetPasswordMode` is "origin unknown" by package,
     * yet it carries the name of the app's declared `Mwallet2ApplicationClass`. Set from the decoded manifest of the loaded APK (kept until the next APK).
     */
    @Volatile var declaredNames: Set<String> = emptySet()
    /** 0.106.0: renamed classes the structure gives to one bundled SDK (SdkAttribution): their hits are the library's, not "origin unknown". Set after each Deep scan. */
    @Volatile var sdkTypes: Set<String> = emptySet()
    internal const val NAME_PREFIX_MIN = 12

    fun setManifest(xml: String) {
        val pkg = Regex("<manifest[^>]*\\spackage=\"([^\"]+)\"").find(xml)?.groupValues?.get(1) ?: ""
        val out = HashSet<String>()
        for (m in Regex("<(application|activity-alias|activity|service|receiver|provider)\\b[^>]*?android:(?:name|targetActivity)=\"([^\"]+)\"").findAll(xml)) {
            var n = m.groupValues[2]
            if (n.startsWith(".")) n = pkg + n
            val type = "L" + n.replace('.', '/') + ";"
            if (try { SecurityScanner.scopeOf(type, pkg) == SecurityScanner.Scope.LIB } catch (_: Throwable) { true }) continue
            out.add(n.substringAfterLast('.'))
        }
        declaredNames = out
    }

    /** A renamed class in the ROOT package whose name starts with at least [NAME_PREFIX_MIN] characters of a class the manifest declares as the app's own. */
    internal fun boundByName(type: String): Boolean {
        if (!type.startsWith("L") || !type.endsWith(";") || type.indexOf('/') >= 0) return false
        val simple = type.substring(1, type.length - 1).substringAfterLast('/')
        return declaredNames.any { d -> d.length >= NAME_PREFIX_MIN && simple.length >= NAME_PREFIX_MIN && simple.commonPrefixWith(d).length >= NAME_PREFIX_MIN }
    }

    fun obfuscationLine(): String {
        val n = appClasses.get()
        if (n == 0) return "no app classes were read"
        val obf = scopes[SecurityScanner.Scope.OBF]?.get() ?: 0
        val src = withSource.get(); val lines = withLines.get()
        return "$obf of $n classes outside the known libraries ${pct(obf, n)} have renamed (short) names; ${pct(src, n)} keep a source-file name and ${pct(lines, n)} keep line numbers"
    }
    private fun pct(a: Int, n: Int) = "(" + (if (n == 0) 0 else Math.round(100.0 * a / n)) + "%)"

    private fun short(t: String) = t.removePrefix("L").removeSuffix(";").replace('/', '.').let { if (it.length > 46) "…" + it.takeLast(45) else it }

    /** The report section. */
    fun section(): String {
        val rs = rows()
        val sb = StringBuilder("\n## Defense posture\n\n")
        sb.append("What the app does to resist tampering, instrumentation, rooted or emulated devices, screen capture and interception. This is NOT a list of vulnerabilities: a missing control is a ")
            .append("decision for the app's threat model (a bank wants most of them, a notes app none). \"Library only\" means the check was found only inside a bundled library (an SDK), where it protects the SDK, not necessarily the app; \"origin unknown\" means a class that R8 renamed without referring to the app's own package, or a readable class outside it: it may be the app's or an SDK's (Sentry, NetCipher, an analytics SDK ...), so it is not counted as the app's protection.\n\n")
        sb.append("| Control | MASVS | Status | Where (examples) |\n|---|---|---|---|\n")
        for (r in rs) {
            val status = when {
                r.app.isNotEmpty() -> "in app code (" + r.app.size + ")"
                r.obf.isNotEmpty() -> "origin unknown: renamed or outside the app's package (" + r.obf.size + ")"
                r.lib.isNotEmpty() -> "library only (" + r.lib.size + ")"
                else -> "not detected"
            }
            val where = (r.app.take(3) + (if (r.app.isEmpty()) r.obf.take(2) + (if (r.obf.isEmpty()) r.lib.take(2) else emptyList()) else emptyList())).joinToString("<br>") { short(it) }
            sb.append("| ").append(r.sig.control).append(" | ").append(r.sig.masvs).append(" | ").append(status).append(" | ").append(where.ifEmpty { "-" }).append(" |\n")
        }
        sb.append("| Certificate pinning: network_security_config pin-set | MASVS-NETWORK-2 | ").append(when (nscPins) { true -> "present"; false -> "a config exists, no pin-set"; null -> if (nscDeclared == false) "no network security config declared (the platform default applies: system CAs only, no cleartext from targetSdk 28)" else "not checked: no network security config was read (see the INFO finding if the manifest declares one)" }).append(" | - |\n")
        sb.append("\nObfuscation / debug information: ").append(obfuscationLine()).append(".\n")
        // 1.1.0: every method over the threshold, not only the largest (one dump per method: the overlay file names one method on its '#decryptor' line)
        val decs = decryptCalls.entries.filter { it.value.get() >= DECRYPTOR_MIN_CALLS }.sortedByDescending { it.value.get() }
        if (decs.isNotEmpty()) {
            sb.append("\nString decryption table: ")
            for ((k, dec) in decs.withIndex()) {
                if (k > 0) sb.append("; ")
                sb.append("the static method ").append(dec.key.substringBefore(";->").removePrefix("L").replace('/', '.')).append('.').append(dec.key.substringAfter(";->")).append("(int) is called ").append(dec.value.get()).append(" times")
            }
            sb.append(": the strings of this app are decrypted at run time (a protector or an in-app scheme; the method may be native). Every rule that reads string constants (secrets, URLs, cipher names, extra names, root-check paths) is BLIND here: ")
                .append("0 findings of those kinds means nothing. To read the strings, dump them on a test device (your own build) and import the file with the Security screen's Strings button (0.102.0: the rules then see the real strings)")
                .append(if (decs.size > 1) "; the script below writes one block per method: save each block (from its '#decryptor' line) as its own file and import them one at a time" else "").append(":\n\n```js\n// frida -U -f <package> -l dump.js\nJava.perform(function () {\n")
            for (dec in decs) {
                val cls = dec.key.substringBefore(";->").removePrefix("L").replace('/', '.'); val m = dec.key.substringAfter(";->")
                sb.append("  console.log('#decryptor\\t").append(dec.key).append("(I)Ljava/lang/String;');\n  Java.use('").append(cls).append("')['").append(m)
                    .append("'].overload('int').implementation = function (i) { var s = this['").append(m).append("'](i); console.log(i + '\\t' + JSON.stringify(s)); return s; };\n")
            }
            sb.append("});\n```\n")
        }
        StringOverlay.current?.let { o ->
            sb.append("\nDecoded-strings overlay: ").append(o.strings.size).append(" strings imported for ").append(o.method).append("; ").append(StringOverlay.coverage(o.replaced, o.unresolved)).append(" (")
                .append(o.unresolved).append(" stay encrypted: the index is not a constant in the same block, or is not in the dump). The string rules see the plaintext of the replaced sites only.\n")
        }
        if (strEnc.get() >= 20 || reflMarshal.get() >= 20) sb.append("\nString encryption / reflection marshalling (DexGuard-style): ").append(strEnc.get()).append(" classes carry a string-decrypting method and ").append(reflMarshal.get())
            .append(" call the app's own code through a reflection lookup. Everything that reads string constants (secrets, URLs, cipher names, the names of Intent extras) and every call-graph edge made this way is BLIND in those classes: a finding that is absent there is not a pass, and the names in a call path can be misleading.\n")
        sb.append("\nLimits: only the Java / Kotlin code is read. Checks in native code, behind string encryption or made by the server are not seen; a check found here is not proof that it works or is called.\n")
        return sb.toString()
    }

    /** Short findings that belong in the findings list: one summary (INFO) and the use of the retired SafetyNet API (LOW). */
    fun findings(): List<SecurityScanner.Finding> {
        val rs = rows(); val out = ArrayList<SecurityScanner.Finding>()
        val inApp = rs.count { it.app.isNotEmpty() } + (if (nscPins == true) 1 else 0); val total = rs.size + 1
        out.add(SecurityScanner.Finding(SecurityScanner.Severity.INFO, "Defense posture: $inApp of $total controls detected in app code",
            "See the \"Defense posture\" section of the report: pinning, root / emulator / debugger / instrumentation detection, signature and installer checks, device attestation and screen-capture protection. " +
                "Only controls that are in the app's own code count; a check that exists only inside a library is listed as such.",
            "Decide which controls your threat model needs; for a financial app most of them.", null, -1, -1, "", "").also { it.ruleId = "posture-summary"; it.confidence = "MEDIUM" })
        rs.firstOrNull { it.sig.id == "safetynet" && it.app.isNotEmpty() }?.let {
            out.add(SecurityScanner.Finding(SecurityScanner.Severity.LOW, "The retired SafetyNet attestation API is used",
                "The app calls the SafetyNet API (" + short(it.app.first()) + "). Google retired SafetyNet attestation: new calls fail or are turned down, so the check it was meant to provide is not working.",
                "Migrate to the Play Integrity API (IntegrityManager / StandardIntegrityManager).", null, -1, -1, "CWE-1104", short(it.app.first())).also { f -> f.ruleId = "posture-safetynet-retired"; f.confidence = "HIGH" })
        }
        return out
    }
}
