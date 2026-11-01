package dev.apkrelab

/**
 * 0.40.0: false-positive reduction, applied to the findings of ONE class at the end of SecurityScanner.scanSmali.
 *
 * Principles (nothing is deleted: a finding is only lowered and the reason is stored in Finding.adjusted):
 *  - findings in test classes (JUnit / androidTest / mocks) become INFO;
 *  - heuristic findings (method-level or informational guesses) inside known library code are lowered one level;
 *  - exact findings (exact API + constant argument traced, or a manifest flag) are never lowered by scope.
 * [confidenceOf] tells the reader how much to trust a finding (HIGH = exact signal, MEDIUM = heuristic, LOW = informational).
 */
object FindingPolish {

    private val lowTitleHints = listOf(
        "targetsdk", "accessibility", "fileprovider", "pinning", "detection", "qr/barcode", "logs requests",
        "integrity", "root ", "emulator", "keyboard cache", "high-entropy embedded string(s)"
    )
    private val mediumTitleHints = listOf(
        "possible", "may build", "straight from an intent", "dynamically built", "security-sounding",
        "intent redirection", "dynamic code loading", "shell command", "sensitive value", "near a credential",
        "hardware identifier", "fragment injection"
    )

    /** 0.66.4: TLS rules lowered one level when the class is library / obfuscated code, even though their confidence is HIGH. */
    val SCOPE_LOWERED_RULES: Set<String> = setOf("tls-trustmanager", "tls-hostname-verifier", "tls-insecure-socket-factory")

    /**
     * 2.0.1 (device reports WE Wallet / JustMarkets / Axis Pay 3.1.0): API-presence rules whose card says nothing about input. An ObjectInputStream.readObject, an MD5 /
     * SHA-1 digest or a java.util.Random in R8-obfuscated code is overwhelmingly a third-party SDK (Dynamite loader, Jackson, analytics) and the scan traced no outside
     * value into it: MEDIUM x 9 on three apps. Same one-level lowering as the TLS rules; a traced flow is a taint-flow card and is not touched.
     */
    val OBF_API_ONLY_RULES: Set<String> = setOf("deserialization", "crypto-weak-hash", "weak-random")
    @JvmField var LOWER_OBF_API_ONLY = !java.lang.Boolean.getBoolean("apkrelab.noLowerObfApiOnly")

    fun confidenceOf(f: SecurityScanner.Finding): String {
        val t = f.title.lowercase()
        if (f.severity == SecurityScanner.Severity.INFO) return "LOW"
        if (f.confidence.isNotEmpty()) return f.confidence      // 0.41.0: set by the rule that produced the finding
        if (lowTitleHints.any { t.contains(it) }) return "LOW"
        if (mediumTitleHints.any { t.contains(it) }) return "MEDIUM"
        return "HIGH"
    }

    private fun lowered(s: SecurityScanner.Severity): SecurityScanner.Severity {
        val next = minOf(SecurityScanner.Severity.INFO.rank, s.rank + 1)
        return SecurityScanner.Severity.values().first { it.rank == next }
    }

    private fun isTestClass(type: String): Boolean =
        type.startsWith("Landroidx/test/") || type.startsWith("Lorg/junit/") || type.startsWith("Lorg/mockito/") ||
            type.startsWith("Lio/mockk/") || type.contains("/androidTest/") || type.endsWith("Test;") || type.endsWith("Tests;")

    /**
     * 0.42.0: manifest findings. The manifest describes the WHOLE app, so the class-level lowering (test class, heuristic inside a
     * library) never applies: nothing is lowered here. The pass only guarantees every finding carries a confidence (the rule's own
     * value; the title hints are the fallback) and can never throw.
     */
    fun applyManifest(list: List<SecurityScanner.Finding>): List<SecurityScanner.Finding> {
        for (f in list) {
            try {
                if (f.confidence.isEmpty()) f.confidence = confidenceOf(f)
            } catch (_: Throwable) { }
        }
        return list
    }

    /**
     * 0.43.0: resource findings (res/ XML, resources.arsc). Same contract as [applyManifest]: nothing is lowered (a resource is
     * not a class, so there is no test-class / library scope); every finding just carries a confidence.
     */
    fun applyResource(list: List<SecurityScanner.Finding>): List<SecurityScanner.Finding> = applyManifest(list)

    fun apply(list: List<SecurityScanner.Finding>, classType: String, appBound: Boolean = false): List<SecurityScanner.Finding> {
        val test = isTestClass(classType)
        for (f in list) {
            try {
                // 0.82.0: an obfuscated class tied to the app's own package is app code: scope APP, none of the OBF lowerings below
                if (appBound && f.scope == SecurityScanner.Scope.OBF) {
                    f.scope = SecurityScanner.Scope.APP
                    f.detail = f.detail + "  [Renamed by R8, but this is the app's own code: the class references the app's package.]"
                }
                if (f.severity == SecurityScanner.Severity.INFO) continue
                if (test) {
                    f.severity = SecurityScanner.Severity.INFO
                    f.adjusted = "Lowered to INFO: test class."
                } else if (f.ruleId in SCOPE_LOWERED_RULES && (f.scope == SecurityScanner.Scope.LIB || f.scope == SecurityScanner.Scope.OBF)) {
                    // 0.66.4: these rules are HIGH confidence about the CODE PATTERN, but the pattern in a third-party SDK (named
                    // library or R8-obfuscated) is not the app developer's decision and is often unused. Exness: a CRITICAL no-op
                    // TrustManager in obfuscated `r9e` stayed CRITICAL because the confidence is HIGH. One level down, reason stored.
                    f.severity = lowered(f.severity)
                    f.adjusted = "Lowered one level: " + (if (f.scope == SecurityScanner.Scope.LIB) "known library" else "obfuscated (likely third-party)") +
                        " code; the pattern is exact but usage / reachability from the app is not checked."
                } else if (LOWER_OBF_API_ONLY && f.ruleId in OBF_API_ONLY_RULES && f.scope == SecurityScanner.Scope.OBF) {
                    f.severity = lowered(f.severity)
                    f.adjusted = "Lowered one level: obfuscated (likely third-party) code; the API is called but no outside value was traced into it."
                } else if (f.scope == SecurityScanner.Scope.LIB && confidenceOf(f) != "HIGH") {
                    f.severity = lowered(f.severity)
                    f.adjusted = "Lowered one level: heuristic finding inside known library code."
                } else if (f.scope == SecurityScanner.Scope.OBF && confidenceOf(f) != "HIGH") {
                    // 0.46.0: obfuscated packages (a/b/c, mu.h) in a real APK are overwhelmingly third-party SDK code after R8;
                    // a heuristic (non-exact) finding there is noise for the app developer, so it is lowered like a library one.
                    // Exact findings (confidence HIGH: traced constant / exact API + argument) are kept, so e.g. an
                    // addJavascriptInterface in the app's obfuscated core code still surfaces at full severity.
                    f.severity = lowered(f.severity)
                    f.adjusted = "Lowered one level: heuristic finding inside obfuscated (likely third-party) code."
                }
            } catch (_: Throwable) { }
        }
        return list
    }

    /**
     * 0.49.5: rules whose risk depends on a caller (another app, a deep link, a crafted Intent) reaching the code. Only these are
     * traced beyond HIGH taint flows, and only these get the "not reached" note. Rules such as crypto, external storage or
     * Application-class code loading are NOT caller-driven: "no path from an exported component" says nothing about them.
     */
    val REACH_RULES: Set<String> = setOf(
        "taint-flow", "webview-file-access", "webview-js-interface", "webview-intent-url", "deeplink-config-poisoning",
        "deeplink-host-validation", "provider-openfile-segment", "intent-redirection", "implicit-intent-sensitive",
        "broadcast-unprotected-send", "shell-exec", "zip-slip", "sql-concat", "uri-grant-via-result", "pick-result-file",
        "log-credential-object", "storage-file-mode"
    )

    /**
     * 0.51.3: rules whose finding is intrinsic (the weakness exists whoever calls it), so a lone AI "false positive" is suspicious.
     * NOT here: `deserialization` (rule confidence HIGH, but NewPipe's in-memory byte[] round trip was a correct AI FP).
     */
    val GUARD_EXACT_RULES: Set<String> = setOf(
        "crypto-hardcoded-key", "crypto-static-iv", "res-strings-url-credentials", "dex-load-writable-dir", "package-context-code"
    )

    /**
     * 0.51.1: rules where "an exported component reaches it" makes an AI false positive suspicious (attacker-controlled input is the
     * point). shell-exec / sql-concat / zip-slip / log rules are NOT here: the benchmark run showed a correct AI "FP" on a constant
     * `which su` root check being turned into REVIEW only because the code was reachable.
     */
    val GUARD_REACH_RULES: Set<String> = setOf(
        "taint-flow", "webview-file-access", "webview-js-interface", "webview-intent-url", "deeplink-config-poisoning",
        "deeplink-host-validation", "provider-openfile-segment", "intent-redirection", "uri-grant-via-result", "pick-result-file"
    )

    /** 0.49.5: true if this finding should be traced by the call graph. Manifest findings (no class) never are. */
    fun wantsReach(f: SecurityScanner.Finding): Boolean {
        if (f.clsIndex < 0) return false
        if (f.ruleId == "taint-flow" && f.severity.rank <= 1) return true
        return f.ruleId in REACH_RULES && f.severity.rank <= 2 && f.scope == SecurityScanner.Scope.APP
    }

    /**
     * 0.49.1 / 0.49.3 / 0.49.5: annotation for findings that the call graph traced and could NOT reach from an exported
     * component. 0.49.1 lowered their severity; the OVAA benchmark showed that was wrong: the call graph follows method calls and
     * (since 0.49.4) explicit launches only, not implicit Intents, so a real flow can look "unreachable". The severity is left alone
     * and only a note is added. Nothing is lowered, nothing is dropped. Since 0.49.5 the note covers every traced finding of
     * [REACH_RULES], not only Intent-sourced taint flows.
     */
    fun applyReach(list: List<SecurityScanner.Finding>): List<SecurityScanner.Finding> {
        for (f in list) {
            try {
                if (f.reach != "NO" || f.adjusted.isNotEmpty() || f.ruleId !in REACH_RULES) continue
                if (f.ruleId == "taint-flow" && !f.detail.startsWith("Data from Intent.")) continue
                f.adjusted = "Not reached from an exported component by method calls or explicit startActivity(new Intent(ctx, X.class)) hops. It can still be reached through implicit Intents with a framework action (VIEW, SEND), string-built ComponentNames or PendingIntents " +
                    "(the call graph follows explicit launches and custom-action implicit Intents only): check who launches this component."
            } catch (_: Throwable) { }
        }
        return list
    }

    /**
     * 0.77.0 (Termux Play build: KeystoreAPI$2, reached only through TermuxService guarded by a SIGNATURE permission): a HIGH / CRITICAL
     * taint finding that the call graph could NOT reach from an exported component (reach == "NO") is lowered ONE level when its class is
     * not an Android component at all (a helper: implicit Intents cannot start it, only a component calling it, and those calls are what the
     * graph follows) or belongs to a component guarded by a signature-level permission (only same-signer apps can start it).
     * A component that is NOT a helper keeps its severity (0.49.1 lesson: OVAA WebViewActivity is reached through an implicit forward).
     * Returns the number lowered.
     */
    fun lowerUnreachedHelpers(list: List<SecurityScanner.Finding>, componentTypes: Set<String>, guardedTypes: Set<String>): Int {
        var n = 0
        for (f in list) {
            try {
                if (f.reach != "NO" || !f.ruleId.startsWith("taint") || f.severity.rank > 1) continue
                val t = f.classType ?: continue
                val outer = if (t.contains('$')) t.substringBefore('$') + ";" else t
                val component = t in componentTypes || outer in componentTypes
                val guarded = t in guardedTypes || outer in guardedTypes
                if (component && !guarded) continue
                f.severity = if (f.severity == SecurityScanner.Severity.CRITICAL) SecurityScanner.Severity.HIGH else SecurityScanner.Severity.MEDIUM
                f.confidence = "LOW"
                val why = if (guarded) "it belongs to a component protected by a signature-level permission (only apps signed with the same key can start it)"
                    else "its class is not an Android component (no other app can start it directly; only the app's components call it, and no exported one does)"
                f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") + "Lowered one level: no exported component reaches it and $why."
                n++
            } catch (_: Throwable) { }
        }
        return n
    }

    /**
     * 0.80.0 (Infinity DownloadedMediaDeleteActionBroadcastReceiver): a HIGH / CRITICAL taint finding whose source is an Intent and whose
     * class (or outer class) is a broadcast RECEIVER or a SERVICE that the manifest does NOT export drops one level (confidence LOW): another
     * app cannot send to it directly, it is reached through the app's own PendingIntents / explicit Intents. Activities are left alone: a
     * non-exported activity is often reached through an exported one that forwards the caller's data (OVAA WebViewActivity, Infinity
     * LinkResolverActivity -> WebViewActivity). [internalTypes] = non-exported receiver / service types. Returns the number lowered.
     */
    fun lowerNonExportedReceivers(list: List<SecurityScanner.Finding>, internalTypes: Set<String>): Int {
        var n = 0
        for (f in list) {
            try {
                if (!f.ruleId.startsWith("taint") || f.severity.rank > 1 || !f.detail.startsWith("Data from Intent.")) continue
                val t = f.classType ?: continue
                val outer = if (t.contains('$')) t.substringBefore('$') + ";" else t
                if (t !in internalTypes && outer !in internalTypes) continue
                f.severity = if (f.severity == SecurityScanner.Severity.CRITICAL) SecurityScanner.Severity.HIGH else SecurityScanner.Severity.MEDIUM
                f.confidence = "LOW"
                f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") +
                    "Lowered one level: the Intent is read in a receiver / service that the manifest does not export, so another app cannot send it directly (only through this app's own PendingIntents or explicit Intents)."
                n++
            } catch (_: Throwable) { }
        }
        return n
    }

    /**
     * 0.81.0: the cleartext configuration cards ("Cleartext (plain HTTP) traffic allowed", "Network Security Config: cleartext permitted")
     * are MEDIUM by default; they go back to HIGH when the app's own code uses a plain-HTTP URL ([CleartextUrlUsedRule] produced a card), which
     * is named in them. Returns the number raised.
     */
    fun applyNetworkEvidence(list: List<SecurityScanner.Finding>): Int {
        val use = list.firstOrNull { it.ruleId == "cleartext-url-used" } ?: return 0
        var n = 0
        for (f in list) {
            if (f.ruleId != "manifest-cleartext-traffic" && f.ruleId != "res-nsc-cleartext") continue
            if (f.severity != SecurityScanner.Severity.MEDIUM) continue
            f.severity = SecurityScanner.Severity.HIGH
            f.detail = f.detail + " Raised to HIGH: the app's own code uses a plain-HTTP URL (" + (use.classType ?: "?").removePrefix("L").removeSuffix(";").replace('/', '.') + ")."
            n++
        }
        return n
    }

    /**
     * 0.81.0 (AnkiDroid CardContentProvider): the manifest card "Exported provider without a permission: X" drops to LOW (confidence LOW)
     * when the provider class X produced a [ProviderCodePermissionRule] marker (every data method checks the caller in code).
     */
    fun applyProviderCodeChecks(list: List<SecurityScanner.Finding>): Int {
        val checked = list.filter { it.ruleId == "provider-code-permission" }.mapNotNull { it.classType }
            .map { it.removePrefix("L").removeSuffix(";").replace('/', '.') }.toSet()
        if (checked.isEmpty()) return 0
        var n = 0
        for (f in list) {
            if (f.ruleId != "manifest-exported-components" || !f.title.startsWith("Exported provider without a permission:")) continue
            val name = f.title.substringAfter(":").trim()
            if (checked.none { it == name || it.endsWith(name) || name.endsWith(it) }) continue
            if (f.severity == SecurityScanner.Severity.LOW && f.adjusted.contains("checks the calling app in code")) continue   // reachPass runs per report
            f.severity = SecurityScanner.Severity.LOW
            f.confidence = "LOW"
            f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") +
                "Lowered: the manifest has no permission, but every data method of the provider checks the calling app in code (see the provider-code-permission note)."
            n++
        }
        return n
    }

    /**
     * 0.81.0 (AnkiDroid: ACRA's crash dialog, exported=false, in its own `:acra` process): a HIGH / CRITICAL taint finding whose Intent was
     * handed over by a NON-exported activity that runs in a SEPARATE process (the activity type appears in the finding's chain / via text)
     * drops one level: such a dialog is started by the app's own crash handler, not by another app. Narrow on purpose: non-exported activities
     * in the main process keep their severity (OVAA, Infinity: forwarded by exported ones). Returns the number lowered.
     */
    fun lowerSeparateProcessDialogs(list: List<SecurityScanner.Finding>, separateProcessActivities: Set<String>): Int {
        if (separateProcessActivities.isEmpty()) return 0
        var n = 0
        for (f in list) {
            if (!f.ruleId.startsWith("taint") || f.severity.rank > 1 || !f.detail.startsWith("Data from Intent.")) continue
            val hit = separateProcessActivities.firstOrNull { f.detail.contains(it) || f.classType == it } ?: continue
            f.severity = if (f.severity == SecurityScanner.Severity.CRITICAL) SecurityScanner.Severity.HIGH else SecurityScanner.Severity.MEDIUM
            f.confidence = "LOW"
            f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") +
                "Lowered one level: the Intent belongs to " + hit.removePrefix("L").removeSuffix(";").replace('/', '.') + ", an activity that is not exported and runs in its own process (a crash / report dialog started by the app itself)."
            n++
        }
        return n
    }

    /** 0.81.0: smali types of NOT exported activities declared with their own android:process. */
    fun separateProcessActivities(mc: ManifestContext): Set<String> =
        mc.components.filter { !it.exported && it.tag == "activity" && it.headerAttrs.contains("android:process=") }
            .map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.toSet()

    /**
     * 0.84.0 (OpenTracks `CustomContentProvider`, exported=false): the text rules on provider code ([provider-sql-injection],
     * [provider-openfile-segment]) look at the class only. A provider the manifest does not export is reached only by the app itself or through
     * a URI it grants, so the finding drops one level (confidence LOW) and says why. Returns the number lowered.
     */
    fun lowerNonExportedProviders(list: List<SecurityScanner.Finding>, nonExportedProviders: Set<String>): Int {
        if (nonExportedProviders.isEmpty()) return 0
        var n = 0
        for (f in list) {
            try {
                if (f.ruleId != "provider-sql-injection" && f.ruleId != "provider-openfile-segment") continue
                if (f.adjusted.contains("not exported")) continue                      // reachPass runs per report: idempotent
                val t = f.classType ?: continue
                val outer = if (t.contains('$')) t.substringBefore('$') + ";" else t
                if (t !in nonExportedProviders && outer !in nonExportedProviders) continue
                f.severity = when (f.severity) {
                    SecurityScanner.Severity.CRITICAL -> SecurityScanner.Severity.HIGH
                    SecurityScanner.Severity.HIGH -> SecurityScanner.Severity.MEDIUM
                    SecurityScanner.Severity.MEDIUM -> SecurityScanner.Severity.LOW
                    else -> f.severity
                }
                f.confidence = "LOW"
                f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") +
                    "Lowered one level: this provider is not exported by the manifest, so another app cannot call it directly (only this app, or a URI it grants with grantUriPermissions)."
                n++
            } catch (_: Throwable) { }
        }
        return n
    }

    /**
     * Smali types of the providers the manifest does NOT export. 0.84.0 (OpenTracks: the manifest declares `ShareContentProvider`, exported=false,
     * and the SQL text rule fires in its app-class BASE `CustomContentProvider`): the superclass chain of every declared provider counts too
     * ([superOf] gives the superclass of an app class, null at a framework class), minus every class that is also in the chain of an EXPORTED provider.
     */
    fun nonExportedProviders(mc: ManifestContext, superOf: (String) -> String? = { null }): Set<String> {
        fun chain(t: String): List<String> {
            val out = ArrayList<String>(); var c: String? = t; var n = 0
            while (c != null && n++ < 8) { out.add(c); c = superOf(c) }
            return out
        }
        val exported = mc.components.filter { it.exported && it.tag == "provider" }.map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.flatMap { chain(it) }.toSet()
        val internal = mc.components.filter { !it.exported && it.tag == "provider" }.map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.flatMap { chain(it) }.toSet()
        return internal - exported
    }

    /**
     * 0.85.0 (Quillpad): the 0.66.4 rule lowers a TLS finding in obfuscated code one level because such code is usually an unused third-party SDK
     * (Exness `r9e`). When the app really INSTALLS the class (a method instantiates it and calls `SSLContext.init`, see
     * [SecurityScanner.tlsInstalled]) it is in use and the finding goes back up one level. Run after the whole scan. Returns the number restored.
     */
    fun restoreInstalledTls(list: List<SecurityScanner.Finding>): Int {
        if (SecurityScanner.tlsInstalled.isEmpty()) return 0
        var n = 0
        for (f in list) {
            try {
                if (f.ruleId !in SCOPE_LOWERED_RULES || f.scope != SecurityScanner.Scope.OBF) continue
                if (!f.adjusted.startsWith("Lowered one level: obfuscated")) continue
                val t = f.classType ?: continue
                if (t !in SecurityScanner.tlsInstalled) continue
                f.severity = when (f.severity) {
                    SecurityScanner.Severity.HIGH -> SecurityScanner.Severity.CRITICAL
                    SecurityScanner.Severity.MEDIUM -> SecurityScanner.Severity.HIGH
                    SecurityScanner.Severity.LOW -> SecurityScanner.Severity.MEDIUM
                    else -> f.severity
                }
                f.adjusted = "Restored one level: an obfuscated class, but a method of this app instantiates it and installs it (SSLContext.init, a hostname-verifier / socket-factory setter), so it is in use."
                n++
            } catch (_: Throwable) { }
        }
        return n
    }

    /**
     * 0.86.1 (recall kit case 03): a "Hardcoded sensitive field" card that 0.86.0 left at MEDIUM because its OWN class never uses the value goes to
     * HIGH when another class reads the field in a method that uses a secret sink ([SecurityScanner.secretFieldsUsed]). Run after the whole scan.
     * Returns the number raised.
     */
    fun raiseUsedSecretFields(list: List<SecurityScanner.Finding>): Int {
        if (SecurityScanner.secretFieldsUsed.isEmpty()) return 0
        var n = 0
        for (f in list) {
            try {
                if (f.ruleId != "secrets-sensitive-fields" || f.severity != SecurityScanner.Severity.MEDIUM) continue
                val prefix = "Hardcoded sensitive field: "
                if (!f.title.startsWith(prefix)) continue
                val t = f.classType ?: continue
                if (t + "->" + f.title.removePrefix(prefix) !in SecurityScanner.secretFieldsUsed) continue
                f.severity = SecurityScanner.Severity.HIGH
                f.confidence = "HIGH"
                f.detail = f.detail + " Another class reads this field in a method that uses it as a key / credential (a crypto call, an Authorization header, credentials): it is a working secret."
                n++
            } catch (_: Throwable) { }
        }
        return n
    }

    /**
     * 0.94.0: the key sources the hard-coded key rule could not resolve inside one class: a finding for each one that ends at a constant (another class's static byte[] filled from a
     * literal, or a ()[B method returning it). Returns the findings to add; run once after the whole scan.
     */
    fun resolvePendingKeys(): List<SecurityScanner.Finding> {
        val out = ArrayList<SecurityScanner.Finding>(); val seen = HashSet<String>()
        for (p in SecurityScanner.pendingKeys.toList()) {
            if (!SecurityScanner.isConstBytes(p.source) || !seen.add(p.classType + p.at)) continue
            out.add(SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "Hardcoded encryption key",
                "A ${p.spec} is built from ${p.source.removePrefix("L").replace(';', ' ').replace("->", "")}, which the app fills from a constant (a literal or Base64.decode of a literal, in its class initialiser): the key sits in the APK, so anyone who decompiles it can decrypt / forge whatever it protects.",
                "Generate the key at runtime into the Android Keystore (KeyGenParameterSpec) or derive it from a user secret with PBKDF2; never compile it in.",
                p.classType, p.clsIndex, p.at, "CWE-321").also { it.ruleId = "crypto-hardcoded-key"; it.confidence = "HIGH"; it.scope = SecurityScanner.scopeOf(p.classType, p.appPkg) })
        }
        return out
    }

    /**
     * 0.94.0: an exported component without a manifest permission whose class checks the CALLER in code (its package and signing certificate, or a calling permission) is protected,
     * just not by the manifest: the card drops to LOW and says so. K-9 Mail's SettingsProvider (set 11) was a HIGH false positive. Returns the number lowered.
     */
    fun lowerCallerVerified(list: List<SecurityScanner.Finding>): Int {
        if (SecurityScanner.callerVerified.isEmpty()) return 0
        var n = 0
        for (f in list) {
            if (f.ruleId != "manifest-exported-components" || f.severity.rank > 2) continue
            val name = f.title.substringAfter(": ", "").trim()
            if (name.isEmpty() || !name.contains('.')) continue
            if ("L" + name.replace('.', '/') + ";" !in SecurityScanner.callerVerified) continue
            f.severity = SecurityScanner.Severity.LOW
            f.detail = f.detail + " The component's code checks the CALLER (its package and signing certificate, or a calling permission) before it serves a request, so it is protected in code rather than by the manifest; review that check."
            n++
        }
        return n
    }

    /** 0.80.0: smali types of the receivers and services the manifest does NOT export. */
    /**
     * 0.108.0 (WE Wallet SignUpWebViewActivity, exported="false": "Untrusted input is loaded into a WebView" HIGH, its URL read with getStringExtra): a non-exported activity is often
     * reached through an exported one that FORWARDS the caller's data (OVAA, Infinity), so it keeps its severity by default. When every extra the activity reads has writers in the
     * app and EVERY writer puts a constant or a string resource (IntentExtras), no caller's data can arrive that way: the HIGH / CRITICAL Intent-extra taint card drops one level,
     * naming the writers. One forwarding, user-input, stored, remote or unknown writer keeps it as it is; an activity whose reads were not seen (encrypted names) is left alone.
     */
    fun lowerConstantFedActivities(list: List<SecurityScanner.Finding>, internalActivities: Set<String>): Int {
        var n = 0
        val extraSource = Regex("^Data from Intent\\.get[A-Za-z]*Extra\\(")
        for (f in list) {
            try {
                if (!f.ruleId.startsWith("taint") || f.severity.rank > 1 || !extraSource.containsMatchIn(f.detail)) continue
                val t = f.classType ?: continue
                val outer = if (t.contains('$')) t.substringBefore('$') + ";" else t
                if (outer !in internalActivities) continue
                val reads = IntentExtras.readsOf(outer.removePrefix("L").removeSuffix(";").replace('/', '.')).filter { it.kind != "query" }
                if (reads.isEmpty()) continue
                val writers = reads.map { IntentExtras.writesOf(it.key) }
                if (writers.any { it.isEmpty() }) continue
                val all = writers.flatten()
                if (!all.all { it.origin == "CONSTANT" || it.origin == "RESOURCE" }) continue
                f.severity = if (f.severity == SecurityScanner.Severity.CRITICAL) SecurityScanner.Severity.HIGH else SecurityScanner.Severity.MEDIUM
                f.confidence = "LOW"
                f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") + "Lowered one level: this activity is not exported, and every place in the app that sets the extra(s) it reads (" +
                    reads.joinToString(", ") { "\"" + it.key + "\"" } + ") puts a fixed value: " + all.take(4).joinToString("; ") { it.classType.removePrefix("L").removeSuffix(";").substringAfterLast('/') + "." + it.method + "() sets \"" + it.key + "\" from " + it.detail } +
                    ". Another app cannot supply that value, unless it reaches this activity in a way the scanner does not see (a PendingIntent, reflection)."
                n++
            } catch (_: Throwable) { }
        }
        return n
    }

    /** 2.1.0: switch for the mutation check of [raiseReflectedUriGrant]. */
    internal var RAISE_REFLECTED_GRANT = true

    /**
     * 2.1.0 (real-CVE benchmark C09, Nextcloud News SettingsActivity.onStart: setResult(RESULT_OK, getIntent())): an EXPORTED activity that hands the caller's own Intent back
     * through setResult() lets that caller name any content:// Uri and FLAG_GRANT_*_URI_PERMISSION in the Intent it started the activity with; the system then grants it. With a
     * provider in the manifest that declares grantUriPermissions="true" (and is not exported, so nothing else reaches its data), that is a read of the app's private files by any app:
     * HIGH. Without such a provider, or in a not-exported activity, the card stays at the rule's MEDIUM. Returns the number raised; idempotent.
     */
    fun raiseReflectedUriGrant(list: List<SecurityScanner.Finding>, mc: ManifestContext): Int {
        if (!RAISE_REFLECTED_GRANT) return 0
        val grantProvider = mc.components.any { it.tag == "provider" && it.headerAttrs.contains("grantUriPermissions=\"true\"") }
        if (!grantProvider) return 0
        val exportedActivities = mc.components.filter { it.exported && (it.tag == "activity" || it.tag == "activity-alias") }.map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.toSet()
        var n = 0
        for (f in list) {
            try {
                if (f.ruleId != "uri-grant-via-result" || f.severity != SecurityScanner.Severity.MEDIUM || !f.detail.contains("returns the Intent this activity was started with (getIntent())")) continue
                val t = f.classType ?: continue
                val outer = if (t.contains('$')) t.substringBefore('$') + ";" else t
                if (outer !in exportedActivities) continue
                f.severity = SecurityScanner.Severity.HIGH
                f.confidence = "MEDIUM"
                f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") +
                    "Raised to HIGH: this activity is exported and the manifest declares a provider with grantUriPermissions=\"true\", so the Uri the caller put in the Intent it started this activity with is granted to it."
                n++
            } catch (_: Throwable) { }
        }
        return n
    }

    /** 2.0.2: switch for the mutation check of [lowerUnforwardedPrivateIntentFlows]. */
    internal var PRIVATE_COMPONENT_CARDS = true

    /**
     * 2.0.2 (WE Wallet SignUpWebViewActivity, `android:exported="false"`, still MUST FIX in 2.0.1): the card was made by the single-class IR rule ("a flow inside one class"),
     * which cannot know who builds the Intent, and the reach pass gave it `YES` because a METHOD CALL chain links the exported launcher to that class. 2.0.1 fixed this only
     * in the SSA engine. The rule for every engine: a HIGH / CRITICAL taint card whose value comes from an Intent getter in an Activity / Service the manifest does NOT export stays
     * as it is only when the SSA engine proved that a tainted value flows into the Intent that launches that component ([forwarded], recorded at write time by TaintIr), or when
     * an exported component launches an Intent it received ([openRedirector]). Otherwise it drops one level, confidence LOW, and its reach is approximate (`YES~`), never `YES`.
     * Cards of the SSA engine are skipped (they carry the rule themselves). Idempotent. Returns the number lowered.
     */
    fun lowerUnforwardedPrivateIntentFlows(list: List<SecurityScanner.Finding>, privateComponents: Set<String>, forwarded: Set<String>, openRedirector: Boolean): Int {
        if (!PRIVATE_COMPONENT_CARDS || openRedirector || privateComponents.isEmpty()) return 0
        val intentSource = Regex("^Data from Intent\\.get[A-Za-z]*\\(")
        var n = 0
        for (f in list) {
            try {
                if (!f.ruleId.startsWith("taint") || f.severity.rank > 1 || !intentSource.containsMatchIn(f.detail)) continue
                if (f.detail.contains("SSA data-flow engine") || f.adjusted.contains("not forwarded")) continue
                val t = f.classType ?: continue
                val outer = if (t.contains('$')) t.substringBefore('$') + ";" else t
                if (outer !in privateComponents || outer in forwarded) continue
                f.severity = if (f.severity == SecurityScanner.Severity.CRITICAL) SecurityScanner.Severity.HIGH else SecurityScanner.Severity.MEDIUM
                f.confidence = "LOW"
                if (f.reach == "YES") f.reach = "YES~"
                f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") +
                    "Lowered one level: this component is not exported and no tainted value was proven to flow into the Intent that starts it (a method-call path from an exported component is not " +
                    "a data flow); not forwarded, so another app cannot supply this value unless it reaches the component in a way the scanner does not see (a PendingIntent, reflection)."
                n++
            } catch (_: Throwable) { }
        }
        return n
    }

    /** smali types of Activities and Services the manifest does NOT export (outer classes). */
    fun privateActivitiesAndServices(mc: ManifestContext): Set<String> =
        mc.components.filter { !it.exported && (it.tag == "activity" || it.tag == "service") }.map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.toSet()

    /** Phase 3: switch for the mutation check of [lowerGuardedProviderFlows]. */
    internal var PROVIDER_CONTEXT = true

    /**
     * Maturity protocol phase 3 (Nextcloud DiskLruImageCacheFileProvider: exported, android:permission="android.permission.MANAGE_DOCUMENTS"; the class-level flow
     * "Data from a ContentProvider method parameter ... reaches FileOutputStream" was HIGH): a HIGH / CRITICAL taint card whose source is a ContentProvider parameter and whose
     * class (or outer class) is a provider that the manifest does NOT export, or that only a SIGNATURE-level permission opens (PermissionGuard: signature / signatureOrSystem /
     * privileged / system, or a platform permission such as MANAGE_DOCUMENTS / BIND_*), drops one level with confidence LOW. A dangerous or normal permission (READ_SMS) is not a
     * guard: the card stays. The provider's guard for the operation is the weaker of read and write. Returns the number lowered; idempotent.
     */
    fun lowerGuardedProviderFlows(list: List<SecurityScanner.Finding>, mc: ManifestContext, guard: PermissionGuard): Int {
        if (!PROVIDER_CONTEXT) return 0
        val providers = mc.components.filter { it.tag == "provider" }.groupBy { mc.smaliTypeOf(it) }.filterKeys { it.isNotEmpty() }
        var n = 0
        for (f in list) {
            try {
                if (!f.ruleId.startsWith("taint") || f.severity.rank > 1 || !f.detail.startsWith("Data from a ContentProvider method parameter")) continue
                if (f.adjusted.contains("provider is not exported") || f.adjusted.contains("signature-level permission guards this provider")) continue
                val t = f.classType ?: continue
                val outer = if (t.contains('$')) t.substringBefore('$') + ";" else t
                val key = if (providers.containsKey(t)) t else outer
                val entries = providers[key] ?: continue
                val why = when {
                    entries.none { it.exported } -> "the provider is not exported (only the app itself, or a URI it grants, reaches it)"
                    guard.guardFor(key, PermissionGuard.Access.ANY) == PermissionGuard.Guard.SIGNATURE ->
                        "a signature-level permission guards this provider (" + (entries.first { it.exported }.let { it.permission ?: it.readPermission ?: it.writePermission } ?: "") + "): only apps signed with the same key, or the system, can call it"
                    else -> continue
                }
                f.severity = if (f.severity == SecurityScanner.Severity.CRITICAL) SecurityScanner.Severity.HIGH else SecurityScanner.Severity.MEDIUM
                f.confidence = "LOW"
                f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") + "Lowered one level: $why."
                n++
            } catch (_: Throwable) { }
        }
        return n
    }

    /** 0.108.0: smali types of NOT exported activities. */
    fun nonExportedActivities(mc: ManifestContext): Set<String> =
        mc.components.filter { !it.exported && it.tag == "activity" }.map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.toSet()

    fun nonExportedReceiversAndServices(mc: ManifestContext): Set<String> =
        mc.components.filter { !it.exported && (it.tag == "receiver" || it.tag == "service") }.map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.toSet()

    /**
     * 0.51.0: an AI "false positive" verdict is a second opinion, not a fact (the same InsecureBankv2 finding was FP in one run and TP
     * in the next). If the rule itself marked the finding HIGH confidence, or it is a caller-driven finding (REACH_RULES) that the call graph
     * reaches from an exported component (exact or approximate), the verdict becomes REVIEW and the AI's reason stays in the note.
     * Returns true when the verdict was changed.
     */
    fun guardFalsePositive(f: SecurityScanner.Finding): Boolean {
        if (f.verdict != "FP") return false
        val exact = f.confidence == "HIGH" && f.ruleId in GUARD_EXACT_RULES   // 0.51.3: only intrinsic weaknesses
        val reached = f.ruleId in GUARD_REACH_RULES && f.reach.startsWith("YES")
        if (!exact && !reached) return false
        // 0.51.2: a confident AI reason about what the code really does is kept (Aegis: `equals("offline")` flagged as indexOf host check,
        // AI 90% FP, was right). The guard is for the unsure / unstable verdicts and for exact rules.
        val conf = Regex("\\(confidence (\\d+)%\\)").find(f.verdictNote)?.groupValues?.get(1)?.toIntOrNull() ?: -1
        if (!exact && conf >= 85) return false
        f.verdict = "REVIEW"
        f.verdictNote = ("AI said false positive, but " + (if (exact) "an exact rule matched" else "an exported component reaches this code") +
            " (AI verdicts are not stable between runs): look at it yourself.\nAI reason: " + f.verdictNote).trim()
        return true
    }
}
