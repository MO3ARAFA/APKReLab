package dev.apkrelab

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

/**
 * 0.40.0: plugin-style scan rules. A rule is one small object; the registry runs all of them per class
 * from SecurityScanner.scanSmali (right before the findings of a class are merged).
 *
 * How to add a rule (no other file needs to change):
 *   1. write `object MyRule : ScanRule { override val id = "my-rule"; override val title = "..."; override fun scan(ctx: RuleContext) = ... }`
 *   2. add `register(MyRule)` in [RuleRegistry] init
 *   3. add one line to Capabilities.SCANNER and, if the CWE is new, one `put(Entry(...))` in VulnKnowledge.
 * A rule that throws is skipped for that class and counted in [RuleRegistry.errors]; it never stops the scan.
 * 0.42.0: AndroidManifest.xml rules are a second kind (ManifestRule, ScanRulesManifest.kt) in the same registry.
 * 0.43.0: res/ XML and resources.arsc rules are a third kind (ResourceRule, ScanRulesResources.kt).
 * 0.44.0: TaintFlowRule (ScanRulesTaint.kt) follows data from Intent / JS-bridge / provider inputs to dangerous APIs inside one class.
 */
class RuleContext(
    val classType: String,
    val clsIndex: Int,
    val text: String,          // baksmali text of the class
    val appPkg: String
) {
    val scope: SecurityScanner.Scope by lazy { SecurityScanner.scopeOfText(classType, appPkg, text) }   // 0.83.0: text-aware (repackaged libraries)

    /**
     * 0.75.0: the class parsed into the IR (methods + instructions), built at most once per class and only when an IR rule asks for it
     * (each IR rule checks the raw text for its trigger API first). null when the parser fails: the rule then falls back or stays quiet.
     */
    val ir: dev.apkrelab.ir.ClassIr? by lazy { try { dev.apkrelab.ir.SmaliParser.parse(text) } catch (_: Throwable) { null } }

    /** Builds a finding with the "(around line N)" suffix every other check uses. */
    fun finding(sev: SecurityScanner.Severity, title: String, detail: String, rec: String, offset: Int, cwe: String): SecurityScanner.Finding =
        SecurityScanner.Finding(sev, title, detail + "  (around line ${SecurityScanner.lineNo(text, offset)})", rec, classType, clsIndex, offset, cwe)
}

interface ScanRule {
    val id: String
    val title: String
    /** Weaknesses this rule can report; every one must have an entry in VulnKnowledge (see [RuleRegistry.audit]). */
    val cwes: List<String> get() = emptyList()
    /** HIGH = exact API / traced constant, MEDIUM = heuristic, LOW = informational; "" = FindingPolish decides from the title. */
    val confidence: String get() = ""
    fun scan(ctx: RuleContext): List<SecurityScanner.Finding>
}

object RuleRegistry {
    private val rules = CopyOnWriteArrayList<ScanRule>()
    private val manifestRules = CopyOnWriteArrayList<ManifestRule>()   // 0.42.0: AndroidManifest.xml rules (ScanRulesManifest.kt)
    private val resourceRules = CopyOnWriteArrayList<ResourceRule>()   // 0.43.0: res/ XML + resources.arsc rules (ScanRulesResources.kt)
    val errors = AtomicInteger(0)
    private val ruleErrors = ConcurrentHashMap<String, AtomicInteger>()

    fun register(r: ScanRule) {
        if (rules.none { it.id == r.id }) rules.add(r)
    }

    /** 0.42.0: manifest rules run once per manifest (not per class), see [runManifest]. */
    fun registerManifest(r: ManifestRule) {
        if (manifestRules.none { it.id == r.id }) manifestRules.add(r)
    }

    /** 0.43.0: resource rules run once per resource file (decoded XML, plain values file, arsc string pool), see [runResource]. */
    fun registerResource(r: ResourceRule) {
        if (resourceRules.none { it.id == r.id }) resourceRules.add(r)
    }

    fun ids(): List<String> = rules.map { it.id + ": " + it.title } + manifestRules.map { it.id + ": " + it.title } + resourceRules.map { it.id + ": " + it.title }

    fun count(): Int = rules.size


    fun resourceCount(): Int = resourceRules.size

    /** Counts a failure that a rule (or the manifest parser) handled itself, so it shows up in [errorReport]. */
    fun noteError(id: String) {
        errors.incrementAndGet()
        ruleErrors.getOrPut(id) { AtomicInteger(0) }.incrementAndGet()
    }

    /** Rules that threw at least once, with how many times (empty = all healthy). */
    fun errorReport(): String =
        ruleErrors.entries.sortedByDescending { it.value.get() }.joinToString("\n") { it.key + ": " + it.value.get() }

    /** CWEs reported by a rule that have no VulnKnowledge entry (should be empty). */
    fun audit(): List<String> {
        val missing = LinkedHashSet<String>()
        for (r in rules) for (c in r.cwes) if (VulnKnowledge.forCwe(c) == null) missing.add(r.id + " -> " + c)
        for (r in manifestRules) for (c in r.cwes) if (VulnKnowledge.forCwe(c) == null) missing.add(r.id + " -> " + c)
        for (r in resourceRules) for (c in r.cwes) if (VulnKnowledge.forCwe(c) == null) missing.add(r.id + " -> " + c)
        return missing.toList()
    }

    /**
     * Runs every rule over one class, in registration order. A rule that throws is skipped (its findings for this class are lost,
     * every other rule is unaffected) and counted. Classes are already scanned in parallel by the caller (runDeepScan workers),
     * so rules run sequentially inside one class: no shared state, no locking, deterministic order.
     */
    fun runAll(ctx: RuleContext): List<SecurityScanner.Finding> {
        val out = ArrayList<SecurityScanner.Finding>()
        for (r in rules) {
            try {
                val got = r.scan(ctx)
                for (f in got) {
                    if (f.ruleId.isEmpty()) f.ruleId = r.id
                    if (f.confidence.isEmpty() && r.confidence.isNotEmpty()) f.confidence = r.confidence
                }
                out.addAll(got)
            } catch (_: Throwable) {
                errors.incrementAndGet()
                ruleErrors.getOrPut(r.id) { AtomicInteger(0) }.incrementAndGet()
            }
        }
        return out
    }

    /**
     * 0.42.0: runs every manifest rule over the parsed manifest, in registration order. A rule that throws is skipped
     * (its findings are lost, every other rule is unaffected) and counted. Component rules also isolate one malformed
     * component each (see ManifestComponentRule).
     */
    fun runManifest(ctx: ManifestContext): List<SecurityScanner.Finding> {
        val out = ArrayList<SecurityScanner.Finding>()
        for (r in manifestRules) {
            try {
                val got = r.scan(ctx)
                for (f in got) {
                    if (f.ruleId.isEmpty()) f.ruleId = r.id
                    if (f.confidence.isEmpty() && r.confidence.isNotEmpty()) f.confidence = r.confidence
                }
                out.addAll(got)
            } catch (_: Throwable) {
                noteError(r.id)
            }
        }
        return out
    }

    /**
     * 0.43.0: runs every resource rule that applies to ONE resource file, in registration order. A rule that throws is skipped
     * (its findings for this file are lost, every other rule is unaffected) and counted, like the other two kinds of rule.
     */
    fun runResource(ctx: ResourceContext): List<SecurityScanner.Finding> {
        val out = ArrayList<SecurityScanner.Finding>()
        for (r in resourceRules) {
            try {
                if (!r.appliesTo(ctx)) continue
                val got = r.scan(ctx)
                for (f in got) {
                    if (f.ruleId.isEmpty()) f.ruleId = r.id
                    if (f.confidence.isEmpty() && r.confidence.isNotEmpty()) f.confidence = r.confidence
                }
                out.addAll(got)
            } catch (_: Throwable) {
                noteError(r.id)
            }
        }
        return out
    }

    init {
        // 1. the former inline checks, in their ORIGINAL order (the order decides which finding of a duplicate title is kept)
        register(WebviewJsInterfaceRule)
        register(JsBridgeMethodRule)           // 0.78.0
        register(JacksonDefaultTypingRule)     // 0.100.0
        register(SqlCipherPassphraseRule)      // 0.100.0
        register(ProviderCodePermissionRule)   // 0.81.0
        register(CleartextUrlUsedRule)         // 0.81.0
        register(WebviewFileAccessRule)
        register(WebviewMixedContentRule)
        register(WebviewDebuggingRule)
        register(WebviewSslErrorRule)
        register(CryptoCipherRule)
        register(CryptoWeakHashRule)
        register(CryptoHardcodedKeyRule)
        register(CryptoStaticIvRule)
        register(CryptoPbkdf2IterationsRule)
        register(CryptoSha1prngSeedRule)
        register(JwtHardcodedSecretRule)
        register(IntentRedirectionRule)
        register(FragmentInjectionRule)
        register(WebviewIntentUrlRule)
        register(OkhttpLoggingRule)
        register(SecretsKnownFormatsRule)
        register(SecretsVendorTokensRule)   // 0.89.0
        register(SecretsGoogleApiKeyRule)
        register(SecretsSensitiveFieldsRule)
        register(TlsTrustmanagerRule)
        register(TlsHostnameVerifierRule)
        register(TlsInsecureSocketFactoryRule)
        register(StorageFileModeRule)
        register(PendingintentMutableRule)
        register(ReceiverExportFlagRule)
        register(DeserializationRule)
        register(IntentParseuriRule)
        register(DynamicCodeLoadingRule)
        register(ExternalStorageRule)
        register(ShellExecRule)
        register(CleartextUrlRule)
        register(LogSensitiveStringsRule)
        register(SqlConcatRule)
        register(WeakRandomRule)
        register(ZipSlipRule)
        register(TlsProtocolVersionRule)
        register(ProviderSqlInjectionRule)
        // 2. the two scanners that always ran after the inline block
        register(AndroGoatRule)
        register(EntropyRule)
        // 3. rules added in 0.40.0
        register(DeviceIdentifierRule)
        register(WeakKeySizeRule)
        // 3b. 0.44.0: taint analysis (ScanRulesTaint.kt), last of the code rules so its findings never decide a duplicate-title merge
        register(TaintFlowRule)
        // 3c. 0.46.0: dedicated Firebase Realtime DB URL rule (exact host regex, smali string pool) - closes the AndroGoat MISS
        register(FirebaseDbUrlRule)
        // 3d. 0.48.0: rules written from the OVAA vulnerability list (ScanRulesOvaa.kt)
        register(BroadcastUnprotectedSendRule)
        register(ImplicitIntentSensitiveRule)
        register(SqliteUnencryptedRule)        // 0.75.0 (ScanRulesIr.kt)
        register(WebviewPluginStateRule)       // 0.75.0 (ScanRulesIr.kt)
        register(DangerousSerializableRule)
        register(ProviderOpenFileSegmentRule)
        register(PackageContextCodeRule)
        register(DexLoadWritableDirRule)
        register(PickResultFileRule)
        register(DeeplinkHostValidationRule)
        register(DeeplinkConfigPoisoningRule)
        register(UriGrantViaResultRule)
        register(LogCredentialObjectRule)   // 0.48.2
        // 3e. 0.52.0: financial-app-focused rules (ScanRulesFinTech.kt) - trading/banking/fintech SAST modules
        register(FinancialAsyncTaintRule)
        register(UnencryptedSensitiveStorageRule)
        register(InsecureWebSocketRule)
        register(ExportedSensitiveActionRule)
        register(FridaDetectionRule)
        // 4. 0.42.0: manifest rules (ScanRulesManifest.kt), in the order of the former scanManifest body
        registerManifest(ManifestDebuggableRule)
        registerManifest(ManifestTestOnlyRule)
        registerManifest(ManifestAllowBackupRule)
        registerManifest(ManifestCleartextTrafficRule)
        registerManifest(ManifestNetworkSecurityConfigRule)
        registerManifest(ManifestDeepLinksRule)
        registerManifest(ManifestTaskHijackingRule)
        registerManifest(ManifestPermissionProtectionRule)
        registerManifest(ManifestExportedComponentsRule)
        registerManifest(ManifestProviderPartialPermissionRule)
        registerManifest(ManifestProviderGrantUriRule)
        registerManifest(ManifestPowerfulPermissionsRule)
        registerManifest(ManifestSensitivePermissionsRule)
        registerManifest(ManifestMinSdkRule)
        registerManifest(ManifestTargetSdkRule)
        registerManifest(ManifestSharedUserIdRule)
        registerManifest(ManifestLegacyExternalStorageRule)
        registerManifest(ManifestAccessibilityServiceRule)
        // 5. 0.43.0: resource rules (ScanRulesResources.kt): network security config first, then secrets in strings
        registerResource(NscCleartextRule)
        registerResource(TapjackingLayoutRule) // 0.75.0 (ScanRulesIr.kt)
        registerResource(NscCleartextDomainsRule)
        registerResource(NscUserCaRule)
        registerResource(NscOverridePinsRule)
        registerResource(NscNoPinningRule)
        registerResource(NscPinLifecycleRule)
        registerResource(ResGoogleApiKeyRule)
        registerResource(ResFirebaseUrlRule)
        registerResource(ResAwsKeysRule)
        registerResource(ResJwtRule)
        registerResource(ResKnownTokensRule)
        registerResource(ResUrlCredentialsRule)
        registerResource(ResSecretNamesRule)
    }
}

/** AndroGoat benchmark checks (AndroGoatChecks.kt: storage, clipboard, biometric, pinning, cloud keys ...). Unchanged code, wrapped as a rule. */
object AndroGoatRule : ScanRule {
    override val id = "androgoat-checks"
    override val title = "AndroGoat / MASTG benchmark checks"
    override fun scan(ctx: RuleContext): List<SecurityScanner.Finding> =
        AndroGoatChecks.scan(ctx.classType, ctx.clsIndex, ctx.text, ctx.appPkg)
}

/**
 * 0.46.0: Firebase Realtime Database URL as a standalone code rule. The AndroGoat check and the arsc string rules only fire
 * under specific conditions (literal length window, SDK class present, pool parse); this one is the guaranteed catch:
 * it matches the exact host shape (https://<project>.firebaseio.com, also the regional firebasedatabase.app hosts) in ANY
 * const-string of the class, independent of the Firebase SDK and of how the URL was built. Library classes are skipped.
 */
object FirebaseDbUrlRule : ScanRule {
    override val id = "firebase-db-url"
    override val title = "Insecure Firebase Realtime Database URL"
    override val cwes = listOf("CWE-284")
    override val confidence = "HIGH"

    private val hostRe = rx("https://[a-zA-Z0-9_-]+\\.(?:firebaseio\\.com|firebasedatabase\\.app)")
    private val litRe = rx("const-string(?:/jumbo)?\\s+[vp]\\d+,\\s*\"([^\"\\n]{10,400})\"")
    private val fakeHosts = setOf("project-id", "your-project", "yourproject", "my-project", "example", "demo")

    override fun scan(ctx: RuleContext): List<SecurityScanner.Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        if (!ctx.text.contains("firebaseio.com") && !ctx.text.contains("firebasedatabase.app")) return emptyList()
        val urls = LinkedHashSet<String>()
        for (m in litRe.findAll(ctx.text)) {
            val h = hostRe.find(m.groupValues[1]) ?: continue
            val pid = h.value.removePrefix("https://").substringBefore('.')
            if (pid in fakeHosts || pid.contains("your") || pid.contains("xxxx")) continue
            urls.add(h.value)
        }
        if (urls.isEmpty()) return emptyList()
        val first = urls.first()
        return listOf(ctx.finding(SecurityScanner.Severity.MEDIUM, title,
            "A Firebase Realtime Database URL (" + first + (if (urls.size > 1) " and " + (urls.size - 1) + " more" else "") +
                ") is embedded in this class. The URL itself is not secret, but if the database rules allow public reads or writes (public \"test mode\"), anyone can dump or change the data with a plain HTTPS request, bypassing the app entirely (MASVS-NETWORK / CWE-284).",
            "Open \"$first/.json\" from a browser you control: if it returns data (or \"null\" instead of \"Permission denied\") without a login, the rules are public. In the Firebase console require auth != null (or a stricter per-field rule) and never rely on client-side checks for access control.",
            ctx.text.indexOf(first), "CWE-284"))
    }
}

/** Generic embedded-secret detection by entropy. Unchanged code, wrapped as a rule. */
object EntropyRule : ScanRule {
    override val id = "high-entropy-strings"
    override val title = "High-entropy embedded strings"
    override val cwes = listOf("CWE-798")
    override fun scan(ctx: RuleContext): List<SecurityScanner.Finding> =
        SecurityScanner.scanHighEntropyStrings(ctx.classType, ctx.clsIndex, ctx.text)
}

/** Reads of non-resettable hardware identifiers (IMEI, IMSI, SIM serial, phone number). */
object DeviceIdentifierRule : ScanRule {
    override val id = "device-identifier"
    override val title = "Hardware identifier read (IMEI / IMSI / phone number)"
    override val cwes = listOf("CWE-359")

    private val callRe = rx("Landroid/telephony/TelephonyManager;->(getDeviceId|getImei|getMeid|getSubscriberId|getSimSerialNumber|getLine1Number)\\(")

    override fun scan(ctx: RuleContext): List<SecurityScanner.Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val m = callRe.find(ctx.text) ?: return emptyList()
        return listOf(ctx.finding(SecurityScanner.Severity.LOW, title,
            "TelephonyManager." + m.groupValues[1] + "() returns an identifier that cannot be reset by the user. Collecting or sending it enables long-term tracking (and it needs a privileged permission on Android 10+, so the call may simply fail).",
            "Do not use hardware identifiers. Use a random app-scoped id (UUID stored in private storage) or the advertising id with the user's opt-out.",
            m.range.first, "CWE-359"))
    }
}

/** RSA / DSA / DH key pair generated with fewer than 2048 bits (algorithm and size traced from constants in the same method). */
object WeakKeySizeRule : ScanRule {
    override val id = "weak-key-size"
    override val title = "Asymmetric key shorter than 2048 bits"
    override val cwes = listOf("CWE-326")

    private val initRe = rx("Ljava/security/KeyPairGenerator;->initialize\\(I")
    private val getRe = rx("Ljava/security/KeyPairGenerator;->getInstance\\(")

    override fun scan(ctx: RuleContext): List<SecurityScanner.Finding> {
        val text = ctx.text
        if (!text.contains("KeyPairGenerator;->initialize")) return emptyList()
        val inits = initRe.findAll(text).toList()
        if (inits.isEmpty()) return emptyList()
        for (g in getRe.findAll(text)) {
            val algo = SecurityScanner.argString(text, g.range.first, 0)?.uppercase() ?: continue
            if (algo != "RSA" && algo != "DSA" && algo != "DH" && algo != "DIFFIEHELLMAN") continue
            val bounds = SecurityScanner.methodBounds(text, g.range.first)
            for (i in inits) {
                val at = i.range.first
                if (at < bounds.first || at > bounds.second) continue
                val size = SecurityScanner.argNumber(text, at, 1) ?: continue
                if (size in 1L..2047L) {
                    // 0.86.1 (recall kit case 20): below 1024 bits the key can be factored / solved with modest resources: HIGH
                    return listOf(ctx.finding(if (size < 1024L) SecurityScanner.Severity.HIGH else SecurityScanner.Severity.MEDIUM, title,
                        algo + " key pair generated with " + size + " bits. Keys under 2048 bits no longer give the expected security margin" + (if (size < 1024L) " and keys under 1024 bits can be broken with modest resources." else "."),
                        "Use at least 2048 bits (3072 preferred) for RSA/DSA/DH, or an elliptic-curve key (EC P-256, Ed25519).",
                        at, "CWE-326"))
                }
            }
        }
        return emptyList()
    }
}
