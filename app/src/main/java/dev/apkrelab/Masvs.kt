package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity

/**
 * 0.92.0: findings tied to a CONTROL of the OWASP MASVS v2 (https://mas.owasp.org/MASVS/), not just to its group, and a coverage table that says which of the 24 controls the tool
 * assesses at all. The control statements are quoted from the official MASVS repository (CC BY-SA 4.0). The mapping of a rule to a control is APKReLab's own judgement, not an OWASP
 * publication: a rule can serve more than one control, and a few (native hardening) have no exact control in MASVS v2 and are mapped to the nearest one.
 */
object Masvs {

    val controls: LinkedHashMap<String, String> = linkedMapOf(
        "MASVS-AUTH-1" to "The app uses secure authentication and authorization protocols and follows the relevant best practices.",
        "MASVS-AUTH-2" to "The app performs local authentication securely according to the platform best practices.",
        "MASVS-AUTH-3" to "The app secures sensitive operations with additional authentication.",
        "MASVS-CODE-1" to "The app requires an up-to-date platform version.",
        "MASVS-CODE-2" to "The app has a mechanism for enforcing app updates.",
        "MASVS-CODE-3" to "The app only uses software components without known vulnerabilities.",
        "MASVS-CODE-4" to "The app validates and sanitizes all untrusted inputs.",
        "MASVS-CRYPTO-1" to "The app employs current strong cryptography and uses it according to industry best practices.",
        "MASVS-CRYPTO-2" to "The app performs key management according to industry best practices.",
        "MASVS-NETWORK-1" to "The app secures all network traffic according to the current best practices.",
        "MASVS-NETWORK-2" to "The app performs identity pinning for all remote endpoints under the developer's control.",
        "MASVS-PLATFORM-1" to "The app uses IPC mechanisms securely.",
        "MASVS-PLATFORM-2" to "The app uses WebViews securely.",
        "MASVS-PLATFORM-3" to "The app uses the user interface securely.",
        "MASVS-PRIVACY-1" to "The app minimizes access to sensitive data and resources.",
        "MASVS-PRIVACY-2" to "The app prevents identification of the user.",
        "MASVS-PRIVACY-3" to "The app is transparent about data collection and usage.",
        "MASVS-PRIVACY-4" to "The app offers user control over their data.",
        "MASVS-RESILIENCE-1" to "The app validates the integrity of the platform.",
        "MASVS-RESILIENCE-2" to "The app implements anti-tampering mechanisms.",
        "MASVS-RESILIENCE-3" to "The app implements anti-static analysis mechanisms.",
        "MASVS-RESILIENCE-4" to "The app implements anti-dynamic analysis techniques.",
        "MASVS-STORAGE-1" to "The app securely stores sensitive data.",
        "MASVS-STORAGE-2" to "The app prevents leakage of sensitive data."
    )

    private fun p(vararg ids: String) = ids.toList()

    /** rule id -> MASVS controls. An id that is missing here falls back to the CWE group of [VulnKnowledge]. */
    private val byRule: Map<String, List<String>> = HashMap<String, List<String>>().also { m ->
        fun put(controls: List<String>, vararg rules: String) { for (r in rules) m[r] = controls }
        put(p("MASVS-STORAGE-1"), "external-storage", "manifest-legacy-external-storage", "storage-file-mode", "fintech-unencrypted-storage", "sqlite-unencrypted",
            "high-entropy-strings", "secrets-sensitive-fields", "secrets-known-formats", "secrets-google-api-key", "secrets-vendor-tokens", "jwt-hardcoded-secret", "native-secrets",
            "res-strings-aws-keys", "res-strings-firebase-url", "res-strings-google-api-key", "res-strings-jwt", "res-strings-known-tokens", "res-strings-secret-names", "res-strings-url-credentials", "firebase-db-url")
        put(p("MASVS-STORAGE-2"), "apkrelab-keyboard-cache-sensitive-input-field", "manifest-allow-backup", "log-credential-object", "log-sensitive-strings", "okhttp-logging", "androgoat-checks", "fintech-async-taint")
        put(p("MASVS-CRYPTO-1"), "crypto-cipher", "crypto-weak-hash", "crypto-sha1prng-seed", "crypto-static-iv", "crypto-pbkdf2-iterations", "weak-random", "weak-key-size")
        put(p("MASVS-STORAGE-1"), "assets-secrets", "assets-private-key", "assets-firebase-db")
        put(p("MASVS-NETWORK-1"), "assets-cleartext-url")
        put(p("MASVS-PLATFORM-2"), "assets-cordova-access-wildcard", "assets-cordova-navigation-wildcard")
        put(p("MASVS-CRYPTO-2"), "crypto-hardcoded-key")
        put(p("MASVS-CRYPTO-2", "MASVS-STORAGE-1"), "crypto-db-passphrase")
        put(p("MASVS-NETWORK-1"), "cleartext-url", "cleartext-url-used", "manifest-cleartext-traffic", "manifest-network-security-config", "res-nsc-cleartext", "res-nsc-cleartext-domains",
            "res-nsc-user-ca", "res-nsc-unreferenced", "tls-hostname-verifier", "tls-insecure-socket-factory", "tls-protocol-version", "tls-trustmanager", "fintech-insecure-websocket", "native-flutter-cleartext")
        put(p("MASVS-NETWORK-2"), "res-nsc-no-pinning", "res-nsc-override-pins", "res-nsc-pin-lifecycle")
        put(p("MASVS-PLATFORM-1"), "broadcast-unprotected-send", "deeplink-config-poisoning", "deeplink-host-validation", "manifest-deep-links", "manifest-exported-components",
            "manifest-exported-provider-grant-uri", "manifest-provider-partial-permission", "manifest-permission-protection", "manifest-shared-user-id", "intent-parseuri", "intent-redirection",
            "implicit-intent-sensitive", "fragment-injection", "pendingintent-mutable", "receiver-export-flag", "uri-grant-via-result", "pick-result-file", "provider-code-permission",
            "res-fileprovider-paths", "fintech-exported-sensitive-action")
        put(p("MASVS-PLATFORM-1", "MASVS-CODE-4"), "provider-openfile-segment", "provider-sql-injection")
        put(p("MASVS-PLATFORM-2"), "webview-debugging", "webview-file-access", "webview-intent-url", "webview-js-bridge-method", "webview-js-interface", "webview-mixed-content",
            "webview-plugin-state", "webview-ssl-error")
        put(p("MASVS-PLATFORM-3"), "tapjacking-sensitive-layout", "manifest-task-hijacking", "manifest-accessibility-service")
        put(p("MASVS-CODE-1"), "manifest-min-sdk", "manifest-target-sdk", "native-16kb-alignment")
        put(p("MASVS-CODE-3"), "sca-known-vuln", "sca-package-heuristics")
        put(p("MASVS-CODE-4"), "deserialization", "jackson-default-typing", "serializable-dangerous", "sql-concat", "shell-exec", "zip-slip", "dex-load-writable-dir", "dynamic-code-loading", "package-context-code",
            "native-unsafe-imports", "native-hardening")
        put(p("MASVS-RESILIENCE-4"), "manifest-debuggable", "manifest-test-only", "fintech-frida-detection")
        put(p("MASVS-RESILIENCE-1"), "posture-safetynet-retired")
        put(p("MASVS-PRIVACY-1"), "manifest-powerful-permissions", "manifest-sensitive-permissions")
        put(p("MASVS-PRIVACY-2"), "device-identifier")
    }

    /** The sinks of a taint finding decide the control(s): the rule id alone ("taint-flow") covers a dozen different weaknesses. */
    private fun forTaint(title: String): List<String> {
        val t = title.lowercase()
        val out = ArrayList<String>()
        if (t.contains("webview") || t.contains("javascript") || t.contains("loaded as a url") || t.contains("url is loaded")) out.add("MASVS-PLATFORM-2")
        if (t.contains("intent") || t.contains("redirect") || t.contains("component")) out.add("MASVS-PLATFORM-1")
        if (t.contains("log") || t.contains("stored") || t.contains("preferences") || t.contains("written to a file")) out.add("MASVS-STORAGE-2")
        out.add("MASVS-CODE-4")
        return out
    }

    /** MASVS v2 controls of a finding; empty when the rule has no mapping (the report then keeps the CWE group of VulnKnowledge). */
    fun controlsFor(f: Finding): List<String> {
        val id = SarifExport.ruleIdOf(f)           // a legacy finding without a rule id has its title slug as id
        if (id == "taint-flow" || id == "taint-xclass") return forTaint(f.title)
        if (id == "posture-summary") return emptyList()
        return byRule[id] ?: emptyList()
    }

    /** "MASVS-NETWORK-1, MASVS-PLATFORM-2" or "" when unmapped. */
    fun label(f: Finding): String = controlsFor(f).joinToString(", ")

    /** The rule ids the table maps (for the coverage statement and the tests). */
    internal fun mappedRules(): Set<String> = byRule.keys

    class Cover(val control: String, val statement: String, val rules: Int, val findings: Int, val worst: Severity?, val libFindings: Int = 0)

    /** Per control: how many mapped rules assess it (the posture signals count for RESILIENCE / NETWORK-2 / PLATFORM-3) and what the scan found. */
    fun coverage(findings: List<Finding>): List<Cover> {
        val rulesPer = HashMap<String, MutableSet<String>>()
        for ((r, cs) in byRule) for (c in cs) rulesPer.getOrPut(c) { HashSet() }.add(r)
        for (s in PostureScanner.signals) rulesPer.getOrPut(s.masvs) { HashSet() }.add("posture:" + s.id)
        rulesPer.getOrPut("MASVS-RESILIENCE-3") { HashSet() }.add("posture:obfuscation")      // the share of renamed classes is read for every app
        // what a reader sees as a finding: LOW or higher, in the app's own code (or code of unknown origin); library findings are counted apart, and INFO is information, not a finding
        val found = HashMap<String, MutableList<Finding>>(); val inLib = HashMap<String, Int>()
        for (f in findings) {
            if (f.severity.rank > 3) continue
            for (c in controlsFor(f)) { if (f.scope == SecurityScanner.Scope.LIB) inLib[c] = (inLib[c] ?: 0) + 1 else found.getOrPut(c) { ArrayList() }.add(f) }
        }
        return controls.map { (id, st) -> Cover(id, st, rulesPer[id]?.size ?: 0, found[id]?.size ?: 0, found[id]?.minByOrNull { it.severity.rank }?.severity, inLib[id] ?: 0) }
    }

    /** Markdown section: which of the 24 controls were assessed, what was found, which cannot be assessed by this tool. */
    fun section(findings: List<Finding>): String {
        val cov = coverage(findings)
        val sb = StringBuilder("\n## MASVS v2 coverage\n\n")
        sb.append("The OWASP Mobile Application Security Verification Standard has 24 controls. This table says which of them APKReLab assesses at all (a rule or a posture signal exists), ")
            .append("and what the scan found (LOW and above, in the app's own code; findings inside libraries are counted in their own column; INFO is not counted). \"No findings\" is NOT a pass: the rules cover known patterns, and static analysis cannot assess authentication, privacy policy or server-side behaviour. ")
            .append("The mapping of rules to controls is APKReLab's own.\n\n")
        sb.append("| Control | What it requires | Assessed by | Findings in app code | Worst | In libraries |\n|---|---|---|---|---|---|\n")
        for (c in cov) {
            val by = if (c.rules == 0) "not assessed by this tool" else c.rules.toString() + " rule(s) / signal(s)"
            sb.append("| ").append(c.control).append(" | ").append(c.statement).append(" | ").append(by).append(" | ").append(if (c.rules == 0) "-" else c.findings.toString()).append(" | ")
                .append(c.worst?.label ?: "-").append(" | ").append(if (c.rules == 0) "-" else c.libFindings.toString()).append(" |\n")
        }
        val assessed = cov.count { it.rules > 0 }
        sb.append("\n").append(assessed).append(" of ").append(cov.size).append(" controls are assessed; ").append(cov.count { it.findings > 0 }).append(" have findings in the app's code. ")
            .append("Controls with no rule: ").append(cov.filter { it.rules == 0 }.joinToString(", ") { it.control.removePrefix("MASVS-") }.ifEmpty { "none" }).append(".\n")
        return sb.toString()
    }
}
