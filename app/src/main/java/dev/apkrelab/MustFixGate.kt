package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding

/**
 * Maturity protocol, phase 2: a card enters MUST FIX only when ALL four binary conditions hold. No CWE weights, no scores:
 * the score only orders the cards that pass.
 *
 *  (a) HIGH-IMPACT SINK: the card names a sink (FixTemplates.sinkOf) that runs code, loads a page or script, builds SQL, opens / writes / deletes a file,
 *      deserializes, picks a class by name, or launches an Intent: the HIGH / CRITICAL sinks of TaintIr. SSRF (URL / OkHttp), getMethod and logging do not count.
 *  (b) TRUE UNPROTECTED REACHABILITY: the reach pass found an exported entry (reach YES / YES~) AND that entry is not guarded by a SIGNATURE-level
 *      permission. A guard counts ONLY when its protectionLevel contains signature / signatureOrSystem / privileged / system (PermissionGuard.isSignatureLevel)
 *      or when it is a platform BIND_* service permission. A `dangerous` permission (android.permission.READ_SMS) or a `normal` one is NOT a guard:
 *      any app can request it, so the entry stays unprotected.
 *  (c) UNSANITIZED PATH: no validation-like call was seen on the path (the "also contains validation-like calls" sentence of SsaBridge / the taint rule).
 *  (d) TRUE DATA-FLOW / MANIFEST PROOF: an SSA flow (source to sink traced by the engine), or an exact method-level path from the exported component
 *      the manifest declares (reach YES with a chain). An approximate class-level path (YES~) of a pattern rule is not a proof.
 */
object MustFixGate {

    class Result(val sink: Boolean, val reach: Boolean, val unsanitized: Boolean, val proof: Boolean) {
        val passes get() = sink && reach && unsanitized && proof
        /** The failed conditions, e.g. "b (entry guarded by a signature permission)"; empty when the card passes. */
        val failed: List<String> get() = listOfNotNull(if (!sink) "a" else null, if (!reach) "b" else null, if (!unsanitized) "c" else null, if (!proof) "d" else null)
    }

    /** Switches for the mutation checks (each must make a gate test fail when turned off). */
    internal var CHECK_SINK = true
    internal var CHECK_GUARD = true
    internal var CHECK_SANITIZED = true
    internal var CHECK_PROOF = true

    // TaintIr's HIGH / CRITICAL sinks, as FixTemplates.sinkOf names them ("Owner.method"); an entry ending in '.' is a class prefix, one ending in '*' a method prefix
    private val HIGH_IMPACT = listOf(
        "Runtime.exec", "Runtime.load", "ProcessBuilder.", "DexClassLoader.", "PathClassLoader.", "System.load", "System.loadLibrary",
        "WebView.loadUrl", "WebView.loadData", "WebView.loadDataWithBaseURL", "WebView.evaluateJavascript", "WebView.postUrl", "WebView.addJavascriptInterface",
        "SQLiteDatabase.", "SupportSQLiteDatabase.", "SQLiteQueryBuilder.", "SimpleSQLiteQuery.",
        "FileInputStream.<init>", "FileOutputStream.<init>", "FileReader.<init>", "FileWriter.<init>", "RandomAccessFile.<init>", "ParcelFileDescriptor.open",
        "File.delete", "File.renameTo", "Files.write", "Files.newOutputStream", "ZipFile.<init>", "ContentResolver.open*",
        "ObjectInputStream.<init>", "Class.forName", "ClassLoader.loadClass", "Method.invoke")
    private val REDIRECT = TaintRedirect.NAMES

    fun highImpactSink(sink: String?): Boolean {
        if (sink == null) return false
        if (HIGH_IMPACT.any { when { it.endsWith(".") -> sink.startsWith(it); it.endsWith("*") -> sink.startsWith(it.dropLast(1)); else -> sink == it } }) return true
        return sink.substringAfterLast('.') in REDIRECT
    }

    private val entryRe = Regex("^exported (?:activity-alias|activity|service|receiver|provider) ([A-Za-z0-9_$.]+)")

    /** The smali type of the exported component the reach pass entered by ("exported activity com.x.Foo (deep link)" -> "Lcom/x/Foo;"); null when unknown. */
    fun entryType(f: Finding): String? = Correlation.entryOf(f)?.let { entryRe.find(it)?.groupValues?.get(1) }?.let { "L" + it.replace('.', '/') + ";" }

    /**
     * [guard] = the app's manifest guards (null = not available here: the reach pass already left SIGNATURE-guarded entries out of its seeds on the device,
     * so the card's reach is taken as it is).
     */
    fun check(f: Finding, guard: PermissionGuard? = null): Result {
        // 2.1.0: a reflected setResult(getIntent()) card raised to HIGH by FindingPolish.raiseReflectedUriGrant is its own high-impact sink (it grants a provider's data)
        val sink = !CHECK_SINK || highImpactSink(FixTemplates.sinkOf(f)) || (f.ruleId == "uri-grant-via-result" && f.adjusted.contains("Raised to HIGH"))
        val reachable = f.reach == "YES" || f.reach == "YES~"
        val entry = entryType(f)
        val guarded = CHECK_GUARD && guard != null && entry != null && guard.guardFor(entry) == PermissionGuard.Guard.SIGNATURE
        val validated = FindingScore.confidence(f).evidence < 0.6
        val ssa = f.detail.contains("Found by the SSA data-flow engine")
        val proof = !CHECK_PROOF || ssa || (f.reach == "YES" && f.chain.isNotBlank())
        return Result(sink, reachable && !guarded, !CHECK_SANITIZED || !validated, proof)
    }
}

/** The Intent-launching method names of TaintIr.REDIRECT_NAMES, kept here so the gate needs no access to the engine's package-private set. */
internal object TaintRedirect {
    val NAMES = setOf("startActivity", "startActivityForResult", "startService", "startForegroundService", "sendBroadcast", "bindService")
}
