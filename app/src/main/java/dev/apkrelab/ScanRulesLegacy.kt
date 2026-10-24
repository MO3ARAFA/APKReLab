package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.METHOD_PREAMBLE
import dev.apkrelab.SecurityScanner.NULL_CHECKS
import dev.apkrelab.SecurityScanner.Severity
import dev.apkrelab.SecurityScanner.argNumber
import dev.apkrelab.SecurityScanner.argString
import dev.apkrelab.SecurityScanner.charClasses
import dev.apkrelab.SecurityScanner.contextHas
import dev.apkrelab.SecurityScanner.identHas
import dev.apkrelab.SecurityScanner.lineNo
import dev.apkrelab.SecurityScanner.base64LiteralArg
import dev.apkrelab.SecurityScanner.byteSourceArg
import dev.apkrelab.SecurityScanner.constByteArrayArg
import dev.apkrelab.SecurityScanner.staticByteArrayFieldArg
import dev.apkrelab.SecurityScanner.literalBytesArg
import dev.apkrelab.SecurityScanner.methodBounds
import dev.apkrelab.SecurityScanner.randomWords
import dev.apkrelab.SecurityScanner.secretWords

/**
 * 0.41.0: the checks that used to live inline in SecurityScanner.scanSmali, moved one by one into rules.
 * The detection code of every rule is the ORIGINAL code, unchanged (same regexes, same thresholds, same titles, same CWE tags),
 * so findings are identical to 0.40.0; only the structure changed. Each rule has:
 *   id          stable name (shows in reports as "Rule: ...", used for per-rule error counts)
 *   cwes        weaknesses it can report (each must exist in VulnKnowledge: RuleRegistry.audit() checks this)
 *   confidence  HIGH = exact API / constant traced, MEDIUM = heuristic, LOW = informational ("" = decided from the title by FindingPolish)
 * Registration order = the old execution order (it decides which finding of a duplicate title is kept), see RuleRegistry.
 */

object WebviewJsInterfaceRule : ScanRule {
    override val id = "webview-js-interface"
    override val title = "WebView addJavascriptInterface"
    override val cwes = listOf("CWE-749")
    override val confidence = "HIGH"

    /**
     * 0.78.0 (real-app set 3: Kiwix TTS / TOC bridges and Markor's "toast" bridge were HIGH): the risk of a bridge is what its
     * @JavascriptInterface methods can do. Since API 17 only those methods are callable, so the call site alone is MEDIUM ("review the
     * bridge"). It is HIGH when the bridge object is THIS class and one of its exposed methods reaches a sensitive API (see
     * [JsBridgeMethodRule.dangerousApis]). A bridge in another class is judged in that class by [JsBridgeMethodRule].
     */
    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val m = rx("->addJavascriptInterface\\(").find(text) ?: return emptyList()
        val selfBridge = bridgeIsThis(ctx)
        val danger = if (selfBridge) JsBridgeMethodRule.dangerousExposed(text) else emptyList()
        val sev = if (danger.isNotEmpty()) Severity.HIGH else Severity.MEDIUM
        val what = when {
            danger.isNotEmpty() -> " The bridge is this class and its exposed method(s) reach: " + danger.take(4).joinToString("; ") + "."
            selfBridge -> " The bridge is this class; none of its @JavascriptInterface methods reaches a file, process, Intent, database, preferences, account, location or reflection API, so a page can only call what you see there."
            else -> " The bridge object is another class: its @JavascriptInterface methods are judged there (\"JavaScript-exposed method\" findings)."
        }
        return listOf(ctx.finding(sev, "WebView addJavascriptInterface",
            "A Java/Kotlin object is bridged into a WebView's JavaScript context. Any page the WebView loads - including one reached via a hijacked link or a MITM'd connection - can call that object's @JavascriptInterface methods." + what,
            "Avoid exposing a JS interface to untrusted pages; restrict it to known HTTPS origins, or use WebMessageListener on modern APIs instead.",
            m.range.first, "CWE-749").also { if (danger.isEmpty()) it.confidence = "MEDIUM" })
    }

    /** The argument object of the first addJavascriptInterface call is `this` (p0, also through moves). Text-level, register reuse safe enough for p0. */
    private fun bridgeIsThis(ctx: RuleContext): Boolean {
        val c = ctx.ir ?: return rx("invoke-virtual \\{[vp]\\d+, p0, [vp]\\d+\\}, L[^;]+;->addJavascriptInterface").containsMatchIn(ctx.text)
        for (mm in c.methods) for (insn in mm.insns) {
            if (insn.kind != dev.apkrelab.ir.Insn.Kind.INVOKE || insn.targetName() != "addJavascriptInterface" || insn.uses.size < 2) continue
            if (mm.isStatic) return false
            return insn.uses[1] == mm.firstParam()    // p0 (this) of an instance method
        }
        return false
    }
}

/**
 * 0.78.0: a method annotated @JavascriptInterface whose body reaches a sensitive API: any page loaded in a WebView that bridges this object
 * can call it. Judged in the class that declares the method, so a bridge in another class than the addJavascriptInterface call is covered too.
 */
object JsBridgeMethodRule : ScanRule {
    override val id = "webview-js-bridge-method"
    override val title = "JavaScript-exposed method reaches a sensitive API"
    override val cwes = listOf("CWE-749")
    override val confidence = "HIGH"

    internal val dangerousApis: List<Pair<Regex, String>> = listOf(
        rx("Ljava/io/File(?:OutputStream|InputStream|Writer|Reader)?;-><init>|Ljava/io/RandomAccessFile;-><init>|Ljava/nio/file/") to "files",
        rx("Ljava/lang/Runtime;->exec|Ljava/lang/ProcessBuilder;") to "process execution",
        rx("->(?:startActivity|startActivityForResult|startService|sendBroadcast|sendOrderedBroadcast|bindService)\\(") to "starting components / broadcasts",
        rx("Landroid/content/Intent;->parseUri") to "Intent.parseUri",
        rx("Landroid/database/sqlite/SQLiteDatabase;->|Landroid/content/ContentResolver;->") to "databases / content providers",
        rx("Landroid/content/SharedPreferences") to "preferences",
        rx("Landroid/accounts/AccountManager;->|Landroid/telephony/TelephonyManager;->|Landroid/location/") to "account / phone / location data",
        rx("Ljava/lang/Class;->forName|Ljava/lang/reflect/Method;->invoke|Ldalvik/system/(?:Dex|Path|InMemoryDex)ClassLoader;") to "reflection / code loading",
        rx("Landroid/content/ClipboardManager;->") to "the clipboard",
        rx("Landroid/webkit/WebView;->(?:loadUrl|evaluateJavascript)") to "navigating the WebView")

    /** "methodName(): files, process execution" for every @JavascriptInterface method of [text] that reaches a dangerous API. */
    internal fun dangerousExposed(text: String): List<String> {
        val out = ArrayList<String>()
        val all = rx("\\.method [^\\n]*?([A-Za-z0-9_\$<>]+)\\(([^\\n]*)\\n((?:(?!\\.end method)[\\s\\S])*?)\\.end method").findAll(text).toList()
        // 0.81.0 (Jellyfin openUrl / downloadFiles reach their APIs through helpers of the same class): follow calls to methods of THIS
        // class up to 2 hops; a hit found that way names the helper
        val cls = rx("^\\.class[^\\n]* (L[^;]+;)", RegexOption.MULTILINE).find(text)?.groupValues?.get(1) ?: ""
        val byName = HashMap<String, String>()
        for (mm in all) byName[mm.groupValues[1]] = (byName[mm.groupValues[1]] ?: "") + mm.groupValues[3]
        // 0.97.1 (a wallet app's LiveChat bridge: "reflection / code loading via a()" was the obfuscator's own runtime helper): a helper that returns void and takes only primitives
        // (or primitive arrays) plus a trailing Object[] out-array is marshalling plumbing of a commercial obfuscator (string decryption, reflective lookups). Nothing JavaScript sent
        // can reach it as a parameter, so ITS reflection says nothing about the page; its other hits (files, processes ...) still count.
        val plumbing = HashSet<String>()
        val onlyPlumbing = HashSet<String>()
        for (mm in all) {
            val sig = mm.groupValues[2]
            if (sig.endsWith("[Ljava/lang/Object;)V") && Regex("^[ICZJSBFD\\[]*\\[Ljava/lang/Object;\\)V").containsMatchIn(sig.substringAfterLast(".method ").trim())) plumbing.add(mm.groupValues[1])
        }
        onlyPlumbing.addAll(plumbing)
        val callRe = if (cls.isEmpty()) null else rx(Regex.escape(cls) + "->([A-Za-z0-9_\$]+)\\(")
        for (mm in all) {
            val body = mm.groupValues[3]
            if (!body.contains("Landroid/webkit/JavascriptInterface;")) continue
            val hits = LinkedHashSet<String>()
            dangerousApis.filter { it.first.containsMatchIn(body) }.forEach { hits.add(it.second) }
            if (callRe != null) {
                var frontier = listOf(body)
                val seen = HashSet<String>()
                for (hop in 1..2) {
                    val next = ArrayList<String>()
                    for (b in frontier) for (c in callRe.findAll(b)) {
                        val name = c.groupValues[1]
                        if (name == mm.groupValues[1] || !seen.add(name)) continue
                        val hb = byName[name] ?: continue
                        dangerousApis.filter { it.first.containsMatchIn(hb) }.forEach { if (!(name in onlyPlumbing && it.second.startsWith("reflection"))) hits.add(it.second + " (via $name())") }
                        next.add(hb)
                    }
                    frontier = next
                }
            }
            if (hits.isNotEmpty()) out.add(mm.groupValues[1] + "(): " + hits.joinToString(", "))
        }
        return out
    }

    override fun scan(ctx: RuleContext): List<Finding> {
        if (!ctx.text.contains("Landroid/webkit/JavascriptInterface;")) return emptyList()
        val d = dangerousExposed(ctx.text)
        if (d.isEmpty()) return emptyList()
        val at = ctx.text.indexOf("Landroid/webkit/JavascriptInterface;").coerceAtLeast(0)
        return listOf(ctx.finding(Severity.HIGH, title,
            "Methods of this class are annotated @JavascriptInterface, so JavaScript in any page of a WebView that bridges this object can call them, and they reach: " +
                d.take(5).joinToString("; ") + ". A malicious or MITM'd page can use them with the app's permissions.",
            "Expose only what the page needs, validate every argument as untrusted input, and load only your own HTTPS content in a WebView with a bridge.",
            at, "CWE-749"))
    }
}

object WebviewFileAccessRule : ScanRule {
    override val id = "webview-file-access"
    override val title = "WebView: {m.groupValues[1]}(true)"
    override val cwes = listOf("CWE-200")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Landroid/webkit/WebSettings;->(setAllowFileAccessFromFileURLs|setAllowUniversalAccessFromFileURLs)\\(Z\\)V").findAll(text)) {
            if (argNumber(text, m.range.first, 1) == 1L) {
                add(Severity.HIGH, "WebView: ${m.groupValues[1]}(true)",
                    "A page loaded from file:// can read other local files (or any origin) through JavaScript. Combined with any way to load attacker-chosen HTML this leaks app-private files.",
                    "Remove the call (the default is false since API 16) and keep file access off unless a reviewed local page truly needs it.",
                    m.range.first, "CWE-200")
            }
        }

        return out
    }
}

object WebviewMixedContentRule : ScanRule {
    override val id = "webview-mixed-content"
    override val title = "WebView: mixed content always allowed"
    override val cwes = listOf("CWE-319")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Landroid/webkit/WebSettings;->setMixedContentMode\\(I\\)V").findAll(text)) {
            if (argNumber(text, m.range.first, 1) == 0L) {
                add(Severity.MEDIUM, "WebView: mixed content always allowed",
                    "MIXED_CONTENT_ALWAYS_ALLOW lets an HTTPS page load HTTP sub-resources (scripts included), which a network attacker can tamper with.",
                    "Use MIXED_CONTENT_NEVER_ALLOW (or COMPATIBILITY_MODE at most).", m.range.first, "CWE-319")
            }
        }

        return out
    }
}

object WebviewDebuggingRule : ScanRule {
    override val id = "webview-debugging"
    override val title = "WebView remote debugging enabled"
    override val cwes = listOf("CWE-489")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Landroid/webkit/WebView;->setWebContentsDebuggingEnabled\\(Z\\)V").findAll(text)) {
            if (argNumber(text, m.range.first, 0) == 1L) {
                add(Severity.MEDIUM, "WebView remote debugging enabled",
                    "setWebContentsDebuggingEnabled(true) lets anyone with USB access open Chrome DevTools on the app's WebViews and read/modify pages and JS state.",
                    "Enable it only for debug builds (guard with BuildConfig.DEBUG).", m.range.first, "CWE-489")
            }
        }

        return out
    }
}

object WebviewSslErrorRule : ScanRule {
    override val id = "webview-ssl-error"
    override val title = "WebView ignores TLS errors (SslErrorHandler.proceed)"
    override val cwes = listOf("CWE-295")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        if (text.contains("onReceivedSslError")) {
            // 0.66.4: the proceed() must be INSIDE onReceivedSslError (not any other method of the class), and a proceed() that
            // sits behind a branch (host allow-list, debug flag, user dialog) is MEDIUM: still worth a look, not a blanket proceed.
            val all = rx("Landroid/webkit/SslErrorHandler;->proceed\\(\\)V").findAll(text).toList()
            val inHandler = all.firstOrNull { p ->
                val (s, _) = SecurityScanner.methodBounds(text, p.range.first)
                val eol = text.indexOf('\n', s + 1).let { if (it < 0) text.length else it }
                text.substring(s, eol).contains("onReceivedSslError(")
            }
            // proceed() in a helper method (R8 often moves it out of the override): kept, but MEDIUM and with a note
            val hit = inHandler ?: all.firstOrNull()
            if (hit != null) {
                val (ms, _) = SecurityScanner.methodBounds(text, hit.range.first)
                val helper = inHandler == null
                val guarded = helper || rx("\\n\\s*if-").containsMatchIn(text.substring(ms, hit.range.first))
                add(if (guarded) Severity.MEDIUM else Severity.HIGH, "WebView ignores TLS errors (SslErrorHandler.proceed)",
                    "onReceivedSslError calls handler.proceed(), so the WebView keeps loading pages with invalid/untrusted certificates - the classic way TLS gets silently disabled." +
                        (if (helper) " The proceed() is in a helper method called from the handler: check the callers." else if (guarded) " The call sits behind a condition (allow-list / flag / dialog): check what the condition is before treating it as a blanket proceed." else ""),
                    "Call handler.cancel() (and show an error) instead of proceed(); never ship a blanket proceed.", hit.range.first, "CWE-295")
            }
        }

        return out
    }
}

object CryptoCipherRule : ScanRule {
    override val id = "crypto-cipher"
    override val title = "Weak cipher mode: ECB (algo)"
    override val cwes = listOf("CWE-327", "CWE-780")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // --- crypto ---
        for (m in rx("Ljavax/crypto/Cipher;->getInstance\\(").findAll(text)) {
            val algo = argString(text, m.range.first, 0) ?: continue
            val up = algo.uppercase()
            when {
                // 0.102.0: AES/ECB/NoPadding whose only use is doFinal on ONE fresh all-zero 16-byte array is the AES-CMAC / CBC-MAC subkey primitive E_K(0^128), not data encryption
                up == "AES/ECB/NOPADDING" && ConstantArgGuards.isZeroBlockOnly(text, m.range.first) ->
                    add(Severity.LOW, "AES/ECB/NoPadding on a constant all-zero block (CMAC-style primitive)",
                        "Cipher.getInstance(\"$algo\") is used only to encrypt one fresh, never-written 16-byte array (the all-zero block) and nothing else in this method: that is how AES-CMAC / CBC-MAC derive their subkeys (L = AES_K(0^128)). ECB's weakness is repeated plaintext blocks and a single constant block has none, so this is not data encryption in ECB mode. Check that the same transformation is not used for data elsewhere.",
                        "No change if this is a CMAC / subkey step. For data use AES/GCM/NoPadding with a fresh random 12-byte IV per message.", m.range.first, "CWE-327")
                // 0.76.0 (andOTP): "RSA/ECB/PKCS1Padding" is the standard JCA name of RSA; ECB means nothing for an asymmetric cipher
                (up.contains("/ECB") && !up.startsWith("RSA") && !up.startsWith("EC") && !up.startsWith("ELGAMAL")) ||
                    up == "AES" || up == "DES" || up == "DESEDE" || up == "BLOWFISH" ->
                    add(Severity.HIGH, "Weak cipher mode: ECB (\"$algo\")",
                        "Cipher.getInstance(\"$algo\") uses ECB (a bare \"AES\"/\"DES\" defaults to ECB on Android): identical plaintext blocks give identical ciphertext blocks, leaking structure and allowing block swapping.",
                        "Use AES/GCM/NoPadding with a fresh random 12-byte IV per message (or AES/CBC + HMAC if GCM is not possible).", m.range.first, "CWE-327")
                up.startsWith("DES/") || up.startsWith("DESEDE/") || up.startsWith("RC4") || up.startsWith("ARCFOUR") || up.startsWith("RC2") ->
                    add(Severity.HIGH, "Weak/legacy cipher: \"$algo\"",
                        "DES/3DES/RC4/RC2 have known practical attacks or tiny key/block sizes.",
                        "Use AES-256-GCM.", m.range.first, "CWE-327")
                up.startsWith("RSA") && (up == "RSA" || up.contains("PKCS1PADDING")) ->
                    add(Severity.LOW, "RSA with PKCS#1 v1.5 padding (\"$algo\")",
                        "PKCS#1 v1.5 encryption padding is vulnerable to padding-oracle (Bleichenbacher-style) attacks when decryption errors are observable.",
                        "Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding.", m.range.first, "CWE-780")
            }
        }

        return out
    }
}

object CryptoWeakHashRule : ScanRule {
    override val id = "crypto-weak-hash"
    override val title = "Weak hash: algo"
    override val cwes = listOf("CWE-328")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Ljava/security/MessageDigest;->getInstance\\(").findAll(text)) {
            val algo = argString(text, m.range.first, 0) ?: continue
            when (algo.uppercase()) {
                "MD5", "MD4", "MD2" -> add(Severity.MEDIUM, "Weak hash: $algo",
                    "$algo is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum.",
                    "Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash.", m.range.first, "CWE-328")
                "SHA-1", "SHA1" -> add(Severity.LOW, "Weak hash: SHA-1",
                    "SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.",
                    "Use SHA-256 or better.", m.range.first, "CWE-328")
            }
        }

        // 0.74.0: the algorithm name is handed to a hash helper as a constant (PIVAA: `Encryption.hash("MD5", value)`, the helper calls
        // MessageDigest.getInstance(parameter)). Class-local heuristic: a call whose method name says hash / digest / checksum / md5 and whose
        // first or second argument is the constant "MD5" / "SHA-1". MEDIUM confidence: it does not follow the value into the callee.
        val helperRe = rx("invoke-(?:static|virtual|direct)(?:/range)?\\s+\\{[^}]*\\},\\s*L(?!java/security/MessageDigest;)[^;]+;->[A-Za-z0-9_$]*(?:hash|digest|checksum|md5)[A-Za-z0-9_$]*\\(Ljava/lang/String;", RegexOption.IGNORE_CASE)
        val seenAlgo = HashSet<String>()
        for (m in helperRe.findAll(text)) {
            val algo = (argString(text, m.range.first, if (m.value.startsWith("invoke-static")) 0 else 1)) ?: continue
            val a = algo.uppercase()
            if (a !in setOf("MD5", "MD4", "MD2", "SHA-1", "SHA1") || !seenAlgo.add(a)) continue
            val md = a.startsWith("MD")
            val f = ctx.finding(if (md) Severity.MEDIUM else Severity.LOW, if (md) "Weak hash: $algo" else "Weak hash: SHA-1",
                (if (md) "$algo is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum." else "SHA-1 is deprecated for security use (collision attacks exist); not safe for certificates or signatures.") +
                    " The algorithm name is passed to a hash helper as a constant (the value is not followed into the helper, so check what it hashes).",
                if (md) "Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash." else "Use SHA-256 or better.", m.range.first, "CWE-328")
            f.confidence = "MEDIUM"
            out.add(f)
        }

        return out
    }
}

object CryptoHardcodedKeyRule : ScanRule {
    override val id = "crypto-hardcoded-key"
    override val title = "Hardcoded encryption key"
    override val cwes = listOf("CWE-321")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // 0.94.0: DESKeySpec / DESedeKeySpec take a key too (InjuredAndroid's DES challenge was missed)
        for (m in rx("Ljavax/crypto/spec/(?:SecretKeySpec;-><init>\\(\\[BLjava/lang/String;\\)V|DESKeySpec;-><init>\\(\\[B\\)V|DESedeKeySpec;-><init>\\(\\[B\\)V)").findAll(text)) {
            val spec = m.value.substringAfter("spec/").substringBefore(";")
            val lit = literalBytesArg(text, m.range.first, 1)
            // 0.76.0 (Unstoppable / stellar SLIP10): the HMAC keys of BIP32 / SLIP-0010 master-key derivation are PUBLIC constants of the spec
            if (lit != null && lit in setOf("Bitcoin seed", "ed25519 seed", "Nist256p1 seed", "nist256p1 seed", "curve25519 seed", "Curve25519 seed")) continue
            if (lit == null) {
                // 0.86.1: Base64.decode("<constant>") and a static byte[] field filled in <clinit> are literals too (recall kit cases 41, 42)
                val b64 = base64LiteralArg(text, m.range.first, 1)
                val fld = if (b64 == null) staticByteArrayFieldArg(text, ctx.classType, m.range.first, 1) else null
                if (b64 != null || fld != null) {
                    add(Severity.HIGH, "Hardcoded encryption key",
                        if (b64 != null) "A $spec is built from Base64.decode of a string literal ($b64 bytes): the key is only encoded, it sits in the APK, so anyone who decompiles it can decrypt/forge whatever this key protects."
                        else "A $spec is built from the static byte array $fld, which the class initialiser fills from constants: the key sits in the APK, so anyone who decompiles it can decrypt/forge whatever this key protects.",
                        "Generate the key at runtime into the Android Keystore (KeyGenParameterSpec) or derive it from a user secret with PBKDF2; never compile it in.",
                        m.range.first, "CWE-321")
                    continue
                }
                // 0.74.0: the key is a constant byte[] (new-array + fill-array-data), e.g. `byte[] key = {1,2,3,...}` (PIVAA)
                val arr = constByteArrayArg(text, m.range.first, 1)
                if (arr == null) {
                    // 0.94.0: a static byte[] of another class, or a ()[B method: resolved after the whole scan (FindingPolish.resolvePendingKeys)
                    byteSourceArg(text, m.range.first, 1)?.let { SecurityScanner.pendingKeys.add(SecurityScanner.PendingKey(ctx.classType, ctx.clsIndex, m.range.first, it, spec, ctx.appPkg)) }
                    continue
                }
                add(Severity.HIGH, "Hardcoded encryption key",
                    "A $spec is built from a constant byte array (${arr.size} bytes) written in the code - it sits in the APK, so anyone who decompiles it can decrypt/forge whatever this key protects.",
                    "Generate the key at runtime into the Android Keystore (KeyGenParameterSpec) or derive it from a user secret with PBKDF2; never compile it in.",
                    m.range.first, "CWE-321")
                continue
            }
            add(Severity.HIGH, "Hardcoded encryption key",
                "A $spec is built from a string literal (\"${lit.take(3)}…\", ${lit.length} chars) that sits in the APK - anyone who decompiles it can decrypt/forge whatever this key protects.",
                "Generate the key at runtime into the Android Keystore (KeyGenParameterSpec) or derive it from a user secret with PBKDF2; never compile it in.",
                m.range.first, "CWE-321")
        }

        // 0.50.2 (InsecureBankv2 CryptoClass): the key is a FIELD, not a literal next to SecretKeySpec. Either a compile-time constant
        // (".field ... key:Ljava/lang/String; = \"...\"") or an instance/static field set from a literal in <init>/<clinit>
        // (const-string + iput-object / sput-object). Only classes that use javax.crypto are checked, and only fields whose NAME ends in
        // key / secret / passphrase. A class that talks to the AndroidKeyStore is skipped (such a literal is an alias, not a key).
        if (!text.contains("AndroidKeyStore") && rx("Ljavax/crypto/(?:spec/SecretKeySpec|Cipher|Mac);").containsMatchIn(text)) {
            val nameRe = rx("^[A-Za-z0-9_]*(?:key|secret|passphrase)$", RegexOption.IGNORE_CASE)
            val keySpec = text.contains("Ljavax/crypto/spec/SecretKeySpec;-><init>")
            val seen = HashSet<String>()
            fun report(name: String, lit: String, at: Int) {
                if (!nameRe.containsMatchIn(name) || lit.startsWith("http") || lit.contains("android.")) return
                if (seen.size >= 2 || !seen.add(name)) return
                val read = rx("[is]get-object\\s+[vp]\\d+,\\s*(?:[vp]\\d+,\\s*)?L[^;]*;->" + name + ":Ljava/lang/String;").containsMatchIn(text)
                val strong = keySpec && read
                val f = ctx.finding(if (strong) Severity.HIGH else Severity.MEDIUM, "Hardcoded encryption key (field)",
                    "The field \"$name\" is initialised with a string literal (\"${lit.take(3)}…\", ${lit.length} chars) in a class that uses javax.crypto" +
                        (if (strong) " and builds a SecretKeySpec, so this literal is very likely the key itself" else "; if it feeds a key or cipher it is compiled into the APK") +
                        ". Anyone who decompiles the app can read it and decrypt/forge whatever it protects.",
                    "Generate the key at runtime into the Android Keystore (KeyGenParameterSpec) or derive it from a user secret with PBKDF2; never compile it in.",
                    at, "CWE-321")
                f.confidence = if (strong) "HIGH" else "MEDIUM"
                out.add(f)
            }
            for (m in rx("\\.field\\s+[^\\n]*?\\b(\\w+):Ljava/lang/String;\\s*=\\s*\"([^\"\\n]{8,120})\"").findAll(text))
                report(m.groupValues[1], m.groupValues[2], m.range.first)
            for (m in rx("const-string\\s+(v\\d+),\\s*\"([^\"\\n]{8,120})\"\\s*(?:\\.line\\s+\\d+\\s*)?[is]put-object\\s+\\1,\\s*(?:[vp]\\d+,\\s*)?L[^;]*;->(\\w+):Ljava/lang/String;").findAll(text))
                report(m.groupValues[3], m.groupValues[2], m.range.first)
        }

        return out
    }
}

object CryptoStaticIvRule : ScanRule {
    override val id = "crypto-static-iv"
    override val title = "Static IV"
    override val cwes = listOf("CWE-329")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Ljavax/crypto/spec/IvParameterSpec;-><init>\\(\\[B\\)V").findAll(text)) {
            val lit = literalBytesArg(text, m.range.first, 1)
            if (lit != null) {
                add(Severity.MEDIUM, "Static IV",
                    "An IvParameterSpec is built from a fixed string literal (\"${lit.take(3)}…\"). Reusing an IV with the same key breaks CBC/CTR/GCM confidentiality (GCM: catastrophic).",
                    "Generate a fresh random IV (SecureRandom) for every encryption and store it alongside the ciphertext.", m.range.first, "CWE-329")
                continue
            }
            // 0.74.0: the IV is a constant byte[] (new-array + fill-array-data), e.g. `byte[] iv = {0,0,...}` (PIVAA)
            val arr = constByteArrayArg(text, m.range.first, 1) ?: continue
            add(Severity.MEDIUM, "Static IV",
                "An IvParameterSpec is built from a constant byte array (${describeBytes(arr)}) written in the code. Reusing an IV with the same key breaks CBC/CTR/GCM confidentiality (GCM: catastrophic).",
                "Generate a fresh random IV (SecureRandom) for every encryption and store it alongside the ciphertext.", m.range.first, "CWE-329")
        }
        // 0.74.0: GCMParameterSpec(tagBits, byte[]) with a constant nonce
        for (m in rx("Ljavax/crypto/spec/GCMParameterSpec;-><init>\\(I\\[B\\)V").findAll(text)) {
            val arr = constByteArrayArg(text, m.range.first, 2) ?: continue
            add(Severity.MEDIUM, "Static IV",
                "A GCMParameterSpec is built from a constant nonce (${describeBytes(arr)}). With GCM, repeating a nonce under the same key leaks the plaintext XOR and lets an attacker forge messages.",
                "Generate a fresh random 12-byte nonce for every encryption and store it alongside the ciphertext.", m.range.first, "CWE-329")
        }

        return out
    }
}

object CryptoPbkdf2IterationsRule : ScanRule {
    override val id = "crypto-pbkdf2-iterations"
    override val title = "PBKDF2 with a low iteration count (iter)"
    override val cwes = listOf("CWE-916")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // --- 0.39.0: more crypto / token / IPC checks. Each one keys on an exact API call (no keyword guessing). ---
        for (m in rx("Ljavax/crypto/spec/PBEKeySpec;-><init>\\(\\[C\\[BII\\)V").findAll(text)) {
            val iter = argNumber(text, m.range.first, 3) ?: continue
            if (iter in 1L..9999L) {
                add(Severity.MEDIUM, "PBKDF2 with a low iteration count ($iter)",
                    "PBEKeySpec is created with only $iter iterations. A key (or stored password hash) derived from a password with so few iterations can be brute-forced very quickly.",
                    "Use at least 100,000 iterations of PBKDF2WithHmacSHA256 (OWASP currently recommends 600,000), or a memory-hard KDF such as Argon2 / scrypt.",
                    m.range.first, "CWE-916")
                break
            }
        }

        return out
    }
}

object CryptoSha1prngSeedRule : ScanRule {
    override val id = "crypto-sha1prng-seed"
    override val title = "SecureRandom(SHA1PRNG) seeded manually"
    override val cwes = listOf("CWE-336")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Ljava/security/SecureRandom;->getInstance\\(").findAll(text)) {
            if (argString(text, m.range.first, 0)?.equals("SHA1PRNG", ignoreCase = true) != true) continue
            val (bs, be) = methodBounds(text, m.range.first)
            if (!text.substring(bs, be).contains("Ljava/security/SecureRandom;->setSeed(")) continue
            // 0.86.1 (recall kit case 35): a seed that is a constant makes every output reproducible by anyone who has the APK
            val seedAt = text.indexOf("Ljava/security/SecureRandom;->setSeed(", bs)
            val constSeed = seedAt in bs..be && (literalBytesArg(text, seedAt, 1) != null || constByteArrayArg(text, seedAt, 1) != null)
            add(if (constSeed) Severity.HIGH else Severity.MEDIUM, "SecureRandom(SHA1PRNG) seeded manually" + (if (constSeed) " with a constant" else ""),
                "SecureRandom.getInstance(\"SHA1PRNG\") followed by setSeed() in the same method. With SHA1PRNG a seed set before the first use makes the output deterministic, so keys/tokens/IVs generated from it can be predicted (the classic Android key-derivation bug).",
                "Use new SecureRandom() without setSeed (the platform seeds it), and derive keys with a KDF or the Android Keystore.",
                m.range.first, "CWE-336")
            break
        }

        return out
    }
}

object JwtHardcodedSecretRule : ScanRule {
    override val id = "jwt-hardcoded-secret"
    override val title = "Hardcoded JWT signing secret"
    override val cwes = listOf("CWE-798")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        val jwtSinks = listOf(
            rx("Lio/jsonwebtoken/JwtParser;->setSigningKey\\(Ljava/lang/String;\\)") to 1,
            rx("Lio/jsonwebtoken/JwtBuilder;->signWith\\(Lio/jsonwebtoken/SignatureAlgorithm;Ljava/lang/String;\\)") to 2,
            rx("Lcom/auth0/jwt/algorithms/Algorithm;->HMAC(?:256|384|512)\\(Ljava/lang/String;\\)") to 0
        )
        var jwtDone = false
        for ((jre, jIdx) in jwtSinks) {
            if (jwtDone) break
            for (m in jre.findAll(text)) {
                val lit = argString(text, m.range.first, jIdx) ?: continue
                add(Severity.HIGH, "Hardcoded JWT signing secret",
                    "A JWT library is given a signing secret that is a string literal (\"${lit.take(3)}…\", ${lit.length} chars). Anyone who decompiles the APK can forge valid tokens for whatever this secret protects.",
                    "Sign tokens on your server only; the app should just send and store the token. Rotate this secret now, it is effectively public.",
                    m.range.first, "CWE-798")
                jwtDone = true
                break
            }
        }

        return out
    }
}

object IntentRedirectionRule : ScanRule {
    override val id = "intent-redirection"
    override val title = "Possible intent redirection (an Intent from the extras is launched)"
    override val cwes = listOf("CWE-927")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("->getParcelable(?:Extra)?\\((?:Landroid/content/Intent;)?Ljava/lang/String;").findAll(text)) {   // 0.48.2: also IntentCompat.getParcelableExtra(Intent, String, Class)
            val (bs, be) = methodBounds(text, m.range.first)
            val body = text.substring(bs, be)
            if (!rx("check-cast\\s+v\\d+,\\s*Landroid/content/Intent;").containsMatchIn(body)) continue
            if (!rx("->(?:startActivity|startActivityForResult|startService|startForegroundService|sendBroadcast)\\(").containsMatchIn(body)) continue
            if (body.contains("->resolveActivity(") || body.contains("Landroid/content/Intent;->setComponent(") || body.contains("Landroid/content/Intent;->setPackage(")) continue
            add(Severity.MEDIUM, "Possible intent redirection (an Intent from the extras is launched)",
                "This method reads a Parcelable from the incoming extras, casts it to Intent and then starts an activity/service or sends a broadcast. If the component is reachable by other apps, the caller chooses WHAT gets started - including non-exported components of this app, with this app's permissions.",
                "Do not launch an Intent received from outside. If you must, check the target (resolveActivity / allow-list of components) and clear flags such as FLAG_GRANT_*_URI_PERMISSION first.",
                m.range.first, "CWE-927")
            break
        }

        return out
    }
}

object FragmentInjectionRule : ScanRule {
    override val id = "fragment-injection"
    override val title = "Fragment injection (PreferenceActivity.isValidFragment returns true)"
    override val cwes = listOf("CWE-470")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        if (text.contains(".super Landroid/preference/PreferenceActivity;")) {
            rx("\\.method[^\\n]*isValidFragment\\(Ljava/lang/String;\\)Z[ \\t]*\\n(?:[ \\t]*\\.[^\\n]*\\n|[ \\t]*\\n)*[ \\t]*const/4[ \\t]+(v\\d+),[ \\t]*0x1[ \\t]*\\n(?:[ \\t]*\\.[^\\n]*\\n|[ \\t]*\\n)*[ \\t]*return[ \\t]+\\1[ \\t]*\\n(?:[ \\t]*\\.[^\\n]*\\n|[ \\t]*\\n)*[ \\t]*\\.end method").find(text)?.let {
                add(Severity.MEDIUM, "Fragment injection (PreferenceActivity.isValidFragment returns true)",
                    "This PreferenceActivity accepts ANY fragment name. If the activity is exported, another app can pass :android:show_fragment with the name of any Fragment class available to this app and make it run inside this app's process and permissions.",
                    "Return true only for an explicit allow-list of your own fragment class names, or do not export the activity.",
                    it.range.first, "CWE-470")
            }
        }

        return out
    }
}

object WebviewIntentUrlRule : ScanRule {
    override val id = "webview-intent-url"
    override val title = "WebView loads a URL taken straight from an Intent"
    override val cwes = listOf("CWE-939")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Landroid/webkit/WebView;->loadUrl\\(").findAll(text)) {
            if (argString(text, m.range.first, 1) != null) continue          // constant URL
            val (bs, be) = methodBounds(text, m.range.first)
            val body = text.substring(bs, be)
            if (!rx("Landroid/content/Intent;->(?:getStringExtra|getDataString|getData)\\(").containsMatchIn(body)) continue
            if (body.contains("Landroid/net/Uri;->getHost()") || body.contains("Ljava/lang/String;->startsWith(") || body.contains("Ljava/lang/String;->equals(") ||
                body.contains("Ljava/lang/StringBuilder;->append(") || body.contains("Ljava/lang/String;->concat(")) continue
            add(Severity.MEDIUM, "WebView loads a URL taken straight from an Intent",
                "loadUrl() receives a value read from the incoming Intent with no host check or fixed prefix in the same method. Another app (or a link) can make the WebView open any page, including a phishing page inside your app, or a file:// / javascript: URL.",
                "Allow-list the host (and https only) before loading, or build the URL from a fixed base plus a validated id.",
                m.range.first, "CWE-939")
            break
        }

        return out
    }
}

object OkhttpLoggingRule : ScanRule {
    override val id = "okhttp-logging"
    override val title = "OkHttp logs requests/responses (Level.{it.groupValues[1]})"
    override val cwes = listOf("CWE-532")
    override val confidence = "LOW"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        rx("Lokhttp3/logging/HttpLoggingInterceptor\\\$Level;->(BODY|HEADERS):").find(text)?.let {
            add(Severity.LOW, "OkHttp logs requests/responses (Level.${it.groupValues[1]})",
                "HttpLoggingInterceptor is set to ${it.groupValues[1]}: request/response data (tokens, cookies, personal data) is written to logcat, which other tools on the device or a connected PC can read.",
                "Use Level.NONE (or BASIC) in release builds; enable BODY only when BuildConfig.DEBUG.",
                it.range.first, "CWE-532")
        }

        return out
    }
}

object SecretsKnownFormatsRule : ScanRule {
    override val id = "secrets-known-formats"
    override val title = "Hardcoded credential: what"
    override val cwes = listOf("CWE-798")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // --- hardcoded secrets (known formats) ---
        val formats = listOf(
            Triple(rx("const-string[^,]*,\\s*\"[^\"\\n]*(AKIA[0-9A-Z]{16})"), Severity.CRITICAL, "AWS access key id"),
            Triple(rx("const-string[^,]*,\\s*\"[^\"\\n]*(sk_live_[0-9a-zA-Z]{20,})"), Severity.CRITICAL, "Stripe live secret key"),
            Triple(rx("const-string[^,]*,\\s*\"[^\"\\n]*(gh[pousr]_[A-Za-z0-9]{36,})"), Severity.CRITICAL, "GitHub token"),
            Triple(rx("const-string[^,]*,\\s*\"[^\"\\n]*(xox[baprs]-[0-9A-Za-z-]{10,})"), Severity.HIGH, "Slack token"),
            Triple(rx("const-string[^,]*,\\s*\"[^\"\\n]*(\\d{8,10}:[A-Za-z0-9_-]{35})\""), Severity.HIGH, "Telegram bot token"),
            Triple(rx("const-string[^,]*,\\s*\"[^\"\\n]*(eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,})"), Severity.HIGH, "JWT"),
            // 0.76.0: a header alone is what every key PARSER contains (jsch, sshj): a key needs its base64 body in the same literal
            Triple(rx("const-string[^,]*,\\s*\"[^\"\\n]*(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----(?:\\\\[rn]|\\s)*[A-Za-z0-9+/]{40,})"), Severity.CRITICAL, "Private key block")
        )
        for ((re, sev, what) in formats) {
            re.find(text)?.let {
                add(sev, "Hardcoded credential: $what",
                    "A string matching the $what format is embedded in the code (\"${it.groupValues[1].take(8)}…\"). Anyone who decompiles the APK - as this tool just did - can read it in plain text.",
                    "Never ship live secrets inside the app. Fetch short-lived tokens from your own backend, or scope the credential down heavily and rotate it now since it is effectively public.",
                    it.range.first, "CWE-798")
            }
        }

        return out
    }
}

object SecretsGoogleApiKeyRule : ScanRule {
    override val id = "secrets-google-api-key"
    override val title = "Google API key embedded"
    override val cwes = listOf("CWE-798")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        rx("const-string[^,]*,\\s*\"(AIza[0-9A-Za-z_\\-]{35})\"").find(text)?.let {
            add(Severity.MEDIUM, "Google API key embedded",
                "A Google API key (AIza…) is in the code. Firebase/Maps client keys are meant to ship in apps, but if the key is unrestricted anyone can use your quota and any enabled paid API.",
                "In Google Cloud Console restrict this key to your package name + signing SHA-1 and to only the APIs you use; keep server-side keys out of the app.",
                it.range.first, "CWE-798")
        }

        return out
    }
}

object SecretsSensitiveFieldsRule : ScanRule {
    override val id = "secrets-sensitive-fields"
    override val title = "Hardcoded sensitive field: name"
    override val cwes = listOf("CWE-798")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // fields with a credential-like name initialised with a secret-looking literal
        var fieldHits = 0
        for (m in rx("\\.field[^\\n]*?\\s([\\w\$]+):[^\\n]*=\\s*\"([^\"\\n]{6,})\"").findAll(text)) {
            if (fieldHits >= 3) break
            val name = m.groupValues[1]
            val v = m.groupValues[2]
            if (!identHas(name, secretWords)) continue
            if (v.contains(' ') || v.contains("://") || v.contains('%')) continue
            // JSON/pref key names ("auth_token", "access.token") and CONSTANT_NAMES are not secrets
            if (rx("^[a-z][a-z0-9]*([_.\\-][a-z0-9]+)*$").matches(v) && (v.any { it == '_' || it == '.' || it == '-' } || v.all { it.isLetter() })) continue
            if (rx("^[A-Z][A-Z0-9_]*$").matches(v)) continue
            // 0.66.4: Binder interface descriptors ("com.google.android.gms.ads.identifier.internal.IAdvertisingIdService"),
            // JCA transformations and similar NAMES are not secrets (same filter the entropy rule already uses)
            if (SecurityScanner.looksLikeName(v)) continue
            val classes = charClasses(v)
            val strong = classes >= 3 || v.length >= 16
            // 0.86.0: HIGH only with positive evidence (the value reaches a key / credential sink in this class), see SecretEvidence
            val ev = SecretEvidence.forField(text, classType, name, v) ?: SecretEvidence.formatOf(v)
            val sev = when {
                ev != null && strong -> Severity.HIGH
                ev != null || strong -> Severity.MEDIUM
                else -> Severity.LOW
            }
            fieldHits++
            add(sev, "Hardcoded sensitive field: $name",
                "A field named like a credential is initialised with a fixed secret-looking string (\"${v.take(3)}…\", ${v.length} chars), so it is baked into the APK and readable after decompiling. " +
                    (if (ev != null) "Evidence that it is a working secret: $ev."
                     else "No use as a key, IV or credential was seen in this class: the name and the shape of the value are the only evidence, so it may be a public value (an id, a name, a key-store alias)."),
                "Load this from a secure backend at runtime, or store it via the Android Keystore - don't compile it into the APK.",
                m.range.first, "CWE-798")
            if (ev == null) out.last().confidence = "MEDIUM"
        }

        return out
    }
}

object TlsTrustmanagerRule : ScanRule {
    override val id = "tls-trustmanager"
    override val title = "TLS certificate validation disabled"
    override val cwes = listOf("CWE-295")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // --- TLS ---
        if (text.contains("X509TrustManager")) {
            // 0.66.4: only the 2-argument overload (X509Certificate[], String) and only a real method declaration (".method ... checkServerTrusted(")
            rx("\\.method[^\\n]* checkServerTrusted\\(\\[Ljava/security/cert/X509Certificate;Ljava/lang/String;\\)V[^\\n]*\\n$METHOD_PREAMBLE$NULL_CHECKS\\s*return-void").find(text)?.let {
                add(Severity.CRITICAL, "TLS certificate validation disabled",
                    "This class implements X509TrustManager, and checkServerTrusted() returns right after its locals/param declarations with no verification call in between - it accepts ANY certificate, attacker's included.",
                    "Remove the custom TrustManager and use the platform default (or pin to the real certificate/public key via a network security config); never ship a no-op trust manager.",
                    it.range.first, "CWE-295")
            }
        }

        return out
    }
}

object TlsHostnameVerifierRule : ScanRule {
    override val id = "tls-hostname-verifier"
    override val title = "Hostname verification disabled"
    override val cwes = listOf("CWE-297")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        if (text.contains("HostnameVerifier")) {
            (rx("ALLOW_ALL_HOSTNAME_VERIFIER").find(text)
                ?: rx("\\.method[^\\n]* verify\\(Ljava/lang/String;Ljavax/net/ssl/SSLSession;\\)Z[^\\n]*\\n$METHOD_PREAMBLE\\s*const/4[^\\n]*,\\s*0x1\\s*\\n$METHOD_PREAMBLE\\s*return").find(text))
                ?.let {
                    add(Severity.HIGH, "Hostname verification disabled",
                        "A HostnameVerifier that accepts every hostname (ALLOW_ALL_HOSTNAME_VERIFIER, or a verify() that always returns a hardcoded true) is used - TLS stops confirming the server is who it claims to be.",
                        "Use the default HostnameVerifier, or a strict one that actually checks the certificate against the hostname.",
                        it.range.first, "CWE-297")
                }
        }

        return out
    }
}

object TlsInsecureSocketFactoryRule : ScanRule {
    override val id = "tls-insecure-socket-factory"
    override val title = "Insecure SSL socket factory"
    override val cwes = listOf("CWE-295")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        rx("Landroid/net/SSLCertificateSocketFactory;->getInsecure\\(").find(text)?.let {
            add(Severity.HIGH, "Insecure SSL socket factory",
                "SSLCertificateSocketFactory.getInsecure() skips certificate and hostname checks.",
                "Use the default SSLSocketFactory / HttpsURLConnection behaviour.", it.range.first, "CWE-295")
        }

        return out
    }
}

object StorageFileModeRule : ScanRule {
    override val id = "storage-file-mode"
    override val title = "World-readable/writable file mode ({m.groupValues[1]})"
    override val cwes = listOf("CWE-276")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // --- storage / IPC ---
        for (m in rx("L(?:android/content/Context|android/content/ContextWrapper|android/app/Activity|android/app/Application|android/app/Service);->(openFileOutput|getSharedPreferences|getDir)\\(").findAll(text)) {
            val mode = argNumber(text, m.range.first, 0, fromEnd = true) ?: continue
            if (mode == 1L || mode == 2L || mode == 3L) {
                add(Severity.MEDIUM, "World-readable/writable file mode (${m.groupValues[1]})",
                    "MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE exposes the file to every app on the device (and throws SecurityException on targetSdk >= 24, so it may also be dead/buggy code).",
                    "Use MODE_PRIVATE and share data through a FileProvider/ContentProvider with explicit permissions.", m.range.first, "CWE-276")
            }
        }

        return out
    }
}

object PendingintentMutableRule : ScanRule {
    override val id = "pendingintent-mutable"
    override val title = "PendingIntent without FLAG_IMMUTABLE"
    override val cwes = listOf("CWE-927")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Landroid/app/PendingIntent;->get(?:Activity|Broadcast|Service|ForegroundService)\\(").findAll(text)) {
            val flags = argNumber(text, m.range.first, 0, fromEnd = true) ?: continue
            if ((flags and 0x04000000L) == 0L) {
                // 0.86.1 (recall kit case 28): the base Intent is EMPTY and implicit (new Intent() and nothing that names a target in this method):
                // the receiver of a mutable PendingIntent can then fill in the action AND the component, i.e. redirect it anywhere
                val (bs, be) = methodBounds(text, m.range.first)
                val body = text.substring(bs, be)
                // a RemoteViews template (setPendingIntentTemplate) MUST be mutable and empty: the app fills it per row (Catima ListWidget) and the
                // holder is the launcher, so that pattern stays LOW
                val emptyImplicit = body.contains("Landroid/content/Intent;-><init>()V") &&
                    listOf("->setComponent(", "->setClass(", "->setClassName(", "->setPackage(").none { body.contains(it) } &&
                    !text.contains("RemoteViews;->setPendingIntentTemplate(")
                add(if (emptyImplicit) Severity.MEDIUM else Severity.LOW, "PendingIntent without FLAG_IMMUTABLE",
                    "A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly." +
                        (if (emptyImplicit) " The base Intent is empty and implicit here (no component, no package), so the receiver can also choose the target: the PendingIntent can be redirected anywhere with this app's identity." else ""),
                    "Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.", m.range.first, "CWE-927")
            }
        }

        return out
    }
}

object ReceiverExportFlagRule : ScanRule {
    override val id = "receiver-export-flag"
    override val title = "Dynamic receiver registered without export flag"
    override val cwes = listOf("CWE-926")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        rx("->registerReceiver\\(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;\\)").find(text)?.let {
            add(Severity.LOW, "Dynamic receiver registered without export flag",
                "registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.",
                "Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.",
                it.range.first, "CWE-926")
        }

        return out
    }
}

object DeserializationRule : ScanRule {
    override val id = "deserialization"
    override val title = "Java deserialization (ObjectInputStream.readObject)"
    override val cwes = listOf("CWE-502")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        rx("Ljava/io/ObjectInputStream;->readObject\\(").find(text)?.let {
            add(Severity.MEDIUM, "Java deserialization (ObjectInputStream.readObject)",
                "Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.",
                "Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.", it.range.first, "CWE-502")
        }

        return out
    }
}

object IntentParseuriRule : ScanRule {
    override val id = "intent-parseuri"
    override val title = "Intent.parseUri (intent redirection)"
    override val cwes = listOf("CWE-927")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        rx("Landroid/content/Intent;->parseUri\\(").find(text)?.let {
            add(Severity.MEDIUM, "Intent.parseUri (intent redirection)",
                "Building an Intent from a string (often from a link/extra) lets an attacker choose the target component and extras; unchecked, this reaches non-exported components.",
                "Parse with URI_INTENT_SCHEME, then clear the component/selector, and verify the target is allow-listed before startActivity.", it.range.first, "CWE-927")
        }

        return out
    }
}

object DynamicCodeLoadingRule : ScanRule {
    override val id = "dynamic-code-loading"
    override val title = "Dynamic code loading"
    override val cwes = listOf("CWE-94")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        rx("Ldalvik/system/(?:DexClassLoader|InMemoryDexClassLoader|PathClassLoader);-><init>").find(text)?.let {
            add(Severity.MEDIUM, "Dynamic code loading",
                "The app loads code at runtime (DexClassLoader & co). If the dex/jar comes from a writable or downloaded location without integrity checks, an attacker can swap it and run code with the app's permissions.",
                "Load code only from app-private, read-only storage, verify a signature/hash, or bundle it in the APK.", it.range.first, "CWE-94")
        }

        return out
    }
}

object ExternalStorageRule : ScanRule {
    override val id = "external-storage"
    override val title = "Shared external storage used"
    override val cwes = listOf("CWE-922")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        rx("Landroid/os/Environment;->getExternalStorageDirectory\\(").find(text)?.let {
            add(Severity.LOW, "Shared external storage used",
                "Files on shared storage can be read (and before scoped storage, replaced) by other apps.",
                "Keep sensitive data in internal storage (filesDir) or getExternalFilesDir with encryption.", it.range.first, "CWE-922")
        }

        return out
    }
}

object ShellExecRule : ScanRule {
    override val id = "shell-exec"
    override val title = "Shell command execution"
    override val cwes = listOf("CWE-78")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        rx("Ljava/lang/Runtime;->exec\\(|Ljava/lang/ProcessBuilder;-><init>").find(text)?.let {
            // 0.102.0: every call site of the class has only constant arguments (literals, or a constant-indexed string-table lookup): nothing to inject into
            val (sites, fixed) = ConstantArgGuards.shellSites(text)
            if (sites > 0 && fixed == sites) {
                add(Severity.LOW, "Shell command execution with fixed arguments",
                    "Every Runtime.exec / ProcessBuilder call in this class ($sites) takes only constant arguments: string literals, or the result of a constant-indexed static string lookup (the string-table decryptor of a protector). There is no input to inject into. Such calls are typical of root / emulator checks (su, which su, getprop); with the decoded-strings overlay the command is visible. Read the command to see what it does.",
                    "Nothing to fix for injection. If the command is a root / emulator check, note that it is easy to bypass; if it is something else, check that it needs to run a shell at all.",
                    it.range.first, "CWE-78")
                return out
            }
            add(Severity.MEDIUM, "Shell command execution",
                "The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.",
                "Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.",
                it.range.first, "CWE-78")
        }

        return out
    }
}

object CleartextUrlRule : ScanRule {
    override val id = "cleartext-url"
    override val title = "Hardcoded cleartext URL"
    override val cwes = listOf("CWE-319")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // cleartext URLs (one finding per class; XML/namespace/loopback hosts are ignored)
        val ignoredHttp = rx("^http://(?:schemas\\.android\\.com|www\\.w3\\.org|xml\\.org|xmlpull\\.org|ns\\.adobe\\.com|www\\.apache\\.org|apache\\.org|java\\.sun\\.com|localhost|127\\.0\\.0\\.1|10\\.0\\.2\\.2|www\\.google\\.com/schemas|schemas\\.microsoft\\.com|purl\\.org|www\\.opengis\\.net|www\\.sitemaps\\.org|json-schema\\.org|ietf\\.org|www\\.ietf\\.org)")
        var httpCount = 0
        var httpFirst: MatchResult? = null
        for (m in rx("const-string[^,]*,\\s*\"(http://[^\"\\s]{4,})\"").findAll(text)) {
            if (ignoredHttp.containsMatchIn(m.groupValues[1])) continue
            httpCount++
            if (httpFirst == null) httpFirst = m
        }
        httpFirst?.let {
            val f = Finding(Severity.LOW, "Hardcoded cleartext URL",
                "A plain http:// URL is hardcoded (${it.groupValues[1].take(60)})" + (if (httpCount > 1) " and ${httpCount - 1} more in this class" else "") +
                    ". Traffic to it can be read or modified on the network.  (around line ${lineNo(text, it.range.first)})",
                "Switch to https:// (and make sure the server supports it).", classType, clsIndex, it.range.first, "CWE-319")
            out.add(f)
        }

        return out
    }
}

object LogSensitiveStringsRule : ScanRule {
    override val id = "log-sensitive-strings"
    override val title = "Possible sensitive data in logs"
    override val cwes = listOf("CWE-532")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // --- Logs / SQL / Random ---
        var logHits = 0
        for (m in rx("const-string[^,]*,\\s*\"([^\"\\n]*\\b(?:password|passwd|token|secret|session|auth)\\b[^\"\\n]*)\"", RegexOption.IGNORE_CASE).findAll(text)) {
            if (logHits >= 3) break
            val window = text.substring(m.range.first, minOf(text.length, m.range.last + 250))
            if (rx("Landroid/util/Log;->[dwiev]\\(").containsMatchIn(window)) {
                logHits++
                add(Severity.LOW, "Possible sensitive data in logs",
                    "A string passed near a Log call mentions a credential-like word (\"${m.groupValues[1].take(40)}\"). Logcat output can be read by other apps with the right permission on many devices.",
                    "Never log passwords, tokens, or session identifiers, even at debug level; strip such log calls from release builds.",
                    m.range.first, "CWE-532")
            }
        }

        return out
    }
}

object SqlConcatRule : ScanRule {
    override val id = "sql-concat"
    override val title = "Possible SQL built by string concatenation"
    override val cwes = listOf("CWE-89")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Landroid/database/sqlite/SQLiteDatabase;->(rawQuery|execSQL)").findAll(text)) {
            val start = maxOf(0, m.range.first - 400)
            if (text.substring(start, m.range.first).contains("Ljava/lang/StringBuilder;->append")) {
                add(Severity.MEDIUM, "Possible SQL built by string concatenation",
                    "rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.",
                    "Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.",
                    m.range.first, "CWE-89")
                break
            }
        }

        return out
    }
}

object WeakRandomRule : ScanRule {
    override val id = "weak-random"
    override val title = "Non-cryptographic Random used near security-sounding code"
    override val cwes = listOf("CWE-338")
    override val confidence = "MEDIUM"

    /**
     * 0.75.1: decided on the IR (IrRules.weakRandom): the OUTPUT of java.util.Random / Math.random is followed in SSA to a security use
     * (key / IV spec, a field / column / extra named like a secret, the return value of a crypto class or a token-like method). The old
     * "security word within a few lines" heuristic ([legacy]) runs only when the class cannot be parsed.
     */
    override fun scan(ctx: RuleContext): List<Finding> {
        if (!ctx.text.contains("Ljava/util/Random;->") && !ctx.text.contains("Ljava/lang/Math;->random")) return emptyList()
        val c = ctx.ir ?: return legacy(ctx)
        return IrHits.toFindings(ctx, dev.apkrelab.ir.IrRules.weakRandom(c, ctx.text),
            "Use java.security.SecureRandom (and never a fixed seed) for tokens, PINs, salts, IVs and keys.")
    }

    fun legacy(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        for (m in rx("Ljava/util/Random;-><init>").findAll(text)) {
            if (contextHas(text, m.range.first, m.range.last + 1, randomWords)) {
                add(Severity.MEDIUM, "Non-cryptographic Random used near security-sounding code",
                    "java.util.Random (predictable once its seed/state is known) is created close to code whose identifiers mention token/session/nonce/otp/secret/password.",
                    "If this Random feeds anything security-sensitive, replace it with java.security.SecureRandom.",
                    m.range.first, "CWE-338")
                break
            }
        }

        return out
    }
}

object ZipSlipRule : ScanRule {
    override val id = "zip-slip"
    override val title = "Possible Zip Slip (unsanitized zip entry path)"
    override val cwes = listOf("CWE-22")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // --- 0.35.0: Zip Slip (unsanitized zip-entry path during extraction) ---
        rx("Ljava/util/zip/ZipEntry;->getName\\(").find(text)?.let { m ->
            val (ms, me) = methodBounds(text, m.range.first)
            val body = text.substring(ms, me)
            val writesFile = body.contains("Ljava/io/FileOutputStream;-><init>") ||
                body.contains("Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V") ||
                body.contains("Ljava/io/File;-><init>(Ljava/lang/String;Ljava/lang/String;)V")
            val guarded = body.contains("getCanonicalPath") || body.contains("getCanonicalFile") || body.contains("normalize")
            // 0.77.0 (Termux TermuxInstaller: the bootstrap zip is a byte[] from the app's own native library): an archive that comes from
            // inside the APK (assets, raw resources, class-path resources, a byte[] returned by an app method with no arguments) is not
            // attacker-controlled; reported LOW so a reviewer can still see it
            val embedded = body.contains("Landroid/content/res/AssetManager;->open") || body.contains("->openRawResource(") ||
                body.contains(";->getResourceAsStream(") ||
                (body.contains("Ljava/io/ByteArrayInputStream;-><init>") && rx("invoke-static \\{\\}, L[^;]+;->[A-Za-z0-9_\$]+\\(\\)\\[B").containsMatchIn(body))
            if (writesFile && !guarded && embedded) {
                add(Severity.LOW, "Zip extraction without a path check (archive from inside the APK)",
                    "This method builds output paths from ZipEntry.getName() with no getCanonicalPath()/normalize() check, but the archive comes from inside the APK (assets, a raw resource or a byte[] the app loads itself), so an attacker cannot choose the entry names unless the APK itself is modified.",
                    "Add the canonical-path check anyway if this code may ever extract an archive from outside the APK.",
                    m.range.first, "CWE-22")
            } else if (writesFile && !guarded) {
                add(Severity.HIGH, "Possible Zip Slip (unsanitized zip entry path)",
                    "This method reads ZipEntry.getName() while extracting an archive and builds a File/output path from it, with no getCanonicalPath()/normalize() check anywhere in the method. A crafted entry name containing \"../\" segments can write outside the intended extraction directory (e.g. overwrite app files or drop an executable in a sensitive location).",
                    "Resolve the destination file, call getCanonicalPath() on it, and verify it still starts with the intended output directory before writing; reject/skip any entry that fails the check.",
                    m.range.first, "CWE-22")
            }
        }

        return out
    }
}

object TlsProtocolVersionRule : ScanRule {
    override val id = "tls-protocol-version"
    override val title = "Insecure TLS protocol requested: proto"
    override val cwes = listOf("CWE-327")
    override val confidence = "HIGH"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // --- 0.35.0: insecure/downgraded TLS protocol version ---
        for (m in rx("Ljavax/net/ssl/SSLContext;->getInstance\\(").findAll(text)) {
            val proto = argString(text, m.range.first, 0)?.uppercase() ?: continue
            val broken = proto in setOf("SSL", "SSLV2", "SSLV3")
            // 0.66.4: plain "TLS" is NOT insecure on Android: it means the platform default (TLS 1.2/1.3 on modern releases).
            // Only flag it when the app can run on a release where "TLS" meant TLSv1 (minSdk < 20): not known here, so it is left out.
            val deprecated = proto in setOf("TLSV1", "TLSV1.1")
            if (broken || deprecated) {
                add(if (broken) Severity.HIGH else Severity.MEDIUM, "Insecure TLS protocol requested: \"$proto\"",
                    "SSLContext.getInstance(\"$proto\") is used. " + (if (broken)
                        "SSL/SSLv2/SSLv3 are broken (POODLE and other attacks let a network attacker decrypt or tamper with the connection)."
                    else "\"$proto\" pins an old protocol version (TLSv1/TLSv1.1 are deprecated and disabled by many servers as of 2021)."),
                    "Use SSLContext.getInstance(\"TLSv1.3\") (fall back to \"TLSv1.2\" only if you must support very old peers), or omit explicit protocol selection and rely on the platform default on modern API levels.",
                    m.range.first, "CWE-327")
                break
            }
        }

        return out
    }
}

object ProviderSqlInjectionRule : ScanRule {
    override val id = "provider-sql-injection"
    override val title = "ContentProvider.query() may build SQL by string concatenation"
    override val cwes = listOf("CWE-89")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val classType = ctx.classType
        val clsIndex = ctx.clsIndex
        val appPkg = ctx.appPkg
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String = "") {
            out.add(ctx.finding(sev, title, detail, rec, offset, cwe))
        }

        // --- 0.35.0: ContentProvider SQL injection (query()/raw SQL built by concatenation) ---
        if (text.contains(".super Landroid/content/ContentProvider;")) {
            val qi = text.indexOf(".method public query(")
            if (qi >= 0) {
                val (qs, qe) = methodBounds(text, qi)
                val body = text.substring(qs, qe)
                val concatenated = body.contains("Ljava/lang/StringBuilder;->append(") || body.contains("Ljava/lang/String;->concat(")
                val rawSql = body.contains("->rawQuery(") || body.contains("->execSQL(")
                if (concatenated && rawSql) {
                    add(Severity.HIGH, "ContentProvider.query() may build SQL by string concatenation",
                        "This provider's query() both concatenates strings (StringBuilder/concat) and runs rawQuery/execSQL. If any part of the SQL comes from the incoming Uri (path segments, a query parameter) or the caller-supplied selection/projection, another app can inject SQL through this exported entry point.",
                        "Use SQLiteDatabase.query()'s own selection + selectionArgs (parameterized), or rawQuery(sql, selectionArgs) with '?' placeholders; never concatenate caller-controlled text into the SQL string.",
                        qi, "CWE-89")
                }
            }
        }

        return out
    }
}

/** 0.74.0: short text for a constant byte array in a finding ("16 bytes, all zero", "16 bytes: 01 02 03 ..."); never longer than about 40 chars. */
internal fun describeBytes(b: ByteArray): String {
    if (b.all { it == 0.toByte() }) return "${b.size} bytes, all zero"
    if (b.all { it == b[0] }) return "${b.size} bytes, all the same value"
    return "${b.size} bytes: " + b.take(4).joinToString(" ") { "%02x".format(it) } + if (b.size > 4) " ..." else ""
}

/**
 * 0.81.0 (AnkiDroid CardContentProvider: exported with no manifest permission, but every operation enforces READ_WRITE_DATABASE in code):
 * an INFO marker when EVERY data method this provider overrides (query, insert, update, delete, bulkInsert, openFile, call) checks the
 * caller in its own body or in a method of this class it calls (2 hops): checkCallingPermission, checkCallingOrSelfPermission,
 * enforceCallingPermission, enforceCallingOrSelfPermission, checkCallingUriPermission, or getCallingPackage / Binder.getCallingUid compared
 * against something. [FindingPolish.applyProviderCodeChecks] then lowers the manifest "exported provider without a permission" card.
 * One unchecked method and there is no marker.
 */
object ProviderCodePermissionRule : ScanRule {
    override val id = "provider-code-permission"
    override val title = "ContentProvider checks the caller in code"
    override val cwes = listOf("CWE-926")
    override val confidence = "MEDIUM"

    private val dataMethods = setOf("query", "insert", "update", "delete", "bulkInsert", "openFile", "call")
    private val checkRe = rx("->(?:checkCallingPermission|checkCallingOrSelfPermission|enforceCallingPermission|enforceCallingOrSelfPermission|checkCallingUriPermission|enforceCallingUriPermission|getCallingPackage|getCallingUid)\\(")

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        if (!text.contains(".super Landroid/content/ContentProvider;") || !checkRe.containsMatchIn(text)) return emptyList()
        val all = rx("\\.method [^\\n]*?([A-Za-z0-9_\$<>]+)\\(([^\\n]*)\\n((?:(?!\\.end method)[\\s\\S])*?)\\.end method").findAll(text).toList()
        val byName = HashMap<String, String>()
        for (mm in all) byName[mm.groupValues[1]] = (byName[mm.groupValues[1]] ?: "") + mm.groupValues[3]
        val callRe = rx(Regex.escape(ctx.classType) + "->([A-Za-z0-9_\$]+)\\(")
        fun checked(body: String): Boolean {
            if (checkRe.containsMatchIn(body)) return true
            var frontier = listOf(body); val seen = HashSet<String>()
            for (hop in 1..2) {
                val next = ArrayList<String>()
                for (b in frontier) for (c in callRe.findAll(b)) {
                    val hb = byName[c.groupValues[1]] ?: continue
                    if (!seen.add(c.groupValues[1])) continue
                    if (checkRe.containsMatchIn(hb)) return true
                    next.add(hb)
                }
                frontier = next
            }
            return false
        }
        val present = all.filter { it.groupValues[1] in dataMethods }
        if (present.isEmpty() || present.any { !checked(it.groupValues[3]) }) return emptyList()
        return listOf(ctx.finding(Severity.INFO, title,
            "Every data method of this provider (" + present.map { it.groupValues[1] }.distinct().joinToString(", ") + ") checks the calling app in code (permission check or calling package / uid).",
            "Keep the check in every method; a manifest android:permission / readPermission / writePermission is easier to audit.",
            text.indexOf(".super Landroid/content/ContentProvider;").coerceAtLeast(0), "CWE-926"))
    }
}

/**
 * 0.89.0: vendor credential formats (206 of them: Stripe, Slack, GitHub, GitLab, Twilio, SendGrid, Mailgun, Square, Shopify, Telegram, Discord, npm, PyPI, Algolia, Mapbox, Azure AD, Atlassian,
 * Hugging Face, OpenAI, Anthropic, ...) from the gitleaks rule set, checked against every string constant of a class. The few formats already in [SecretsKnownFormatsRule] are not repeated:
 * the dedupe merges findings of one place. A format with a fixed prefix IS the positive evidence, so these are HIGH like the other known formats.
 */
object SecretsVendorTokensRule : ScanRule {
    override val id = "secrets-vendor-tokens"
    override val title = "Vendor credential embedded"
    override val cwes = listOf("CWE-798")
    override val confidence = "HIGH"

    private val constStr = rx("const-string(?:/jumbo)?\\s+[vp]\\d+,\\s*\"((?:[^\"\\\\\\n]|\\\\.)*)\"")

    override fun scan(ctx: RuleContext): List<Finding> {
        if (!SecretFormats.loaded()) return emptyList()
        val text = ctx.text
        if (!text.contains("const-string")) return emptyList()
        val out = ArrayList<Finding>()
        val seen = HashSet<String>()
        for (m in constStr.findAll(text)) {
            val v = m.groupValues[1].replace("\\\"", "\"").replace("\\\\", "\\")
            if (v.length < 12) continue
            for (h in SecretFormats.scan(v)) {
                if (SecretFormats.looksLikePlaceholder(h.secret) || !seen.add(h.ruleId + h.secret)) continue
                val shown = h.secret.take(4) + "… (" + h.secret.length + " chars)"
                out.add(ctx.finding(Severity.HIGH, "Hardcoded credential: " + h.desc.removePrefix("Identified a ").removePrefix("Detected a ").removePrefix("Uncovered a ").removePrefix("Found a ").removePrefix("Discovered a ").take(70).trimEnd('.', ' '),
                    "A string matching the format of a vendor credential (\"${h.ruleId}\", value $shown) is embedded in the code. Anyone who decompiles the APK can read it in plain text and, if it is live, use it.",
                    "Never ship a live credential in the app: fetch a short-lived token from your own backend, or scope the credential down hard and rotate it now, since it is effectively public.",
                    m.range.first, "CWE-798"))
            }
        }
        return out
    }
}
