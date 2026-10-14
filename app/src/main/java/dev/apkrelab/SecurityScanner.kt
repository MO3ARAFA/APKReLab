package dev.apkrelab

import kotlin.math.log2

/**
 * Lightweight static security scanner (SAST) over the decoded manifest and baksmali text.
 * 0.18.0 first version, 0.19.0 accuracy pass, 0.21.0: context-aware matching (no more substring
 * hits inside type descriptors), register back-tracing for const arguments, library/app scope,
 * CWE tags, per-class dedup, and many new checks.
 * Heuristic and educational: it flags patterns worth a human look (use the AI triage for a
 * second opinion); it is not a replacement for MobSF or a real audit.
 */
object SecurityScanner {

    // a run of smali metadata lines (.locals/.line/.param/...) between a method header and its first real instruction.
    // 0.74.0: also whole `.annotation ... .end annotation` blocks (their inner lines, `value = {` / `Ljava/...;` / `}`, do not start with a dot).
    // Before, a method with `throws CertificateException` (an `.annotation system Ldalvik/annotation/Throws;` block, which is
    // nearly EVERY empty checkServerTrusted) was never matched.
    internal const val METHOD_PREAMBLE =
        "(?:\\s*\\.annotation[^\\n]*\\n(?:(?!\\s*\\.end annotation)[^\\n]*\\n)*\\s*\\.end annotation[^\\n]*\\n" +
        "|\\s*\\.(?!annotation\\b)[a-z][a-z-]*[^\\n]*\\n)*"

    enum class Severity(val label: String, val rank: Int) {
        CRITICAL("CRITICAL", 0), HIGH("HIGH", 1), MEDIUM("MEDIUM", 2), LOW("LOW", 3), INFO("INFO", 4)
    }

    /** Where the class lives: the app's own package, a known third-party library, obfuscated (short names), or other. */
    enum class Scope(val tag: String) { APP("APP"), LIB("LIB"), OBF("OBF"), OTHER("") }

    class Finding(
        var severity: Severity,
        val title: String,
        var detail: String,            // 0.48.4: var, dedupe() appends "Also matched by"
        val recommendation: String,
        val classType: String? = null, // smali type (e.g. "Lcom/x/Y;") for code findings, null for manifest findings
        val clsIndex: Int = -1,        // index into MainActivity.classDefs, -1 for manifest findings
        val at: Int = -1,              // char offset to jump to inside the disassembled class
        val cwe: String = "",          // e.g. "CWE-327"
        val file: String = ""          // 0.33.0: resource path for findings from res/ XML (shown as the location)
    ) {
        var ruleId: String = ""        // 0.41.0: id of the ScanRule / ManifestRule that produced it ("" = resource findings)
        var confidence: String = ""    // 0.41.0: HIGH / MEDIUM / LOW set by the rule ("" = FindingPolish decides from the title)
        var adjusted: String = ""      // 0.40.0: why FindingPolish lowered the severity ("" = untouched)
        var count: Int = 1             // identical findings merged into this one (same title, same class)
        var scope: Scope = Scope.OTHER
        var verdict: String = ""       // AI triage: "" = not triaged, "TP", "FP", "REVIEW"
        var verdictNote: String = ""
        var reach: String = ""         // 0.23.0 call graph: "" = not traced, "YES" = reachable from an exported component, "YES~" = approximate class-level path, "NO" = no path found
        var chain: String = ""         // "Entry: ...\nPath: a -> b -> c" when reach == "YES"
        var sourceMethod: String = ""  // 0.82.0: SSA flows: key of the method where the untrusted value is held first ("" = the sink method)
        var dataPath: String = ""      // 0.82.0: SSA flows: "source -> ... -> sink" as short names (what the AI triage is shown)
        val location: String
            get() = if (file.isNotEmpty()) file else classType?.removePrefix("L")?.removeSuffix(";")?.replace('/', '.') ?: "AndroidManifest.xml"
    }

    // ---------- scope (app / library / obfuscated) ----------

    private val libPrefixes = listOf(
        "androidx/", "android/", "kotlin/", "kotlinx/", "java/", "javax/", "dalvik/", "j$/",
        "com/google/", "com/android/", "com/squareup/", "okhttp3/", "okio/", "retrofit2/",
        "org/apache/", "org/jetbrains/", "org/intellij/", "org/bouncycastle/", "org/conscrypt/",
        "org/json/", "org/slf4j/", "org/w3c/", "org/xmlpull/", "org/threeten/", "org/greenrobot/",
        "com/facebook/", "com/fasterxml/", "com/bumptech/", "com/airbnb/", "com/jakewharton/",
        "com/github/", "com/crashlytics/", "com/appsflyer/", "com/adjust/", "com/onesignal/",
        "com/amplitude/", "com/mixpanel/", "com/unity3d/", "com/applovin/", "com/ironsource/",
        "com/vungle/", "com/mbridge/", "com/chartboost/", "com/bytedance/", "com/huawei/",
        "com/amazonaws/", "com/microsoft/", "com/twitter/", "com/stripe/", "com/paypal/",
        "io/reactivex/", "io/grpc/", "io/sentry/", "io/branch/", "io/netty/", "io/flutter/",
        "dagger/", "coil/", "timber/", "retrofit/", "com/sun/", "sun/",
        // 0.22.1: common third-party SDKs (chat/support/analytics/maps)
        "com/livechatinc/", "com/zendesk/", "com/intercom/", "io/intercom/", "com/sendbird/", "com/freshchat/",
        "com/clevertap/", "com/segment/", "com/instabug/", "com/pusher/", "io/socket/", "org/chromium/",
        "com/mapbox/", "com/yandex/", "com/tencent/", "com/alibaba/", "com/baidu/", "com/braintreepayments/",
        "com/datadog/", "com/newrelic/", "io/realm/", "com/arthenica/", "com/pubnub/", "org/webrtc/",
        // 0.49.1: libraries seen leaking into reports of real apps (Aegis, Wikipedia, NewPipe, Fossify)
        "com/topjohnwu/", "com/nulabinc/", "org/joda/", "org/acra/", "org/mozilla/javascript/", "org/maplibre/", "coil3/",
        "com/hcaptcha/", "org/lsposed/", "com/canhub/", "org/jsoup/", "com/nononsenseapps/", "com/journeyapps/",
        "com/caverock/", "com/davemorrissey/", "me/zhanghai/", "org/commonmark/", "org/kodein/", "io/noties/",
        "com/mikepenz/", "com/google/zxing/", "net/lingala/", "com/nostra13/", "com/squareup/picasso/",
        "org/brotli/", "org/tukaani/",
        // 0.61.0: SDKs that leaked into the JustMarkets report as unclassified code (crypto forks, KYC / ID-document, device-id, realtime)
        "org/spongycastle/", "org/ejbca/", "org/jmrtd/", "net/sf/scuba/", "com/sumsub/", "com/onfido/", "com/fingerprintjs/",
        "io/ably/", "com/microblink/", "com/jumio/", "com/veriff/", "com/incode/", "com/idnow/", "com/gemalto/", "org/spongycastle/",
        // 0.76.0: real-app held-out run (Password Store, Unstoppable): git / ssh / OpenPGP and blockchain SDKs reported as app code
        "org/eclipse/jgit/", "com/jcraft/jsch/", "net/schmizz/", "com/hierynomus/", "org/pgpainless/", "org/openintents/openpgp/",
        "net/i2p/crypto/eddsa/", "com/solana/", "org/sol4k/", "org/tron/", "org/stellar/", "org/web3j/", "org/bitcoinj/",
        "wallet/core/", "org/ton/", "io/github/novacrypto/",
        "com/tonyodev/fetch2"   // 0.79.0: Fetch2 download library (Kiwix), reported as app code
    )

    /**
     * 0.49.1: library code that lives INSIDE the app's own package (checked before the app-package test, otherwise it is
     * reported as app code). Typical: a project's extractor/commons module published under the same group id.
     */
    private val libOverrides = listOf(
        "org/schabi/newpipe/extractor/", "org/fossify/commons/", "com/simplemobiletools/commons/"
    )

    /**
     * 0.22.1: package prefix of the app's OWN code. After a package rename (or with a different applicationId vs namespace)
     * the manifest package no longer matches the code, so the most common non-library, non-obfuscated 2-segment prefix is used.
     */
    fun codePackage(types: List<String>, manifestPkg: String): String {
        val counts = HashMap<String, Int>()
        for (t in types) {
            if (scopeOf(t, "") != Scope.OTHER) continue
            val segs = t.removePrefix("L").split('/')
            if (segs.size < 3) continue
            val key = segs[0] + "." + segs[1]
            counts[key] = (counts[key] ?: 0) + 1
        }
        val msegs = manifestPkg.split('.')
        val mkey = if (msegs.size >= 2) msegs[0] + "." + msegs[1] else manifestPkg
        val mine = counts[mkey] ?: 0
        val best = counts.maxByOrNull { it.value }
        return if (best != null && best.value >= 30 && mine < best.value / 4) best.key else manifestPkg
    }

    /**
     * 0.82.0 (JustMarkets: R8 renamed the app's own classes, e.g. `mu.h` = DefaultPreference.kt with 163 references to com/justmarkets,
     * and the "obfuscated = likely third-party" lowering fired on them): an obfuscated class whose text references the app's own package
     * at least [minRefs] times is the APP's code, not a library. Libraries renamed by R8 reference the app package 0-1 times (measured on
     * JustMarkets: 1,105 of 18,766 renamed classes reference it; the library ones that do have 1).
     */
    // a string that names a library's own package / product: R8 merges unrelated lambdas of an SDK and of the app into one class
    // (Ivy `I4/n` = Firebase Crashlytics code + Room entities of com.ivy); such a mixed class is not attributed to the app
    private val libIdentityRe = rx("const-string(?:/jumbo)? [vp]\\d+, \"[^\"]*(?:com\\.google\\.firebase|com\\.google\\.android\\.gms|com\\.facebook\\.|io\\.sentry|com\\.airbnb\\.lottie|io\\.intercom\\.|com\\.microsoft\\.clarity|FirebaseCrashlytics|Crashlytics|com\\.onesignal|com\\.appsflyer|com\\.adjust\\.sdk)")

    fun isAppBoundObf(text: String, appPkg: String, minRefs: Int = 3): Boolean {
        if (appPkg.isEmpty()) return false
        if (libIdentityRe.containsMatchIn(text)) return false
        val segs = appPkg.split('.')
        val pref = "L" + (if (segs.size >= 2) segs.take(2) else segs).joinToString("/") + "/"
        var n = 0
        var i = text.indexOf(pref)
        while (i >= 0) {
            if (++n >= minRefs) return true
            i = text.indexOf(pref, i + pref.length)
        }
        return false
    }

    /**
     * 0.82.0 (AI triage): the smali text of one method, found by its key `Lcom/x/Y;->name(desc)ret` (the class part is ignored, [text] is the
     * class). Cut to [max] characters at a line end; "" when the method is not in [text]. A taint finding is judged by the AI from the SINK
     * method only, so the method where the untrusted value is read (and the path to the sink) was invisible to it.
     */
    fun methodExcerpt(text: String, methodKey: String, max: Int = 1800): String {
        val nameDesc = methodKey.substringAfter("->", "")
        if (nameDesc.isEmpty()) return ""
        val head = Regex("(?m)^\\.method [^\\n]*\\s" + Regex.escape(nameDesc) + "\\s*$").find(text) ?: return ""
        val end = text.indexOf("\n.end method", head.range.first)
        var body = text.substring(head.range.first, if (end < 0) text.length else end + 12)
        if (body.length > max) {
            val cut = body.lastIndexOf('\n', max)
            body = body.substring(0, if (cut > 0) cut else max) + "\n    # ... (method continues)"
        }
        return body
    }

    fun scopeOf(classType: String, appPkg: String): Scope {
        val p = classType.removePrefix("L")
        if (libOverrides.any { p.startsWith(it) }) return Scope.LIB
        if (appPkg.isNotEmpty()) {
            val segs = appPkg.split('.')
            val pref = (if (segs.size >= 2) segs.take(2) else segs).joinToString("/") + "/"
            if (p.startsWith(pref)) return Scope.APP
        }
        if (libPrefixes.any { p.startsWith(it) }) return Scope.LIB
        val first = p.substringBefore('/')
        return if (!p.contains('/') || first.length <= 2) Scope.OBF else Scope.OTHER
    }

    // ---------- manifest-level checks ----------


    fun scanManifest(xml: String): List<Finding> {
        // 0.42.0: clean orchestrator, like scanSmali. Every manifest check is a ManifestRule (ScanRulesManifest.kt);
        // RuleRegistry.runManifest runs them in registration order and skips a rule that throws (one bad rule never costs the whole manifest).
        val out = RuleRegistry.runManifest(ManifestContext(xml))
        return FindingPolish.applyManifest(out)   // confidence only: the manifest is the whole app, so no test-class / library lowering
    }

    // ---------- smali helpers ----------

    internal fun lineNo(text: String, offset: Int): Int {
        var n = 1
        val end = minOf(offset, text.length)
        for (i in 0 until end) if (text[i] == '\n') n++
        return n
    }

    private fun lineStartOf(text: String, offset: Int): Int = text.lastIndexOf('\n', offset - 1) + 1
    private fun lineEndOf(text: String, ls: Int): Int = text.indexOf('\n', ls).let { if (it < 0) text.length else it }
    private fun prevLineStart(text: String, ls: Int): Int = if (ls <= 0) -1 else text.lastIndexOf('\n', ls - 2) + 1

    private fun invokeRegs(line: String): List<String>? {
        val m = rx("\\{([^}]*)\\}").find(line) ?: return null
        val s = m.groupValues[1]
        if (s.contains("..")) return null
        return s.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }

    private fun opSourceFirst(op: String): Boolean =
        op.startsWith("invoke") || op.startsWith("iput") || op.startsWith("sput") || op.startsWith("aput") ||
            op.startsWith("if-") || op.startsWith("return") || op == "throw" || op.startsWith("monitor") ||
            op.startsWith("fill-array") || op.endsWith("-switch")

    /** The instruction (and its line start) that last defined [reg] before the line starting at [useLineStart], same method, <= 14 lines back. */
    private fun defOf(text: String, useLineStart: Int, reg: String): Pair<String, Int>? {
        var pos = useLineStart
        var steps = 0
        while (steps < 14) {
            val p = prevLineStart(text, pos)
            if (p < 0) return null
            pos = p
            steps++
            val l = text.substring(p, lineEndOf(text, p)).trim()
            if (l.isEmpty() || l.startsWith(".line") || l.startsWith(":") || l.startsWith("#")) continue
            if (l.startsWith(".method")) return null
            if (l.startsWith(".")) continue
            val parts = l.split(rx("\\s+"), limit = 3)
            if (parts.size >= 2 && !opSourceFirst(parts[0]) && parts[1].removeSuffix(",") == reg) return l to p
        }
        return null
    }

    private fun regAt(text: String, invokeAt: Int, idx: Int, fromEnd: Boolean): Pair<Int, String>? {
        val ls = lineStartOf(text, invokeAt)
        val line = text.substring(ls, lineEndOf(text, ls)).trim()
        val regs = invokeRegs(line) ?: return null
        val reg = (if (fromEnd) regs.getOrNull(regs.size - 1 - idx) else regs.getOrNull(idx)) ?: return null
        return ls to reg
    }

    private val constNumRe = rx("^const(?:/4|/16|/high16)?\\s+\\S+,\\s*(-?0x[0-9a-fA-F]+)")
    private val constStrRe = rx("^const-string(?:/jumbo)?\\s+\\S+,\\s*\"(.*)\"$")

    /** Numeric constant passed as argument [idx] (counted from the start, or from the end) of the invoke at [invokeAt]; null if not a plain const. */
    internal fun argNumber(text: String, invokeAt: Int, idx: Int, fromEnd: Boolean = false): Long? {
        val (ls, reg) = regAt(text, invokeAt, idx, fromEnd) ?: return null
        val def = defOf(text, ls, reg)?.first ?: return null
        val m = constNumRe.find(def) ?: return null
        return try { java.lang.Long.decode(m.groupValues[1]) } catch (_: Throwable) { null }
    }

    internal fun argString(text: String, invokeAt: Int, idx: Int): String? {
        val (ls, reg) = regAt(text, invokeAt, idx, false) ?: return null
        val def = defOf(text, ls, reg)?.first ?: return null
        return constStrRe.find(def)?.groupValues?.get(1)
    }

    /** For `new XxxSpec("literal".getBytes())`: the string literal behind the byte[] argument [idx] of the <init> at [initAt]. */
    /**
     * 0.49.3: the receiver of getBytes() was read from a String field of THIS class (iget-object / sget-object). Returns the literal that
     * the class assigns to that field: a static-final initial value (.field ... = "x") or a const-string stored with iput/sput-object.
     * Same class only; a field set from several places or from non-literals returns null (nothing is guessed).
     */
    private fun fieldLiteral(text: String, def: String): String? {
        val m = rx("^[is]get-object\\s+[vp]\\d+,\\s*(?:[vp]\\d+,\\s*)?(L[^;]+;)->([A-Za-z0-9_$]+):Ljava/lang/String;").find(def.trim()) ?: return null
        val owner = m.groupValues[1]
        val name = m.groupValues[2]
        val header = text.lineSequence().firstOrNull { it.startsWith(".class") } ?: return null
        if (!header.trim().endsWith(owner)) return null
        val q = Regex.escape(name)
        rx("^\\.field [^\\n]*\\b" + q + ":Ljava/lang/String; = \"([^\"]*)\"", RegexOption.MULTILINE).find(text)?.let { return it.groupValues[1] }
        val hits = rx("const-string(?:/jumbo)?\\s+([vp]\\d+),\\s*\"([^\"]*)\"\\s*\\n(?:\\s*\\.[a-z][^\\n]*\\n)*\\s*[is]put-object\\s+\\1,\\s*(?:[vp]\\d+,\\s*)?" +
            Regex.escape(owner) + "->" + q + ":Ljava/lang/String;").findAll(text).map { it.groupValues[2] }.distinct().toList()
        return if (hits.size == 1) hits[0] else null
    }

    internal fun literalBytesArg(text: String, initAt: Int, idx: Int): String? {
        val (ls, reg) = regAt(text, initAt, idx, false) ?: return null
        val (def, defStart) = defOf(text, ls, reg) ?: return null
        if (!def.startsWith("move-result")) return null
        var p = prevLineStart(text, defStart)
        var guard = 0
        while (p >= 0 && guard++ < 4) {
            val l = text.substring(p, lineEndOf(text, p)).trim()
            if (l.startsWith("invoke")) {
                if (!l.contains("Ljava/lang/String;->getBytes(")) return null
                val r = invokeRegs(l)?.getOrNull(0) ?: return null
                val d2 = defOf(text, p, r)?.first ?: return null
                constStrRe.find(d2)?.groupValues?.get(1)?.let { return it }
                return fieldLiteral(text, d2)
            }
            if (l.isEmpty() || l.startsWith(".") || l.startsWith(":") || l.startsWith("#")) { p = prevLineStart(text, p); continue }
            return null
        }
        return null
    }

    /**
     * 0.74.0: a constant byte[] passed as argument [idx] of the invoke at [initAt]: `new-array vN, vL, [B` + `fill-array-data vN, :array_k`
     * (what the compiler emits for `new byte[]{1,2,3,...}` / `byteArrayOf(...)` with 4+ elements; the data sits in an `.array-data 1` block
     * at the end of the method). The first held-out run missed PIVAA's static IV and hardcoded key because only `"x".getBytes()` was read.
     * Walks back at most 30 lines in the same method and only follows plain `move-object`; if the register is touched by anything else
     * on the way (an aput, an invoke that gets the array, another definition) it returns null, so a later `nextBytes(iv)` is never called constant.
     */
    internal fun constByteArrayArg(text: String, initAt: Int, idx: Int): ByteArray? {
        var (pos, reg) = regAt(text, initAt, idx, false) ?: return null
        var steps = 0
        while (steps < 30) {
            val p = prevLineStart(text, pos)
            if (p < 0) return null
            pos = p
            steps++
            val l = text.substring(p, lineEndOf(text, p)).trim()
            if (l.isEmpty() || l.startsWith(".line") || l.startsWith(".local") || l.startsWith(".end local") || l.startsWith(".restart local") ||
                l.startsWith(".prologue") || l.startsWith(":") || l.startsWith("#") || l == "nop") continue
            if (l.startsWith(".method")) return null
            if (l.startsWith(".")) continue
            val parts = l.split(rx("\\s+"), limit = 3)
            val op = parts[0]
            if (op == "fill-array-data") {
                if (parts.size < 3 || parts[1].removeSuffix(",") != reg) continue
                val label = parts[2].trim()
                val blk = rx("^\\s*" + Regex.escape(label) + "\\s*\\n\\s*\\.array-data\\s+(\\d+)\\s*\\n(.*?)\\.end array-data", RegexOption.MULTILINE, RegexOption.DOT_MATCHES_ALL)
                    .find(text) ?: return null
                if (blk.groupValues[1] != "1") return null
                val nums = rx("(-?0x[0-9a-fA-F]+)t?").findAll(blk.groupValues[2]).map { it.groupValues[1] }.toList()
                if (nums.isEmpty() || nums.size > 4096) return null
                return try { ByteArray(nums.size) { java.lang.Long.decode(nums[it]).toByte() } } catch (_: Throwable) { null }
            }
            if (op.startsWith("move-object") && parts.size >= 3 && parts[1].removeSuffix(",") == reg) {
                reg = parts[2].trim(); continue
            }
            if (op.startsWith("invoke") || op.startsWith("aput")) {
                val used = invokeRegs(l)
                val mentioned = used?.contains(reg) ?: rx("\\b" + Regex.escape(reg) + "\\b").containsMatchIn(l)
                if (mentioned) return null      // the array may be filled / changed here
                continue
            }
            if (parts.size >= 2 && !opSourceFirst(op) && parts[1].removeSuffix(",") == reg) return null   // redefined (new-array alone = zeros, not judged here)
        }
        return null
    }

    /** (start,end) of the method containing [at]; for non-method positions (fields) a +-400 char window. */
    internal fun methodBounds(text: String, at: Int): Pair<Int, Int> {
        val m = text.lastIndexOf("\n.method", at)
        val e = text.lastIndexOf("\n.end method", at)
        return if (m >= 0 && m > e) {
            val en = text.indexOf("\n.end method", at)
            m to (if (en < 0) text.length else en)
        } else maxOf(0, at - 400) to minOf(text.length, at + 400)
    }

    /** The enclosing method (capped around [at]) with the class header - what the AI triage sees. */
    fun excerpt(text: String, at: Int, maxChars: Int = 3500): String {
        val header = text.lineSequence().firstOrNull { it.startsWith(".class") } ?: ""
        val (s, e) = methodBounds(text, if (at < 0) 0 else at)
        var body = text.substring(s, e).trim('\n')
        if (body.length > maxChars) {
            val rel = (if (at < 0) 0 else at) - s
            val st = maxOf(0, minOf(rel - maxChars / 2, body.length - maxChars))
            body = body.substring(st, st + maxChars)
        }
        return header + "\n# ...\n" + body
    }

    // identifier words: "getApiKey" / "API_KEY" -> [get, api, key]
    private fun words(s: String): List<String> =
        s.replace(rx("([a-z0-9])([A-Z])"), "\$1 \$2").split(rx("[^A-Za-z0-9]+")).filter { it.isNotEmpty() }.map { it.lowercase() }

    internal val secretWords = setOf(
        "secret", "token", "password", "passwd", "pwd", "credential", "credentials", "apikey", "privatekey",
        "secretkey", "accesskey", "clientsecret", "bearer"
    )
    internal val randomWords = setOf(
        "token", "session", "sessionid", "nonce", "otp", "salt", "secret", "password", "passwd", "csrf",
        "apikey", "privatekey", "secretkey", "accesskey"
    )

    internal fun identHas(s: String, set: Set<String>): Boolean {
        val w = words(s)
        if (w.any { it in set }) return true
        for (i in 0 until w.size - 1) if ((w[i] + w[i + 1]) in set) return true
        return false
    }

    private val memberNameRe = rx("->([\\w\$<>]+)")
    private val fieldDeclRe = rx("\\.field[^\\n]*?\\s([\\w\$]+):")
    private val methodNameRe = rx("\\.method[^\\n]*?\\s([\\w\$<>]+)\\(")
    private val quotedRe = rx("\"([^\"\\n]{1,40})\"")

    /**
     * True if, in the same method and within ~300 chars of [litStart, litEnd), there is an identifier
     * (member name after '->', field name, enclosing method name) or a short string literal whose WORDS
     * are in [set]. Type descriptors (Lcom/foo/auth/Token;) are deliberately NOT searched - that substring
     * match was what flooded real obfuscated APKs with false HIGH findings.
     */
    internal fun contextHas(text: String, litStart: Int, litEnd: Int, set: Set<String>): Boolean {
        val (s, e) = methodBounds(text, litStart)
        val from = maxOf(s, litStart - 300)
        val to = minOf(e, litEnd + 300)
        val parts = listOf(text.substring(from, litStart), text.substring(litEnd, maxOf(litEnd, to)))
        for (part in parts) {
            for (m in memberNameRe.findAll(part)) if (identHas(m.groupValues[1], set)) return true
            for (m in fieldDeclRe.findAll(part)) if (identHas(m.groupValues[1], set)) return true
            for (m in quotedRe.findAll(part)) { val q = m.groupValues[1]; if (!q.contains(' ') && identHas(q, set)) return true }
        }
        val head = text.substring(s, minOf(text.length, s + 400))
        methodNameRe.find(head)?.let { if (identHas(it.groupValues[1], set)) return true }
        return false
    }

    // ---------- per-class smali checks ----------

    fun scanSmali(classType: String, clsIndex: Int, text: String, appPkg: String = ""): List<Finding> {
        // 0.41.0: clean orchestrator. Every check is a ScanRule (ScanRulesLegacy.kt = the former inline checks, ScanRules.kt = framework + newer rules);
        // RuleRegistry runs them in registration order and skips a rule that throws (one bad rule never costs the whole class).
        val out = RuleRegistry.runAll(RuleContext(classType, clsIndex, text, appPkg))


        // merge repeated findings of the same title in this class
        val merged = LinkedHashMap<String, Finding>()
        for (f in out) {
            val prev = merged[f.title]
            if (prev == null) merged[f.title] = f else prev.count += f.count
        }
        val scope = scopeOf(classType, appPkg)
        val res = merged.values.toList()
        res.forEach { it.scope = scope }
        return FindingPolish.apply(res, classType,
            scopeOf(classType, appPkg) == Scope.OBF && isAppBoundObf(text, appPkg))   // 0.82.0: renamed app code is not "likely third-party"; 0.40.0: lowers test-class / heuristic-in-library findings, keeps the reason
    }

    // ---------- 0.46.0: findings aggregation (noise reduction) ----------

    /**
     * Merges repeated findings so one card stands for many hits:
     *  - same rule in the SAME class (e.g. repeated high-entropy strings): merged into the first finding, `count` grows (xN);
     *  - INFO-level findings with the same rule ACROSS classes (e.g. 300 classes with "root detection logic"): collapsed into
     *    ONE card whose location is the first hit; the count tells how widespread it is.
     * Nothing is deleted: the count carries the repetitions, and non-INFO findings keep their per-class identity (a real
     * HIGH in two different classes stays two cards). Applied once per scan, after all workers finish.
     */
    fun aggregate(list: List<Finding>): List<Finding> {
        val merged = LinkedHashMap<String, Finding>()
        for (f in list) {
            val rule = if (f.ruleId.isNotEmpty()) f.ruleId else f.title
            val scope = if (f.severity == Severity.INFO) "*" else f.clsIndex.toString() + "|" + f.file
            val key = rule + "|" + f.title + "|" + scope
            val prev = merged[key]
            if (prev == null) merged[key] = f else prev.count += f.count
        }
        return dedupe(merged.values.toList())
    }

    /** 0.48.4: one rule that makes the other rules' report of the SAME issue in the SAME class redundant. */
    private class Absorb(val primary: (Finding) -> Boolean, val absorbed: (Finding) -> Boolean, val sameTitle: Boolean = false)

    private val absorbRules = listOf(
        // ContentProvider.openFile path traversal: the specific rule wins over the taint chain and the generic check.
        Absorb({ it.ruleId == "provider-openfile-segment" },
            { (it.ruleId == "taint-flow" && it.cwe == "CWE-22") ||
                (it.ruleId == "androgoat-checks" && it.title.startsWith("ContentProvider.openFile")) }),
        // generic dynamic-code-loading is implied by the specific code-loading rules.
        Absorb({ it.ruleId == "package-context-code" || it.ruleId == "dex-load-writable-dir" },
            { it.ruleId == "dynamic-code-loading" }),
        // a proven Intent -> WebView.loadUrl chain makes the shallow "URL from an Intent" check redundant.
        Absorb({ it.ruleId == "taint-flow" && it.title.contains("WebView") },
            { it.ruleId == "webview-intent-url" }),
        // 0.49.0: the same sink reported by the in-class taint rule and by the cross-class one: keep the in-class finding.
        Absorb({ it.ruleId == "taint-flow" }, { it.ruleId == "taint-xclass" }, true),
        // 0.75.2 (Allsafe ProxyActivity reported twice): the SSA-proven redirection absorbs the text heuristic of the same class.
        Absorb({ it.ruleId == "taint-flow" && it.title.contains("intent redirection") }, { it.ruleId == "intent-redirection" }),
        // 0.75.2 (Allsafe / Sieve): the SSA SQLite rule absorbs the older AndroGoat text check of the same class.
        Absorb({ it.ruleId == "sqlite-unencrypted" }, { it.ruleId == "androgoat-checks" && it.title.startsWith("Sensitive value written to SQLite") }),
        // 0.80.0 (Infinity: WebViewActivity and the delete receiver were each reported twice): the SSA flow absorbs the in-class taint finding
        // of the same class and title (the SSA one carries the chain and the reach / internal judgement)
        Absorb({ it.ruleId == "taint-flow" && it.detail.contains("SSA data-flow engine") },
            { it.ruleId == "taint-flow" && !it.detail.contains("SSA data-flow engine") }, true)
    )

    /**
     * Merges overlapping findings of one class (see [absorbRules]): the absorbed finding is removed, the primary keeps
     * the higher severity and names the other rule in its text. Findings of different classes and INFO are untouched.
     */
    fun dedupe(list: List<Finding>): List<Finding> {
        val drop = HashSet<Finding>()
        val byClass = list.filter { it.clsIndex >= 0 && it.severity != Severity.INFO }.groupBy { it.clsIndex }
        for ((_, group) in byClass) {
            if (group.size < 2) continue
            for (r in absorbRules) {
                for (g in group) {
                    if (g in drop || !r.absorbed(g)) continue
                    val primary = group.firstOrNull { it !== g && it !in drop && r.primary(it) && (!r.sameTitle || it.title == g.title) } ?: continue
                    if (g.severity.rank < primary.severity.rank) primary.severity = g.severity
                    primary.detail = primary.detail + "  Also matched by: " + (if (g.ruleId.isNotEmpty()) g.ruleId else g.title) + " (merged)."
                    drop.add(g)
                }
            }
        }
        return if (drop.isEmpty()) list else list.filter { it !in drop }
    }

    // ---------- generic embedded-secret detection by entropy ----------

    private val urlLiteralRe = rx("^[a-zA-Z]+://")
    private val packageLikeRe = rx("^[A-Za-z0-9_$]+(\\.[A-Za-z0-9_$]+){2,}$")
    // 0.22.1: Kotlin data-class toString fragments such as "UpdatePassword(password=" are not secrets
    private val toStringFragRe = rx("[A-Za-z0-9_$]\\([A-Za-z0-9_$]*=")
    // 0.61.0: strings that are NAMES, not secrets (JustMarkets report: 11 false HIGH in SpongyCastle / Onfido / Sumsub / Ably:
    // "$PBE...", "Alg.Alias...", "getA...", "KeyG...", "sns_...", "Auth...").
    private val jcaNameRe = rx("^(Alg\\.|Cipher\\.|KeyGenerator|KeyFactory|KeyPairGenerator|Mac\\.|MessageDigest|Signature\\.|SecretKeyFactory|AlgorithmParameter|PBEWith|PBE[A-Z]|\\$[A-Z])")
    private val snakeNameRe = rx("^[a-z][a-z0-9]*(_[a-z0-9]+){2,}$")
    private val camelNameRe = rx("^[a-z]{2,}([A-Z][a-z]{2,}){2,}$")
    private val dottedNameRe = rx("^[A-Za-z][A-Za-z0-9_$]*(\\.[A-Za-z][A-Za-z0-9_$]*)+$")
    private val getterNameRe = rx("^(get|set|is|has|create|on)[A-Z][A-Za-z0-9]+$")

    // 0.66.4: Cipher transformations ("RSA/ECB/PKCS1Padding", 20 chars with mixed case + digits) and signature names
    // ("SHA256withRSA") passed the old filter (Exness: Salesforce Encryptor flagged HIGH).
    private val jcaTransformRe = rx("^(AES|RSA|DES|DESEDE|TRIPLEDES|BLOWFISH|CHACHA20|RC4|ARCFOUR|EC|ECIES|SM2)(/[A-Za-z0-9-]+){1,2}$", RegexOption.IGNORE_CASE)
    private val sigNameRe = rx("^[A-Za-z0-9-]+with[A-Za-z0-9-]+$", RegexOption.IGNORE_CASE)

    // 0.76.0 (real-app held-out run): PUBLIC values that the secret detectors called secrets
    // "getApplicationContext(...)": the message Kotlin's null check builds from an expression
    private val kotlinNullMsgRe = rx("^[A-Za-z_][A-Za-z0-9_.]*\\(\\.\\.\\.\\)$")
    // "safeTransferFrom(address,address,uint256,bytes)": a Solidity / ABI function signature (or any name(args) descriptor)
    private val callSigRe = rx("^[A-Za-z_][A-Za-z0-9_]*\\([A-Za-z0-9_\\[\\], ]*\\)$")
    // a 32-44 char base58 string = a public key / address / program id (Solana, Bitcoin, Tron ...); private keys are longer
    // (Solana secret keys 87-88, Bitcoin WIF 51-52) and are still checked
    private val base58AddrRe = rx("^[1-9A-HJ-NP-Za-km-z]{32,44}$")

    /** "index_TokenTransfer_transactionHash", "averagePrice7d_tokenQueryId", "sellTokenQuantityRemain_": an identifier made of words. */
    internal fun identifierLike(s: String): Boolean {
        if (!rx("^[A-Za-z][A-Za-z0-9_]*$").matches(s)) return false
        val parts = s.split('_').flatMap { it.split(rx("(?<=[a-z0-9])(?=[A-Z])")) }.filter { it.isNotEmpty() }
        if (parts.size < 3) return false
        var letters = 0; var vowels = 0; var short = 0
        val wordRe = rx("^[A-Za-z]+[0-9]{0,2}[a-z]?$")          // a word, optionally with a small number suffix ("Price7d", "v2")
        for (p in parts) {
            if (p.length < 2 || p.length > 14 || !wordRe.matches(p)) return false
            if (p.length == 2) short++
            for (c in p.lowercase()) if (c.isLetter()) { letters++; if (c in "aeiouy") vowels++ }
        }
        // random keys split into many 2-letter chunks ("Qw", "Er", "Pa"...): real identifiers are mostly longer words
        return letters > 0 && vowels * 100 / letters >= 25 && short * 3 <= parts.size && letters >= parts.size * 3
    }

    // 0.80.0 (Read You INJECTION_TOKEN = "/android_asset_font/"): a lower-case path made of words, with at least one slash
    private val pathLikeRe = rx("^/?[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+/?$|^/[a-z0-9_.-]+/$")

    // 0.82.0 (JustMarkets mu.h: "getAccessToken()Ljava/lang/String;" = Kotlin property-reference metadata): a JVM method descriptor
    private val jvmDescRe = rx("^[A-Za-z_$][A-Za-z0-9_$]*\\((?:\\[*(?:[BCDFIJSZ]|L[A-Za-z0-9_/$]+;))*\\)\\[*(?:[BCDFIJSZV]|L[A-Za-z0-9_/$]+;)$")

    internal fun looksLikeName(s: String): Boolean {
        if (jvmDescRe.matches(s)) return true
        if (pathLikeRe.matches(s) && s.count { it.isLetter() } * 2 >= s.length) return true
        if (kotlinNullMsgRe.matches(s) || callSigRe.matches(s) || base58AddrRe.matches(s) || identifierLike(s)) return true
        if (jcaTransformRe.matches(s) || sigNameRe.matches(s)) return true
        if (jcaNameRe.containsMatchIn(s)) return true
        if (snakeNameRe.matches(s)) return true
        if (camelNameRe.matches(s)) return true
        if (getterNameRe.matches(s)) return true
        if (!s.startsWith("eyJ") && dottedNameRe.matches(s) && s.count { it in '0'..'9' } <= 2) return true
        return false
    }

    private const val MAX_ENTROPY_FINDINGS_PER_CLASS = 3

    internal fun charClasses(s: String): Int {
        var lo = false; var up = false; var dg = false; var ot = false
        for (c in s) when {
            c in 'a'..'z' -> lo = true
            c in 'A'..'Z' -> up = true
            c in '0'..'9' -> dg = true
            else -> ot = true
        }
        return (if (lo) 1 else 0) + (if (up) 1 else 0) + (if (dg) 1 else 0) + (if (ot) 1 else 0)
    }

    private fun shannonEntropy(s: String): Double {
        if (s.isEmpty()) return 0.0
        val freq = HashMap<Char, Int>()
        for (c in s) freq[c] = (freq[c] ?: 0) + 1
        val n = s.length.toDouble()
        var h = 0.0
        for (count in freq.values) {
            val p = count / n
            h -= p * log2(p)
        }
        return h
    }

    /**
     * HIGH only when the literal itself looks like a secret (>= 3 character classes, entropy >= 3.8)
     * AND an identifier/short literal with credential words (word-split, not substring) sits in the same
     * method next to it. Everything else is merged into ONE low-confidence INFO per class.
     */
    internal fun scanHighEntropyStrings(classType: String, clsIndex: Int, text: String): List<Finding> {
        val out = ArrayList<Finding>()
        val seen = HashSet<String>()
        var infoCount = 0
        var infoFirst: Int = -1
        var infoSample = ""
        var infoEntropy = 0.0
        for (m in rx("const-string[^,]*,\\s*\"([^\"\\n]{20,200})\"").findAll(text)) {
            val s = m.groupValues[1]
            if (!seen.add(s)) continue
            if (s.contains(' ') || s.contains('%') || s.contains('{') || s.contains('<') || s.contains('\\')) continue
            if (urlLiteralRe.containsMatchIn(s)) continue
            if (packageLikeRe.matches(s)) continue
            if (toStringFragRe.containsMatchIn(s)) continue
            if (looksLikeName(s)) continue
            if (s.count { it == '/' } > 2) continue
            if (s.startsWith("L") && s.endsWith(";")) continue
            val entropy = shannonEntropy(s)
            if (entropy < 3.8 || s.toSet().size < 10) continue
            if (charClasses(s) < 3) continue
            val keyish = contextHas(text, m.range.first, m.range.last + 1, secretWords)
            if (keyish) {
                if (out.size >= MAX_ENTROPY_FINDINGS_PER_CLASS) continue
                out.add(Finding(Severity.HIGH, "High-entropy embedded string near a credential-like name",
                    "A ${s.length}-char string with high character randomness (entropy ${"%.1f".format(entropy)} bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: \"${s.take(4)}…\".  (around line ${lineNo(text, m.range.first)})",
                    "Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.",
                    classType, clsIndex, m.range.first, "CWE-798"))
            } else {
                infoCount++
                if (infoFirst < 0) { infoFirst = m.range.first; infoSample = s; infoEntropy = entropy }
            }
        }
        if (infoCount > 0) {
            out.add(Finding(Severity.INFO, "High-entropy embedded string(s)",
                "$infoCount string(s) in this class look random (mixed case/digits, e.g. entropy ${"%.1f".format(infoEntropy)} bits/char: \"${infoSample.take(4)}…\") but no credential-like name is nearby. Usually encoded assets, hashes, IDs or obfuscated strings; low confidence.  (around line ${lineNo(text, infoFirst)})",
                "Only look at these if the class is app code that handles keys/tokens.",
                classType, clsIndex, infoFirst, "CWE-798").also { it.count = infoCount })
        }
        return out
    }

    // ---------- 0.23.0: lightweight call graph (reverse index) + path tracing to exported components ----------

    /** Reverse call index: for every invoke edge, hash("Lcls;->name(desc)ret" of the callee) -> (callerClassIndex, hash of the caller method). */
    class CallIndex {
        private var callee = IntArray(1 shl 16)
        private var caller = LongArray(1 shl 16)
        var size = 0
            private set

        fun add(calleeHash: Int, callerRef: Long) {
            if (size == callee.size) {
                callee = callee.copyOf(size * 2)
                caller = caller.copyOf(size * 2)
            }
            callee[size] = calleeHash
            caller[size] = callerRef
            size++
        }

        /** 0.37.6: merges the edges of another index (used to join the per-thread indexes of the parallel deep scan). */
        fun addAll(o: CallIndex) {
            for (i in 0 until o.size) add(o.callee[i], o.caller[i])
        }

        // 0.50.2: lazy hash lookup (rebuilt when edges were added since the last query). The class-level edges roughly triple the
        // index, and the approximate trace asks for callers up to 300 times per finding, so the old linear scan would be too slow.
        private var byCallee: HashMap<Int, ArrayList<Long>>? = null
        private var builtSize = -1

        @Synchronized
        fun callersOf(calleeHash: Int): List<Long> {
            var m = byCallee
            if (m == null || builtSize != size) {
                val nm = HashMap<Int, ArrayList<Long>>(size.coerceAtLeast(16))
                for (i in 0 until size) nm.getOrPut(callee[i]) { ArrayList<Long>(2) }.add(caller[i])
                byCallee = nm
                builtSize = size
                m = nm
            }
            return m[calleeHash] ?: emptyList<Long>()
        }
    }

    class Hop(val clsIndex: Int, val methodHash: Int)

    /** hops go from the entry method (first) down to the vulnerable method (last); entry = label of the exported component, or null when no path was found. */
    class Trace(val hops: List<Hop>, val entry: String?, val approximate: Boolean = false)

    /** 0.49.4: key of the synthetic "component launch" edge: every explicit startActivity/startService of class [type] ends here. */
    internal fun launchKey(type: String): Int = ("LAUNCH:" + type).hashCode()

    /** 0.50.0: key of the synthetic "implicit action" edge: every method that puts the custom action string [action] into an Intent ends here. */
    internal fun actionKey(action: String): Int = ("ACTION:" + action).hashCode()

    /** 0.50.2: outer class of an inner class type ("Lp/A$1;" -> "Lp/A;"). */
    internal fun outerType(type: String): String = type.substringBefore('$').let { if (it.endsWith(";")) it else "$it;" }

    /** 0.50.2: key of the CLASS-level edge: every method that calls ANY method of class [type] (inner classes count as their outer class). */
    internal fun classKey(type: String): Int = ("CLS:" + outerType(type)).hashCode()

    /** 0.50.2: owners that never lead to app components; skipping them keeps the class-level edges small. */
    private fun isFrameworkOwner(o: String): Boolean =
        o.startsWith("Landroid/") || o.startsWith("Ljava/") || o.startsWith("Ljavax/") || o.startsWith("Lkotlin/") ||
            o.startsWith("Lkotlinx/") || o.startsWith("Ldalvik/") || o.startsWith("Landroidx/") || o.startsWith("Lcom/google/")

    /** 0.50.0: a string constant that looks like a CUSTOM Intent action ("pkg.action.NAME"); framework actions (android.*) are far too common to link anything. */
    private fun customActionOrNull(line: String): String? {
        val a = line.indexOf('"')
        val b = line.lastIndexOf('"')
        if (a < 0 || b <= a + 1) return null
        val s = line.substring(a + 1, b)
        if (s.length < 6 || s.length > 150 || s.startsWith("android.") || !s.contains('.')) return null
        for (c in s) if (!(c.isLetterOrDigit() || c == '.' || c == '_' || c == '-')) return null
        return s
    }

    /** Adds the invoke edges of one class (smali text) to the index. */
    fun collectEdges(classType: String, clsIndex: Int, text: String, idx: CallIndex) {
        var cur = 0
        var inMethod = false
        // 0.49.4: explicit component launches. A method that loads a class constant AND builds an Intent / ComponentName for a Class
        // (new Intent(ctx, X.class), setClass) launches X. The call graph follows invoke edges only, so without this a deep link ->
        // startActivity -> WebViewActivity flow looked "unreachable" (OVAA, Wikipedia). One synthetic edge per (launcher method, X).
        var consts: ArrayList<String>? = null
        var launches = false
        // 0.50.0: implicit launches. A method that holds a custom action string constant AND builds an Intent from a String / calls
        // setAction puts that action into an Intent; the component whose manifest intent-filter declares it receives it.
        var acts: ArrayList<String>? = null
        var setsAction = false
        // 0.50.2: class-level edges (caller method -> OUTER class of the callee), one per (method, class). Used only by traceApprox.
        val ownOuter = outerType(classType)
        val owners = HashSet<String>()
        for (line in text.lineSequence()) {
            val t = line.trimStart()
            if (t.startsWith(".method ")) {
                cur = (classType + "->" + t.trimEnd().substringAfterLast(' ')).hashCode()
                inMethod = true
                owners.clear()
                consts = null
                launches = false
                acts = null
                setsAction = false
            } else if (t.startsWith(".end method")) {
                val done = consts
                if (inMethod && launches && done != null) {
                    for (c in done) idx.add(launchKey(c), (clsIndex.toLong() shl 32) or (cur.toLong() and 0xFFFFFFFFL))
                }
                val doneActs = acts
                if (inMethod && setsAction && doneActs != null) {
                    for (a in doneActs) idx.add(actionKey(a), (clsIndex.toLong() shl 32) or (cur.toLong() and 0xFFFFFFFFL))
                }
                inMethod = false
                consts = null
                launches = false
                acts = null
                setsAction = false
            } else if (inMethod && t.startsWith("const-string")) {
                val a = customActionOrNull(t)
                if (a != null) {
                    var l = acts
                    if (l == null) { l = ArrayList<String>(); acts = l }
                    if (l.size < 8 && !l.contains(a)) l.add(a)
                }
            } else if (inMethod && t.startsWith("const-class ")) {
                val ty = t.substringAfterLast(", ").trim()
                if (ty.startsWith("L") && ty.endsWith(";")) {
                    var l = consts
                    if (l == null) { l = ArrayList<String>(); consts = l }
                    if (l.size < 8 && !l.contains(ty)) l.add(ty)
                }
            } else if (inMethod && t.startsWith("invoke-")) {
                val i = t.indexOf("}, ")
                if (i > 0) {
                    val target = t.substring(i + 3).trim()
                    val callerRef = (clsIndex.toLong() shl 32) or (cur.toLong() and 0xFFFFFFFFL)
                    idx.add(target.hashCode(), callerRef)
                    val owner = target.substringBefore("->")
                    if (owner.startsWith("L") && owner.endsWith(";") && !isFrameworkOwner(owner)) {
                        val oo = outerType(owner)
                        if (oo != ownOuter && owners.add(oo)) idx.add(("CLS:" + oo).hashCode(), callerRef)
                    }
                    if (!launches && (target.startsWith("Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;") ||
                            target.startsWith("Landroid/content/Intent;->setClass(") ||
                            target.startsWith("Landroid/content/ComponentName;-><init>(Landroid/content/Context;Ljava/lang/Class;"))) launches = true
                    if (!setsAction && (target.startsWith("Landroid/content/Intent;-><init>(Ljava/lang/String;") ||
                            target.startsWith("Landroid/content/Intent;->setAction("))) setsAction = true
                }
            }
        }
    }

    /** "Lcls;->name(desc)ret" of the method that contains char offset [at], or null. */
    fun methodKeyAt(classType: String, text: String, at: Int): String? {
        val pos = if (at < 0) 0 else at
        val m = text.lastIndexOf("\n.method", pos)
        if (m < 0) return null
        val e = text.lastIndexOf("\n.end method", pos)
        if (e > m) return null
        val nl = text.indexOf('\n', m + 1)
        val lineEnd = if (nl < 0) text.length else nl
        val sig = text.substring(m + 1, lineEnd).trim().substringAfterLast(' ')
        return classType + "->" + sig
    }

    /** Breadth-first search up the call graph from the vulnerable method until a class of an exported component is reached. */
    fun trace(idx: CallIndex, startKey: String, startCls: Int, entryOf: (Int) -> String?, typeOf: (Int) -> String? = { null }, actionsOf: (Int) -> List<String> = { emptyList() }, maxDepth: Int = 6, maxNodes: Int = 600): Trace {
        val startHash = startKey.hashCode()
        val sinkId = (startCls.toLong() shl 32) or (startHash.toLong() and 0xFFFFFFFFL)
        entryOf(startCls)?.let { return Trace(listOf(Hop(startCls, startHash)), it) }
        val next = HashMap<Long, Long>()
        next[sinkId] = -1L
        var frontier: List<Long> = listOf(sinkId)
        var nodes = 0
        val launchSeen = HashSet<Int>()
        for (depth in 1..maxDepth) {
            val newFrontier = ArrayList<Long>()
            for (n in frontier) {
                val h = (n and 0xFFFFFFFFL).toInt()
                val callers = ArrayList<Long>(idx.callersOf(h))
                // 0.49.4: the component this method lives in may be launched explicitly from another method (see collectEdges)
                val ci = (n shr 32).toInt()
                if (launchSeen.add(ci)) {
                    val ty = typeOf(ci)
                    if (ty != null) {
                        val outer = ty.substringBefore('$').let { if (it.endsWith(";")) it else "$it;" }
                        callers.addAll(idx.callersOf(launchKey(outer)))
                    }
                    // 0.50.0: ... or implicitly, by a custom action its manifest intent-filter declares
                    for (a in actionsOf(ci)) callers.addAll(idx.callersOf(actionKey(a)))
                }
                for (c in callers) {
                    if (next.containsKey(c)) continue
                    next[c] = n
                    nodes++
                    val label = entryOf((c shr 32).toInt())
                    if (label != null) {
                        val hops = ArrayList<Hop>()
                        var cur = c
                        while (cur != -1L) {
                            hops.add(Hop((cur shr 32).toInt(), (cur and 0xFFFFFFFFL).toInt()))
                            cur = next[cur] ?: -1L
                        }
                        return Trace(hops, label)
                    }
                    newFrontier.add(c)
                    if (nodes >= maxNodes) return Trace(emptyList(), null)
                }
            }
            if (newFrontier.isEmpty()) break
            frontier = newFrontier
        }
        return Trace(emptyList(), null)
    }

    /**
     * 0.50.2: APPROXIMATE trace, used only when [trace] found nothing. It walks the CLASS graph: "some method of class A calls some
     * method of class B" is enough for a link, so it steps over fragments, lambdas, interface dispatch and Kotlin lowering that cut the
     * exact method-level path. The result is "probably connected", never "proven": the caller marks it as approximate.
     * Guards against false links: depth 3 (0.51.2: a 4-hop class-level path on Aegis was pure coincidence), at most [maxNodes] nodes, and a class called from more than [hubLimit] other classes
     * (utility / base classes) is not expanded beyond the first level. Explicit launches and custom actions are followed as in [trace].
     */
    fun traceApprox(
        idx: CallIndex, startKey: String, startCls: Int, entryOf: (Int) -> String?, typeOf: (Int) -> String? = { null },
        actionsOf: (Int) -> List<String> = { emptyList() }, maxDepth: Int = 3, maxNodes: Int = 300, hubLimit: Int = 25
    ): Trace {
        val startHash = startKey.hashCode()
        val sink = (startCls.toLong() shl 32) or (startHash.toLong() and 0xFFFFFFFFL)
        entryOf(startCls)?.let { return Trace(listOf(Hop(startCls, startHash)), it, true) }
        val next = HashMap<Long, Long>()
        next[sink] = -1L
        val seenClasses = HashSet<String>()
        var frontier: List<Long> = listOf(sink)
        var nodes = 0
        for (depth in 1..maxDepth) {
            val newFrontier = ArrayList<Long>()
            for (n in frontier) {
                val ci = (n shr 32).toInt()
                val ty = typeOf(ci) ?: continue
                val outer = outerType(ty)
                if (!seenClasses.add(outer)) continue
                val callers = ArrayList<Long>(idx.callersOf(classKey(ty)))
                callers.addAll(idx.callersOf(launchKey(outer)))
                for (a in actionsOf(ci)) callers.addAll(idx.callersOf(actionKey(a)))
                if (depth > 1) {
                    val distinct = HashSet<Int>()
                    for (c in callers) distinct.add((c shr 32).toInt())
                    if (distinct.size > hubLimit) continue
                }
                for (c in callers) {
                    if (next.containsKey(c)) continue
                    val cc = (c shr 32).toInt()
                    if (cc == ci) continue
                    next[c] = n
                    nodes++
                    val label = entryOf(cc)
                    if (label != null) {
                        val hops = ArrayList<Hop>()
                        var cur = c
                        while (cur != -1L) {
                            hops.add(Hop((cur shr 32).toInt(), (cur and 0xFFFFFFFFL).toInt()))
                            cur = next[cur] ?: -1L
                        }
                        return Trace(hops, label, true)
                    }
                    newFrontier.add(c)
                    if (nodes >= maxNodes) return Trace(emptyList(), null, true)
                }
            }
            if (newFrontier.isEmpty()) break
            frontier = newFrontier
        }
        return Trace(emptyList(), null, true)
    }

    /** 0.50.0: type ("Lpkg/Cls;") of EVERY component (exported or not) -> the CUSTOM actions of its intent-filters. activity-alias is resolved to its targetActivity. */
    fun componentActions(xml: String, manifestPkg: String): Map<String, List<String>> {
        val out = HashMap<String, ArrayList<String>>()
        val compRe = rx("<(activity-alias|activity|service|receiver)(?![\\w-])([^>]*?)(?:/>|>([\\s\\S]*?)</\\1>)")
        val actRe = rx("<action\\s+android:name\\s*=\\s*\"([^\"]+)\"")
        for (m in compRe.findAll(xml)) {
            val tag = m.groupValues[1]
            val header = m.groupValues[2]
            val body = m.groupValues[3]
            if (body.isEmpty()) continue
            var name = rx("android:name\\s*=\\s*\"([^\"]+)\"").find(header)?.groupValues?.get(1) ?: continue
            if (tag == "activity-alias") name = rx("android:targetActivity\\s*=\\s*\"([^\"]+)\"").find(header)?.groupValues?.get(1) ?: continue
            val full = when {
                name.startsWith(".") -> manifestPkg + name
                name.contains('.') -> name
                else -> "$manifestPkg.$name"
            }
            val acts = ArrayList<String>()
            for (a in actRe.findAll(body)) {
                val v = a.groupValues[1]
                if (!v.startsWith("android.") && v.contains('.') && !acts.contains(v)) acts.add(v)
            }
            if (acts.isEmpty()) continue
            out.getOrPut("L" + full.replace('.', '/') + ";") { ArrayList() }.addAll(acts)
        }
        return out
    }

    /** Exported components of the manifest: full class name (dots) -> label. activity-alias is resolved to its targetActivity. */
    fun exportedComponents(xml: String, manifestPkg: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        val compRe = rx("<(activity-alias|activity|service|receiver|provider)(?![\\w-])([^>]*?)(?:/>|>([\\s\\S]*?)</\\1>)")
        for (m in compRe.findAll(xml)) {
            val tag = m.groupValues[1]
            val header = m.groupValues[2]
            val body = m.groupValues[3]
            var name = rx("android:name\\s*=\\s*\"([^\"]+)\"").find(header)?.groupValues?.get(1) ?: continue
            if (tag == "activity-alias") {
                name = rx("android:targetActivity\\s*=\\s*\"([^\"]+)\"").find(header)?.groupValues?.get(1) ?: continue
            }
            val exportedM = rx("android:exported\\s*=\\s*\"(true|false)\"").find(header)
            val exported = if (exportedM != null) exportedM.groupValues[1] == "true" else body.contains("<intent-filter")
            if (!exported) continue
            val full = when {
                name.startsWith(".") -> manifestPkg + name
                name.contains('.') -> name
                else -> "$manifestPkg.$name"
            }
            val extra = when {
                body.contains("android.intent.category.BROWSABLE") -> " (deep link)"
                body.contains("android.intent.category.LAUNCHER") -> " (launcher)"
                else -> ""
            }
            out[full] = "exported $tag $full$extra"
        }
        return out
    }
}
