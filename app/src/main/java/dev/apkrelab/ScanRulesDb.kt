package dev.apkrelab

import dev.apkrelab.SecurityScanner.Severity

/**
 * 0.100.0 (the gaps that MobSF's rules had and ours did not, restricted to what is precise):
 * - Jackson polymorphic typing in the APP's own code: `ObjectMapper.enableDefaultTyping()` (no validator), `activateDefaultTyping` with a permissive validator, `@JsonTypeInfo(use = CLASS | MINIMAL_CLASS)`.
 *   Jackson's own classes are skipped (in a real wallet app the only `enableDefaultTyping` calls were the library's definitions).
 * - A SQLCipher passphrase that is a constant, or a device identifier: found by following the register that reaches `getWritableDatabase(String)` / `getReadableDatabase(String)` /
 *   `SupportFactory(byte[])` inside the method (linear, approximate). A passphrase that comes from anywhere else (a Keystore, a reflective call) is NOT reported: unknown is not a finding.
 */
object JacksonDefaultTypingRule : ScanRule {
    override val id = "jackson-default-typing"
    override val title = "Jackson polymorphic typing enabled (class names in JSON)"
    override val cwes = listOf("CWE-502")
    override val confidence = "HIGH"
    private val enableRe = rx("Lcom/fasterxml/jackson/databind/ObjectMapper;->enableDefaultTyping\\(")
    private val activateRe = rx("Lcom/fasterxml/jackson/databind/ObjectMapper;->activateDefaultTyping(?:AsProperty)?\\(")
    private val laissezRe = rx("LaissezFaireSubTypeValidator")
    private val annoRe = rx("\\.annotation runtime Lcom/fasterxml/jackson/annotation/JsonTypeInfo;[^.]{0,300}?use = \\.enum Lcom/fasterxml/jackson/annotation/JsonTypeInfo\\\$Id;->(?:CLASS|MINIMAL_CLASS)")

    override fun scan(ctx: RuleContext): List<SecurityScanner.Finding> {
        if (ctx.classType.startsWith("Lcom/fasterxml/jackson/")) return emptyList()
        val t = ctx.text
        if (!t.contains("com/fasterxml/jackson/")) return emptyList()
        val en = enableRe.find(t)
        val ac = if (en == null) activateRe.find(t)?.takeIf { laissezRe.containsMatchIn(t) } else null
        val an = annoRe.find(t)
        val hit = en ?: ac ?: an ?: return emptyList()
        val what = when {
            en != null -> "enableDefaultTyping() (no validator at all)"
            ac != null -> "activateDefaultTyping() with a validator that allows every class (LaissezFaireSubTypeValidator)"
            else -> "an @JsonTypeInfo(use = CLASS / MINIMAL_CLASS) annotation"
        }
        return listOf(ctx.finding(Severity.MEDIUM, title,
            "This class uses $what: the JSON names the Java class to instantiate. When the JSON comes from a server, a file or another app, a crafted class name can build a gadget class of the classpath (known Jackson deserialization remote-code-execution family).",
            "Do not enable default typing; use a fixed type, or `activateDefaultTyping` / `@JsonTypeInfo` with a PolymorphicTypeValidator that allow-lists your own base package (BasicPolymorphicTypeValidator), and keep Jackson current.",
            hit.range.first, "CWE-502"))
    }
}

object SqlCipherPassphraseRule : ScanRule {
    override val id = "crypto-db-passphrase"
    override val title = "SQLCipher database passphrase is a constant or a device identifier"
    override val cwes = listOf("CWE-798")
    override val confidence = "HIGH"
    private val trigger = rx("->(?:getWritableDatabase|getReadableDatabase)\\(Ljava/lang/String;\\)|net/sqlcipher/database/SQLiteDatabase;->(?:openOrCreateDatabase|openDatabase)\\(|SupportFactory;-><init>\\(\\[B|SupportOpenHelperFactory;-><init>\\(\\[B")
    private val targetRe = rx("invoke-(?:virtual|direct|static)(?:/range)? \\{([^}]*)\\}, (L[^;]+;->(?:getWritableDatabase|getReadableDatabase)\\(Ljava/lang/String;\\)|Lnet/sqlcipher/database/SQLiteDatabase;->(?:openOrCreateDatabase|openDatabase)\\([^)]*\\)|L[^;]*SupportFactory;-><init>\\(\\[B\\)|L[^;]*SupportOpenHelperFactory;-><init>\\(\\[B\\))")
    private val methodRe = rx("^[ \\t]*\\.method [^\\n]*", RegexOption.MULTILINE)
    private val regTok = rx("[vp]\\d+")
    private val predictable = rx("Landroid/provider/Settings\\\$Secure;->getString|Landroid/os/Build;->getSerial|Landroid/telephony/TelephonyManager;->(?:getDeviceId|getImei|getSubscriberId|getSimSerialNumber)|Landroid/content/Context;->getPackageName|Landroid/content/ContextWrapper;->getPackageName")

    /** (kind, shown) of the value in each passphrase argument of the method bodies of [text]: kind CONSTANT or PREDICTABLE only. */
    internal fun origins(text: String): List<Triple<String, String, Int>> {
        val out = ArrayList<Triple<String, String, Int>>()
        val starts = methodRe.findAll(text).map { it.range.first }.toList()
        for ((i, st) in starts.withIndex()) {
            val end = if (i + 1 < starts.size) starts[i + 1] else text.length
            val body = text.substring(st, end)
            if (!trigger.containsMatchIn(body)) continue
            val defs = HashMap<String, Pair<String, String>>()          // register -> (CONSTANT | PREDICTABLE | OTHER, shown)
            var lastCallee: String? = null; var lastRegs: List<String> = emptyList()
            var pos = st
            for (raw in body.lineSequence()) {
                val l = raw.trim(); val here = pos; pos += raw.length + 1
                if (l.isEmpty()) continue
                if (l.startsWith("const-string")) { val r = regTok.find(l)?.value ?: continue; val v = Regex("\"((?:[^\"\\\\]|\\\\.)*)\"").find(l)?.groupValues?.get(1) ?: ""; defs[r] = "CONSTANT" to v; continue }
                if (l.startsWith("fill-array-data")) { regTok.find(l)?.value?.let { defs[it] = "CONSTANT" to "byte array literal" }; continue }
                if (l.startsWith("invoke")) {
                    val tm = targetRe.find(l)
                    if (tm != null) {
                        val rs = regTok.findAll(tm.groupValues[1]).map { it.value }.toList()
                        // the passphrase is the String argument (virtual: after the receiver) or the byte[] of the constructor
                        for (r in rs.drop(if (l.startsWith("invoke-static")) 0 else 1)) {
                            val d = defs[r] ?: continue
                            if (d.first == "CONSTANT" || d.first == "PREDICTABLE") out.add(Triple(d.first, d.second, here))
                        }
                    }
                    lastCallee = Regex("\\}, (L[^;]+;->[A-Za-z0-9_$<>]+)").find(l)?.groupValues?.get(1); lastRegs = regTok.findAll(l.substringAfter('{').substringBefore('}')).map { it.value }.toList()
                    continue
                }
                if (l.startsWith("move-result")) {
                    val r = regTok.find(l)?.value ?: continue; val c = lastCallee
                    defs[r] = when {
                        c == null -> ("OTHER" to "")
                        predictable.containsMatchIn(c) -> "PREDICTABLE" to ("the result of " + c.substringBefore(";->").substringAfterLast('/') + "." + c.substringAfter(";->"))
                        // a constant stays a constant through getBytes / toCharArray / Base64.decode / String.valueOf / toString
                        (c.endsWith("->getBytes") || c.endsWith("->toCharArray") || c.endsWith("->toString") || c.endsWith("->valueOf") || c.endsWith("->decode") || c.endsWith("->trim")) && lastRegs.firstOrNull()?.let { defs[it]?.first == "CONSTANT" } == true -> "CONSTANT" to (defs[lastRegs.first()]?.second ?: "")
                        else -> "OTHER" to ""
                    }
                    lastCallee = null; continue
                }
                if (l.startsWith("sget")) { val r = regTok.find(l)?.value ?: continue; defs[r] = if (l.contains("Landroid/os/Build;->SERIAL")) ("PREDICTABLE" to "Build.SERIAL") else ("OTHER" to ""); continue }
                if (l.startsWith("move-object") || l.startsWith("move ")) { val ts = regTok.findAll(l).map { it.value }.toList(); if (ts.size >= 2) defs[ts[0]] = defs[ts[1]] ?: ("OTHER" to ""); continue }
                if (!Regex("^(return|goto|if-|iput|sput|aput|throw|check-cast|monitor|nop|\\.|:|#)").containsMatchIn(l)) regTok.find(l)?.let { defs[it.value] = "OTHER" to "" }
            }
        }
        return out
    }

    override fun scan(ctx: RuleContext): List<SecurityScanner.Finding> {
        if (ctx.classType.startsWith("Lnet/sqlcipher/") || ctx.classType.startsWith("Lnet/zetetic/")) return emptyList()        // the library itself
        if (!trigger.containsMatchIn(ctx.text)) return emptyList()
        val o = origins(ctx.text)
        if (o.isEmpty()) return emptyList()
        val const = o.firstOrNull { it.first == "CONSTANT" }
        val (sev, what, at) = if (const != null)
            Triple(Severity.HIGH, "a constant (" + (if (const.second.length > 2 && const.second != "byte array literal") "\"" + const.second.take(2) + "…\", ${const.second.length} characters" else const.second) + ")", const.third)
        else Triple(Severity.MEDIUM, "a value derived from a device identifier (" + o.first().second + ")", o.first().third)
        return listOf(ctx.finding(sev, title,
            "The passphrase handed to the SQLCipher database is $what: it is compiled into the APK or can be recomputed from the device, so anyone with the APK (or the app's data directory) can open the encrypted database, which defeats the encryption.",
            "Generate a random key once, keep it wrapped by an Android Keystore key (EncryptedSharedPreferences / a Keystore-backed AES key), or derive it from a user secret with PBKDF2; never compile it in and never derive it from ANDROID_ID, the serial or the package name.",
            at, "CWE-798"))
    }
}
