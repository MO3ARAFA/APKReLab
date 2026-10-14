package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import dev.apkrelab.ir.IrRules
import java.io.InputStream
import java.util.zip.ZipFile

/**
 * 0.75.0: rules whose decision is made on the IR (SSA of one class, see ir/IrRules.java), plus the tapjacking resource rule.
 * No rule here keeps state between classes or between scans: everything is per class (code rules) or per APK pass (ApkFacts,
 * computed once by ResourceScanner.scanApk and handed to the layout rule through ResourceContext).
 */
object IrHits {
    fun sev(s: String): Severity = when (s) {
        "CRITICAL" -> Severity.CRITICAL; "HIGH" -> Severity.HIGH; "MEDIUM" -> Severity.MEDIUM; "LOW" -> Severity.LOW; else -> Severity.INFO
    }

    fun toFindings(ctx: RuleContext, hits: List<IrRules.Hit>, rec: String): List<Finding> = hits.map { h ->
        ctx.finding(sev(h.sev), h.title, h.detail, rec, h.offset, h.cwe).also { it.ruleId = h.rule; it.confidence = h.conf }
    }
}

/** Sensitive columns / values written to plain SQLite (SSA backward slice), else one INFO per SQLiteOpenHelper. */
object SqliteUnencryptedRule : ScanRule {
    override val id = "sqlite-unencrypted"
    override val title = "Sensitive data stored in plain SQLite"
    override val cwes = listOf("CWE-312")
    override val confidence = "MEDIUM"

    private const val REC = "Do not keep credentials in a database at all (store a salted hash or a revocable token). For private data use SQLCipher " +
        "(net.zetetic:sqlcipher-android) or encrypt the values with a key from the Android Keystore; set allowBackup=false or exclude the database from backups."

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB || !ctx.text.contains("Landroid/database/sqlite/")) return emptyList()
        val c = ctx.ir ?: return emptyList()
        return IrHits.toFindings(ctx, IrRules.sqliteSensitive(c, ctx.text), REC)
    }
}

/** WebSettings.setPluginState(ON / ON_DEMAND) or setPluginsEnabled(true), the enum constant traced in SSA. */
object WebviewPluginStateRule : ScanRule {
    override val id = "webview-plugin-state"
    override val title = "WebView plugins enabled (deprecated setPluginState)"
    override val cwes = listOf("CWE-477")
    override val confidence = "HIGH"

    private const val REC = "Remove setPluginState / setPluginsEnabled (plugins are unsupported since Android 4.3) and review the rest of this WebView's settings (JavaScript, file access, mixed content)."

    override fun scan(ctx: RuleContext): List<Finding> {
        if (!ctx.text.contains("Landroid/webkit/WebSettings;->setPlugin")) return emptyList()
        val c = ctx.ir ?: return emptyList()
        return IrHits.toFindings(ctx, IrRules.pluginState(c), REC)
    }
}

/**
 * APK-wide facts the layout rules need, computed in ONE streaming pass by ResourceScanner.scanApk (no dex is kept in memory):
 * whether code anywhere references a tapjacking mitigation API, and the manifest minSdkVersion.
 */
class ApkFacts(val minSdk: Int?, val mitigations: Set<String>) {
    companion object {
        val NONE = ApkFacts(null, emptySet())
        val MITIGATION_NAMES = listOf("setFilterTouchesWhenObscured", "onFilterTouchEventForSecurity", "setHideOverlayWindows")

        /** Streams every classes*.dex once and reports which [needles] occur (dex string ids hold every referenced method name). */
        fun dexMentions(zip: ZipFile, needles: List<String>): Set<String> {
            val found = HashSet<String>()
            val pats = needles.map { it.toByteArray(Charsets.UTF_8) }
            val maxLen = pats.maxOf { it.size }
            for (e in zip.entries()) {
                if (!e.name.matches(Regex("classes\\d*\\.dex"))) continue
                zip.getInputStream(e).use { scan(it, pats, maxLen, needles, found) }
                if (found.size == needles.size) break
            }
            return found
        }

        private fun scan(ins: InputStream, pats: List<ByteArray>, maxLen: Int, names: List<String>, found: MutableSet<String>) {
            val buf = ByteArray(64 * 1024 + maxLen)
            var keep = 0
            while (true) {
                val n = ins.read(buf, keep, buf.size - keep)
                if (n <= 0) break
                val end = keep + n
                for (k in pats.indices) {
                    if (names[k] in found) continue
                    if (indexOf(buf, end, pats[k]) >= 0) found.add(names[k])
                }
                keep = minOf(maxLen - 1, end)
                System.arraycopy(buf, end - keep, buf, 0, keep)
            }
        }

        private fun indexOf(b: ByteArray, end: Int, p: ByteArray): Int {
            var i = 0
            val last = end - p.size
            outer@ while (i <= last) {
                for (j in p.indices) if (b[i + j] != p[j]) { i++; continue@outer }
                return i
            }
            return -1
        }

        /** minSdkVersion from the decoded manifest text (decimal or hex), or null. */
        fun minSdkOf(manifestXml: String?): Int? {
            val v = Regex("minSdkVersion\\s*=\\s*\"([^\"]+)\"").find(manifestXml ?: return null)?.groupValues?.get(1) ?: return null
            return if (v.startsWith("0x")) v.removePrefix("0x").toIntOrNull(16) else v.toIntOrNull()
        }
    }
}

/**
 * Tapjacking (CWE-1021): a layout with a password field where neither the field nor any parent sets filterTouchesWhenObscured="true".
 * A ViewGroup with the flag drops obscured touches for its whole subtree (ViewGroup.dispatchTouchEvent checks onFilterTouchEventForSecurity
 * first), so the flag anywhere in the file covers the field. Cross-checked with the code: if the dex references setFilterTouchesWhenObscured /
 * onFilterTouchEventForSecurity / setHideOverlayWindows the screen may be protected from code, and the finding drops to LOW.
 * Android 12 (API 31) blocks touches that pass through untrusted overlays for every app, so minSdk >= 31 makes it INFO.
 */
object TapjackingLayoutRule : ResourceRule {
    override val id = "tapjacking-sensitive-layout"
    override val title = "Password screen not protected against tapjacking"
    override val cwes = listOf("CWE-1021")
    override val confidence = "MEDIUM"

    // layouts that belong to well-known libraries (AppCompat, Material, Google sign-in, Facebook ...)
    private val libPrefix = Regex("^(abc_|mtrl_|design_|material_|m3_|com_facebook_|common_google|googleg_|notification_|select_dialog_|support_|exo_|leak_canary)")

    override fun appliesTo(ctx: ResourceContext): Boolean =
        ctx.path.startsWith("res/") && ctx.xml.contains("EditText") && !libPrefix.containsMatchIn(ctx.path.substringAfterLast('/'))

    private fun isPasswordType(v: String): Boolean {
        if (v.contains("assword")) return true
        val n = (if (v.startsWith("0x")) v.removePrefix("0x").toIntOrNull(16) else v.toIntOrNull()) ?: return false
        val cls = n and 0xF
        val variation = n and 0xFF0
        return (cls == 1 && (variation == 0x80 || variation == 0x90 || variation == 0xE0)) || (cls == 2 && variation == 0x10)
    }

    override fun scan(ctx: ResourceContext): List<Finding> {
        val xml = ctx.xml
        if (rx("filterTouchesWhenObscured\\s*=\\s*\"(?:true|0xffffffff|-1)\"").containsMatchIn(xml)) return emptyList()
        val field = rx("<[A-Za-z0-9_.]*EditText\\b[^>]*>").findAll(xml).firstOrNull { m ->
            val tag = m.value
            val it = rx("inputType\\s*=\\s*\"([^\"]*)\"").find(tag)?.groupValues?.get(1)
            (it != null && isPasswordType(it)) || rx("\\bpassword\\s*=\\s*\"true\"").containsMatchIn(tag)
        } ?: return emptyList()
        val idName = rx("android:id\\s*=\\s*\"([^\"]*)\"").find(field.value)?.groupValues?.get(1)?.substringAfterLast('/') ?: "?"
        val facts = ctx.apk
        val mitigated = facts.mitigations.isNotEmpty()
        val modern = (facts.minSdk ?: 0) >= 31
        val sev = when { modern -> Severity.INFO; mitigated -> Severity.LOW; else -> Severity.MEDIUM }
        val detail = StringBuilder("This layout has a password field (\"$idName\") and no view in it sets android:filterTouchesWhenObscured=\"true\", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking).")
        if (mitigated) detail.append(" The app's code references ").append(facts.mitigations.sorted().joinToString(", "))
            .append(", so this screen may be protected from code: check that the Activity using this layout really calls it with true.")
        else detail.append(" No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex.")
        if (facts.minSdk != null) detail.append(" minSdkVersion is ${facts.minSdk}")
            .append(if (modern) ": Android 12+ already blocks touches through untrusted overlays, so this is informational." else ": devices below Android 12 do not block touches through overlays.")
        val f = Finding(sev, title, detail.toString() + "  [${ctx.path}]",
            "Set android:filterTouchesWhenObscured=\"true\" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).",
            null, -1, -1, "CWE-1021", ctx.path)
        f.confidence = if (mitigated) "LOW" else "MEDIUM"
        return listOf(f)
    }
}

/**
 * 0.81.0: a plain-HTTP URL that the app's OWN code (scope APP) actually uses: a `const-string "http://<host>..."` in a method that also opens a
 * connection / builds a request / loads a page (URL, HttpURLConnection, OkHttp Request.Builder / HttpUrl, Retrofit baseUrl, WebView.loadUrl,
 * Volley, Ktor). Local / documentation hosts (localhost, 127.x, 10.x, 192.168.x, schemas / w3 / apache / example) are ignored. Its presence
 * is the evidence [FindingPolish.applyNetworkEvidence] needs to keep the cleartext configuration cards HIGH.
 */
object CleartextUrlUsedRule : ScanRule {
    override val id = "cleartext-url-used"
    override val title = "Plain-HTTP URL used by the app"
    override val cwes = listOf("CWE-319")
    override val confidence = "MEDIUM"

    private val urlRe = rx("const-string(?:/jumbo)? [vp]\\d+, \"(http://([A-Za-z0-9.-]+)[^\"]*)\"")
    private val ignoreHost = rx("^(?:localhost|127\\.|10\\.|192\\.168\\.|0\\.0\\.0\\.0|.*schemas\\.|.*w3\\.org|.*apache\\.org|.*example\\.(?:com|org|net)|.*xmlpull\\.org|.*xml\\.org|ns\\.adobe\\.com|.*purl\\.org|.*openxmlformats\\.org|.*android\\.com$)")
    private val netUse = rx("Ljava/net/URL;-><init>|Ljava/net/HttpURLConnection;|Lokhttp3/Request\\\$Builder;->url|Lokhttp3/HttpUrl|Lretrofit2/Retrofit\\\$Builder;->baseUrl|Landroid/webkit/WebView;->loadUrl|Lcom/android/volley/|Lio/ktor/")

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope != SecurityScanner.Scope.APP || !ctx.text.contains("\"http://")) return emptyList()
        for (m in OvaaHelpers.methods(ctx.text)) {
            if (!netUse.containsMatchIn(m.body)) continue
            val u = urlRe.findAll(m.body).firstOrNull { !ignoreHost.containsMatchIn(it.groupValues[2]) } ?: continue
            return listOf(ctx.finding(SecurityScanner.Severity.MEDIUM, title,
                "The app's own code builds a connection / request / page load with the plain-HTTP URL " + u.groupValues[1].take(80) +
                    ": what it sends or receives there can be read and changed on the network.",
                "Use https:// for this endpoint.", m.start + u.range.first, "CWE-319"))
        }
        return emptyList()
    }
}

