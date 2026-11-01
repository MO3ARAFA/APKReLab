package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity

/**
 * 0.52.0: financial-app-focused SAST rules (trading/banking/fintech audits).
 *
 * Five modules, requested together as a set to prep the scanner for real trading-app audits:
 *   1. FinancialAsyncTaintRule   - secrets/tokens that cross an RxJava/Coroutine/AsyncTask boundary before reaching a sink
 *   2. UnencryptedSensitiveStorageRule - PINs/API keys/tokens written to plain SharedPreferences (no EncryptedSharedPreferences nearby)
 *   3. InsecureWebSocketRule     - ws:// literals and WebSocket clients built with no auth header / token near the handshake
 *   4. ExportedSensitiveActionRule - an exported-looking component reads an Intent extra straight into a trade/transfer/payment call
 *   5. FridaDetectionRule        - client-side Frida/instrumentation detection (maturity signal, same family as AndroGoat's root/emulator checks)
 *
 * Same plugin shape as every other ScanRule: one object, register() in RuleRegistry.init, reuse an existing VulnKnowledge CWE
 * where the weakness is already catalogued (CWE-927 tainted data use, CWE-312 insecure storage, CWE-319 cleartext transmission,
 * CWE-926 exported component, CWE-693 protection-mechanism-failure) so no new knowledge-base entry is required.
 */

private val financialSecretWords = Regex("(?i)(api[_-]?key|secret|bearer|access[_-]?token|refresh[_-]?token|oauth|session[_-]?id|auth[_-]?token)")
private val financialActionWords = Regex("(?i)(trade|order|withdraw|transfer|deposit|payout|payment|wire|remit|placeorder|executeorder|sendmoney|cashout)")
private val pinLikeWords = Regex("(?i)(pin\\b|passcode|password|passwd)")

/** 1. Secrets that flow through an async boundary (RxJava Observable/Single/Flowable, Kotlin Coroutine, or AsyncTask) before hitting a sink. */
object FinancialAsyncTaintRule : ScanRule {
    override val id = "fintech-async-taint"
    override val title = "Sensitive financial data crosses an async boundary toward a sink"
    override val cwes = listOf("CWE-927")
    override val confidence = "MEDIUM"

    // RxJava / Coroutines / AsyncTask entry points used for live price feeds, order submission, auth refresh.
    private val asyncBoundary = rx(
        "L(?:io/reactivex/[\\w/]+/(?:Observable|Single|Flowable|Completable|Maybe)|" +
        "kotlinx/coroutines/(?:BuildersKt|flow/FlowKt|CoroutineScopeKt)|" +
        "android/os/AsyncTask|kotlin/coroutines/Continuation);->" +
        "(subscribe|doOnNext|doOnSuccess|map|flatMap|launch|async|resumeWith|onPostExecute|doInBackground|collect)\\("
    )
    private val sink = rx(
        "L(?:okhttp3/[\\w/]+|java/net/[\\w/]+|android/util/Log|android/webkit/WebView);->" +
        "(newCall|writeUtf8|println?|d|i|w|e|loadUrl|evaluateJavascript)\\("
    )

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val text = ctx.text
        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(text)) {
            val boundary = asyncBoundary.find(m.body) ?: continue
            val strings = OvaaHelpers.constStrings(m.body)
            val secretHit = strings.firstOrNull { financialSecretWords.containsMatchIn(it) }
            // field/member names carrying the value (e.g. a field called apiKey/bearerToken read right before the callback)
            val memberHit = rx("\\biget-object\\b[^\\n]*?->([A-Za-z_$][\\w$]*):").find(m.body)
                ?.takeIf { financialSecretWords.containsMatchIn(it.groupValues[1]) }
            if (secretHit == null && memberHit == null) continue
            val sinkHit = sink.find(m.body.substring(boundary.range.first)) ?: continue
            val label = secretHit?.let { "a literal matching a secret/token pattern (\"${it.take(3)}…\")" }
                ?: "a field named like a credential (\"${memberHit!!.groupValues[1]}\")"
            out.add(ctx.finding(Severity.MEDIUM, title,
                "This method hands $label to an async callback (${boundary.groupValues[1]}), and inside that callback the data reaches " +
                    "${sinkHit.groupValues[1]}(). Taint that crosses a callback/coroutine boundary is easy to miss in manual review and in " +
                    "simple same-method taint trackers - live price feeds, order submission, and token-refresh flows in trading apps are " +
                    "built exactly this way (RxJava chains, suspend functions, or AsyncTask.doInBackground/onPostExecute).",
                "Scope the secret's lifetime to the call that needs it, avoid logging/echoing it from inside the callback, and verify the " +
                    "sink is the intended one, not a diagnostic log left in a release build.",
                m.start + boundary.range.first, "CWE-927"))
        }
        return out
    }
}

/** 2. A PIN/API key/token is written to plain SharedPreferences with no EncryptedSharedPreferences/Keystore use anywhere in the class. */
object UnencryptedSensitiveStorageRule : ScanRule {
    override val id = "fintech-unencrypted-storage"
    override val title = "Credential or secret stored in plain SharedPreferences"
    override val cwes = listOf("CWE-312")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val text = ctx.text
        // If this class (or the prefs object it builds) ever touches EncryptedSharedPreferences or the Keystore, it's covered - skip.
        if (text.contains("Landroidx/security/crypto/EncryptedSharedPreferences;") ||
            text.contains("Ljava/security/KeyStore;") || text.contains("Landroid/security/keystore/")) return emptyList()

        // 0.76.0 (Password Store: Hilt injects EncryptedSharedPreferences("http_proxy")): when this class never OPENS a preferences file itself,
        // the SharedPreferences object comes from outside (dependency injection, a field, a parameter) and may well be encrypted.
        val opensPrefs = text.contains("->getSharedPreferences(") || text.contains("->getDefaultSharedPreferences(")
        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(text)) {
            if (!m.body.contains("Landroid/content/SharedPreferences\$Editor;->putString(")) continue
            for (put in rx("Landroid/content/SharedPreferences\\\$Editor;->putString\\(").findAll(m.body)) {
                // the key literal is normally the const-string loaded just before the putString call
                val before = m.body.substring(maxOf(0, put.range.first - 200), put.range.first)
                val keyLit = rx("const-string[^,]*,\\s*\"([^\"]{2,60})\"").findAll(before).lastOrNull()?.groupValues?.get(1) ?: continue
                val isPin = pinLikeWords.containsMatchIn(keyLit)
                val isSecret = financialSecretWords.containsMatchIn(keyLit)
                if (!isPin && !isSecret) continue
                // 0.75.2: the title says what the key is (Allsafe: "financial value" on a password); the rule id is unchanged
                val shown = if (isPin) "Credential stored in plain SharedPreferences" else "Secret token stored in plain SharedPreferences"
                val sevBase = if (isPin) Severity.HIGH else Severity.MEDIUM
                val injected = !opensPrefs
                out.add(ctx.finding(if (injected) Severity.LOW else sevBase, shown,
                    "A value under the key \"$keyLit\" is written with SharedPreferences.Editor.putString(), and this class never touches " +
                        "EncryptedSharedPreferences or the Android Keystore. Plain SharedPreferences XML is readable on a rooted device, from " +
                        "an adb backup, or from any app sharing the same Linux UID (shared UID apps) - for a PIN, API key or session token " +
                        "that's a direct credential-theft path.",
                    "Move this key to androidx.security.crypto.EncryptedSharedPreferences, or better, keep it only in the Android Keystore " +
                        "(StrongBox/TEE-backed where available) and never serialize it to disk in cleartext.",
                    m.start + put.range.first, "CWE-312").also {
                        if (injected) {
                            it.detail = it.detail + " NOTE: this class never opens a preferences file itself (no getSharedPreferences / getDefaultSharedPreferences), so the SharedPreferences object is provided from outside (dependency injection, a field or a parameter) and may be EncryptedSharedPreferences: check where it is created before trusting this finding."
                            it.confidence = "LOW"
                        }
                    })
            }
        }
        return out
    }
}

/** 3. WebSocket channels used for live market data: a ws:// literal, or a client built with no token/header near the handshake. */
object InsecureWebSocketRule : ScanRule {
    override val id = "fintech-insecure-websocket"
    override val title = "Insecure or unauthenticated WebSocket connection"
    override val cwes = listOf("CWE-319")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        val text = ctx.text
        val out = ArrayList<Finding>()

        // 3a. plain ws:// literal (the wss:// equivalent is fine and not flagged)
        var wsCount = 0
        var wsFirst: MatchResult? = null
        for (m in rx("const-string[^,]*,\\s*\"(ws://[^\"\\s]{4,})\"").findAll(text)) {
            wsCount++
            if (wsFirst == null) wsFirst = m
        }
        wsFirst?.let {
            out.add(ctx.finding(Severity.HIGH, "Hardcoded insecure WebSocket URL (ws://)",
                "A plain ws:// endpoint is hardcoded (${it.groupValues[1].take(60)})" + (if (wsCount > 1) " and ${wsCount - 1} more in this class" else "") +
                    ". Unlike wss://, this channel is not encrypted: anyone on the network path (a rogue Wi-Fi AP, a compromised router) can " +
                    "read every tick of a live price feed and inject forged quotes or order confirmations into the stream.",
                "Switch to wss:// and make sure the server enforces TLS (no downgrade); treat this exactly like the cleartext-HTTP finding.",
                it.range.first, "CWE-319"))
        }

        // 3b. a WebSocket client (OkHttp) built with no Authorization/token header set on the originating Request nearby
        if (ctx.scope == SecurityScanner.Scope.APP) {
            for (m in rx("Lokhttp3/OkHttpClient;->newWebSocket\\(").findAll(text)) {
                val window = text.substring(maxOf(0, m.range.first - 500), m.range.first)
                val authed = window.contains("Lokhttp3/Request\$Builder;->addHeader(") || window.contains("Lokhttp3/Request\$Builder;->header(")
                if (authed) continue
                out.add(ctx.finding(Severity.LOW, "WebSocket opened with no auth header on the handshake request",
                    "newWebSocket() is called with no Request.Builder.addHeader()/header() call found in the preceding lines of this method. " +
                        "If the server identifies the client by a cookie/token set once at login rather than per-connection, a stolen session " +
                        "value could open the same live feed or order channel from elsewhere undetected.",
                    "Confirm the socket's Authorization/token header (or equivalent handshake auth) is actually set - either here or by an " +
                        "interceptor on the OkHttpClient - and that the server re-validates it, not just on initial login.",
                    m.range.first, "CWE-319"))
            }
        }
        return out
    }
}

/** 4. An exported-looking component reads an Intent extra straight into a method whose name looks like it moves money. */
object ExportedSensitiveActionRule : ScanRule {
    override val id = "fintech-exported-sensitive-action"
    override val title = "Intent extra reaches a trade/transfer-like call with no visible authorization check"
    override val cwes = listOf("CWE-926")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val text = ctx.text
        // Only classes that look like components (Activity/Service/BroadcastReceiver) are in scope - IPC entry points.
        if (!rx("\\.super L(?:[\\w/]*?/)?(?:Activity|AppCompatActivity|Service|IntentService|BroadcastReceiver);").containsMatchIn(text) &&
            !rx("\\.implements Landroid/content/BroadcastReceiver;").containsMatchIn(text)) return emptyList()

        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(text)) {
            val extra = rx("Landroid/content/Intent;->get(?:String|Int|Double|Float|Long)Extra\\(").find(m.body) ?: continue
            val after = m.body.substring(extra.range.first)
            // a sink call whose own method NAME looks financial, invoked after the extra is read, with no visible permission/auth gate in between
            val sink = rx("->((?:[A-Za-z_$]*(?:" + financialActionWords.pattern + ")[A-Za-z_$]*))\\(").find(after) ?: continue
            val between = after.substring(0, sink.range.first)
            val gated = rx("->(checkCallingPermission|checkSelfPermission|checkCallingOrSelfPermission|authenticate|getCallingUid|getCallingPackage)\\(").containsMatchIn(between)
            if (gated) continue
            // 2.0.1 (WE Wallet StartupActivity, the launcher, device report): the rule sees a financial-sounding NAME after an Intent read in the same method and
            // traces no value between them (confidence MEDIUM, "a rule's pattern match, no data flow traced"). A pattern match is a lead: MEDIUM, never HIGH.
            out.add(ctx.finding(Severity.MEDIUM, title,
                "This component reads an Intent extra and, later in the same method, calls ${sink.groupValues[1]}() with nothing in between that checks the " +
                    "caller (no checkCallingPermission/checkSelfPermission/getCallingUid/biometric re-auth); no value was traced from the extra into that call, " +
                    "so it can be an ordinary router. If this activity, service or " +
                    "receiver is exported (check android:exported / its intent-filter in the manifest), any app on the device can start it and " +
                    "drive a financial action - a classic deep-link/IPC trade-execution abuse pattern.",
                "Confirm whether this component is actually exported. If it must be, re-validate the caller (signature permission, " +
                    "getCallingUid()/getCallingPackage() allow-list, or a fresh biometric/step-up prompt) before acting on any extra that can " +
                    "trigger a trade, transfer, or withdrawal - never trust the Intent's contents by themselves.",
                m.start + sink.range.first, "CWE-926"))
        }
        return out
    }
}

/** 5. Frida / dynamic-instrumentation detection logic (maturity signal, informational - same family as AndroGoat's root/emulator checks). */
object FridaDetectionRule : ScanRule {
    override val id = "fintech-frida-detection"
    override val title = "Frida / instrumentation detection logic (client-side)"
    override val cwes = listOf("CWE-693")
    override val confidence = "HIGH"

    // ports/names/markers Frida and common hooking frameworks leave behind.
    private val markers = listOf(
        "frida-server", "frida-agent", "frida-gadget", "FRIDA", "re.frida.server",
        "27042", "27043",                                   // default frida-server / gdb-style listener ports
        "/data/local/tmp/frida", "linjector", "XposedBridge", "de.robv.android.xposed",
        "libfridagadget.so", "gum-js-loop", "LIBFRIDA"
    )

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val text = ctx.text
        val hit = markers.firstOrNull { text.contains(it) } ?: run {
            // generic pattern: scanning /proc/<pid>/maps or iterating TCP ports to look for a hooking agent
            if (text.contains("/proc/self/maps") && rx("(?i)port|socket").containsMatchIn(text)) "/proc/self/maps + port scan" else null
        } ?: return emptyList()
        return listOf(ctx.finding(Severity.INFO, title,
            "The class checks for instrumentation/hooking tooling (matched on \"$hit\"). This raises the app's threat-model maturity " +
                "(it is actively trying to detect Frida/Xposed-style dynamic analysis), but like the root/emulator checks already flagged " +
                "elsewhere, any purely client-side detection can be hooked or patched out by the same tooling it is trying to detect.",
            "Treat this as one layer, not a guarantee: pair it with server-side attestation (Play Integrity API) for anything that gates " +
                "money movement, and avoid storing the detection result in a single easily-patched boolean.",
            text.indexOf(hit), "CWE-693"))
    }
}
