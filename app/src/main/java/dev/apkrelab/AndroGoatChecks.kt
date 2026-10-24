package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Scope
import dev.apkrelab.SecurityScanner.Severity

/**
 * 0.33.0 - checks added while benchmarking the scanner against OWASP MASTG-APP-0001 (AndroGoat).
 * Defensive/educational: every finding explains the weakness and how to fix it. Pattern based (smali text),
 * so results are leads to verify, not proof. See tools/androgoat/ for the expected-findings list.
 */
object AndroGoatChecks {

    private val credWords = setOf(
        "password", "passwd", "pwd", "pin", "otp", "token", "secret", "apikey", "credential", "credentials",
        "session", "sessionid", "cvv", "ssn", "creditcard", "cardnumber", "username"
    )

    private class SecretRule(val title: String, val re: Regex, val sev: Severity, val rec: String)

    private val keyRec = "Remove the secret from the APK, rotate it (it must be treated as leaked), and keep it on a server you control; the app should call your backend instead."
    private val secretRules = listOf(
        SecretRule("Anthropic API key embedded", rx("sk-ant-[A-Za-z0-9_-]{20,}"), Severity.HIGH, keyRec),
        SecretRule("OpenAI API key embedded", rx("sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"), Severity.HIGH, keyRec),
        SecretRule("Hugging Face token embedded", rx("hf_[A-Za-z0-9]{30,}"), Severity.HIGH, keyRec),
        SecretRule("AWS access key ID embedded", rx("AKIA[0-9A-Z]{16}"), Severity.HIGH, keyRec),
        SecretRule("GitHub token embedded", rx("gh[pousr]_[A-Za-z0-9]{36,}"), Severity.HIGH, keyRec),
        SecretRule("Slack token embedded", rx("xox[baprs]-[A-Za-z0-9-]{10,}"), Severity.HIGH, keyRec),
        SecretRule("Stripe live secret key embedded", rx("sk_live_[A-Za-z0-9]{16,}"), Severity.CRITICAL, keyRec),
        SecretRule("Private key embedded", rx("-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----(?:\\\\[rn]|\\s)*[A-Za-z0-9+/]{40,}"), Severity.CRITICAL, keyRec),   // 0.76.0: header + body, not a parser's header
        SecretRule("Azure storage account key embedded", rx("AccountKey=[A-Za-z0-9+/=]{40,}"), Severity.HIGH, keyRec),
        SecretRule("SendGrid API key embedded", rx("SG\\.[A-Za-z0-9_-]{22}\\.[A-Za-z0-9_-]{43}"), Severity.HIGH, keyRec),
        SecretRule("GitLab access token embedded", rx("glpat-[A-Za-z0-9_-]{20}"), Severity.HIGH, keyRec),
        SecretRule("FCM legacy server key embedded", rx("AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{100,}"), Severity.CRITICAL, keyRec),
        SecretRule("Mapbox secret token embedded", rx("sk\\.eyJ[A-Za-z0-9_-]{20,}\\.[A-Za-z0-9_-]{20,}"), Severity.HIGH, keyRec),
        SecretRule("Shopify access token embedded", rx("shp(?:at|ca|pa|ss)_[0-9a-f]{32}"), Severity.HIGH, keyRec),
        SecretRule("Square access token embedded", rx("sq0(?:atp|csp)-[A-Za-z0-9_-]{22,}"), Severity.HIGH, keyRec),
        SecretRule("Google OAuth client secret embedded", rx("GOCSPX-[A-Za-z0-9_-]{28}"), Severity.HIGH, keyRec),
        SecretRule("Twilio API key embedded", rx("\\bSK[0-9a-f]{32}\\b"), Severity.HIGH, keyRec),
        SecretRule("npm access token embedded", rx("npm_[A-Za-z0-9]{36}"), Severity.HIGH, keyRec),
        SecretRule("Discord webhook URL embedded", rx("discord(?:app)?\\.com/api/webhooks/\\d{15,}/[A-Za-z0-9_-]{30,}"), Severity.MEDIUM,
            "Anyone with this URL can post to your channel. Delete the webhook and send messages from your server instead."),
        SecretRule("Slack webhook URL embedded", rx("hooks\\.slack\\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}"), Severity.MEDIUM,
            "Anyone with this URL can post to your workspace. Revoke the webhook and send messages from your server instead."),
        SecretRule("Hardcoded HTTP Basic credentials", rx("^Basic [A-Za-z0-9+/]{16,}={0,2}$"), Severity.MEDIUM,
            "Base64 is not encryption: it decodes to user:password. Remove it, rotate that password, and authenticate with a per-user token from your backend."),
        SecretRule(
            "Firebase Realtime Database URL", rx("[A-Za-z0-9.-]*(?:firebaseio\\.com|firebasedatabase\\.app)"), Severity.MEDIUM,
            "Open this URL + \"/.json\" from a test device you own: if it returns data, the database rules allow public reads. Lock the rules down (auth != null) and require authentication."
        ),
        SecretRule(
            "Cloud storage bucket URL (S3/GCS)", rx("[a-z0-9.-]+\\.s3[.-][a-z0-9.-]*amazonaws\\.com|storage\\.googleapis\\.com/[a-z0-9._-]+"), Severity.MEDIUM,
            "Check the bucket's ACL/policy: it must not allow public listing or writes. Use pre-signed URLs from your backend."
        )
    )

    /** Filled by MainActivity.scanResourcesAsync: what the resource scan saw (shown in the AndroGoat check dialog). */
    @Volatile var resStats: String = "not run yet"

    private val credStrictRe = rx("(?i)\\b(password|passwd|pwd|token|secret|api[_ ]?key|credential|username|user name|credit|card number|cvv|ssn)")
    private val shortLiteralRe = rx("const-string(?:/jumbo)?\\s+[vp]\\d+,\\s*\"([^\"\\n]{1,200})\"")

    private val literalRe = rx("const-string(?:/jumbo)?\\s+[vp]\\d+,\\s*\"([^\"\\n]{8,400})\"")

    private fun mask(s: String): String = s.take(6) + "..." + " (" + s.length + " chars)"

    fun scan(classType: String, clsIndex: Int, text: String, appPkg: String): List<Finding> {
        val out = ArrayList<Finding>()
        val scope = SecurityScanner.scopeOf(classType, appPkg)
        fun add(sev: Severity, title: String, detail: String, rec: String, offset: Int, cwe: String) {
            val at = if (offset < 0) 0 else offset
            out.add(Finding(sev, title, detail + "  (around line ${SecurityScanner.lineNo(text, at)})", rec, classType, clsIndex, at, cwe))
        }

        // --- Insecure data storage: SharedPreferences / SQLite / temp files ---
        for (m in rx("Landroid/content/SharedPreferences\\\$Editor;->putString\\(").findAll(text)) {
            if (SecurityScanner.contextHas(text, m.range.first, m.range.last + 1, credWords)) {
                add(Severity.MEDIUM, "Sensitive value saved to SharedPreferences (plaintext)",
                    "putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.",
                    "Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.",
                    m.range.first, "CWE-312")
                break
            }
        }
        if (text.contains("Landroid/database/sqlite/SQLiteDatabase;->insert") || text.contains("Landroid/database/sqlite/SQLiteDatabase;->execSQL")) {
            for (m in rx("Landroid/content/ContentValues;->put\\(").findAll(text)) {
                if (SecurityScanner.contextHas(text, m.range.first, m.range.last + 1, credWords)) {
                    add(Severity.MEDIUM, "Sensitive value written to SQLite (plaintext)",
                        "A credential-like value is put into ContentValues that feed an SQLite insert. The .db file is unencrypted and readable on rooted devices or from a backup.",
                        "Encrypt sensitive columns (or use SQLCipher) and avoid keeping passwords at all; store only a hash or a revocable token.",
                        m.range.first, "CWE-312")
                    break
                }
            }
        }
        rx("Ljava/io/File;->createTempFile\\(").find(text)?.let {
            val hot = SecurityScanner.contextHas(text, it.range.first, it.range.last + 1, credWords)
            add(if (hot) Severity.MEDIUM else Severity.LOW, "Temp file created",
                "The app creates a temp file" + (if (hot) " near credential-like names" else "") +
                    ". If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.",
                "Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.",
                it.range.first, "CWE-377")
        }

        // --- 0.34.0: wider storage / logging / SQL checks ---
        if (text.contains("Landroid/database/sqlite/SQLiteDatabase;->")) {
            for (lit in shortLiteralRe.findAll(text)) {
                val sl = lit.groupValues[1].lowercase()
                // 0.75.2 (Allsafe NoteDatabaseHelper FP): only the COLUMN part is checked, never the VALUES text of an INSERT
                val cols = sqlColumnPart(sl)
                if ((sl.contains("insert into") || sl.contains("create table")) && cols != null && credStrictRe.containsMatchIn(cols)) {
                    add(Severity.MEDIUM, "Sensitive value written to SQLite (plaintext)",
                        "An SQL statement in this class creates or fills a table with a credential-like column. SQLite files are unencrypted and readable on rooted devices or from a backup.",
                        "Do not store passwords in SQLite; if you must keep sensitive columns use SQLCipher or encrypt the values with a Keystore key.",
                        lit.range.first, "CWE-312")
                    break
                }
            }
        }
        var logHit = false
        for (m in rx("Landroid/util/Log;->[dwiev]\\(").findAll(text)) {
            if (logHit) break
            val win = text.substring(maxOf(0, m.range.first - 900), m.range.first)
            for (lit in shortLiteralRe.findAll(win)) {
                val sl = lit.groupValues[1]
                if (sl.length < 80 && credStrictRe.containsMatchIn(sl) && win.substring(lit.range.last).contains("->append(")) {
                    add(Severity.MEDIUM, "Sensitive value written to log",
                        "A log call is built from a credential-like label (\"${sl.take(30)}\") plus an appended variable. Logcat can be read from a computer over ADB, and by other apps on some devices.",
                        "Never log passwords, tokens, or personal data; strip such Log calls from release builds.",
                        m.range.first, "CWE-532")
                    logHit = true
                    break
                }
            }
        }
        if (text.contains("Landroid/widget/EditText;->getText") || text.contains("->getStringExtra(")) {
            for (m in rx("Landroid/database/sqlite/SQLiteDatabase;->(rawQuery|execSQL)\\(").findAll(text)) {
                val win = text.substring(maxOf(0, m.range.first - 1200), m.range.first)
                if (win.contains("->append(") || win.contains("Ljava/lang/String;->format(") ||
                    win.contains("Ljava/lang/String;->concat(") || win.contains("stringPlus")) {
                    add(Severity.MEDIUM, "Possible SQL built from UI input (string concatenation)",
                        "This class reads text from an input field (or an Intent extra) and also runs rawQuery/execSQL after building a string. If the text goes into the SQL, a quote character can change the query (SQL injection).",
                        "Use parameterized queries (? placeholders with selectionArgs / bindArgs) and never put user text into the SQL string.",
                        m.range.first, "CWE-89")
                    break
                }
            }
        }

        // --- Clipboard ---
        rx("Landroid/content/ClipboardManager;->setPrimaryClip\\(").find(text)?.let {
            val hot = SecurityScanner.contextHas(text, it.range.first, it.range.last + 1, credWords)
            add(if (hot) Severity.MEDIUM else Severity.LOW, "Data copied to clipboard",
                "The app puts data on the system clipboard" + (if (hot) " close to credential-like names" else "") +
                    ". On many Android versions other apps can read the clipboard (and clipboard managers keep a history).",
                "Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.",
                it.range.first, "CWE-200")
        }

        // --- Biometric ---
        rx("Landroidx/biometric/BiometricPrompt;->authenticate\\(Landroidx/biometric/BiometricPrompt\\\$PromptInfo;\\)V").find(text)?.let {
            add(Severity.MEDIUM, "Biometric prompt without CryptoObject",
                "authenticate(PromptInfo) is used without a CryptoObject, so the result is just a boolean callback. Anyone who can hook or patch the callback (Frida, smali patching) can fake a successful login.",
                "Bind the biometric check to a Keystore key (setUserAuthenticationRequired(true)) and use authenticate(PromptInfo, CryptoObject), so the secret can only be unlocked by a real authentication.",
                it.range.first, "CWE-287")
        }

        // --- Certificate pinning (OkHttp) ---
        if (scope == Scope.APP) {
            if (text.contains("Lokhttp3/CertificatePinner\$Builder;->add(")) {
                val at = text.indexOf("Lokhttp3/CertificatePinner\$Builder;->add(")
                add(Severity.INFO, "Certificate pinning present (OkHttp CertificatePinner)",
                    "This class pins certificates with OkHttp. Good, but client-side pinning can still be bypassed (Frida, patched smali), so it is a hurdle rather than a guarantee.",
                    "Keep pins for a backup key too, plan pin rotation, and never rely on pinning alone to protect secrets.",
                    at, "CWE-295")
            } else if (text.contains("Lokhttp3/OkHttpClient\$Builder;->build()")) {
                add(Severity.LOW, "HTTP client built without certificate pinning",
                    "An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).",
                    "For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).",
                    text.indexOf("Lokhttp3/OkHttpClient\$Builder;->build()"), "CWE-295")
            }
        }

        // --- Hardcoded secrets (AI / cloud / generic) ---
        val seen = HashSet<String>()
        for (lm in (if (scope == Scope.LIB) emptySequence() else literalRe.findAll(text))) {
            val lit = lm.groupValues[1]
            for (r in secretRules) {
                if (r.title in seen) continue
                val hit = r.re.find(lit) ?: continue
                if (SecretFilters.isPlaceholder(hit.value)) continue   // 0.85.2 (Feeder: sk-test_XXXX... in a Compose preview)
                seen.add(r.title)
                add(r.sev, r.title,
                    "A string literal matches this pattern (${mask(hit.value)}). Anything inside the APK can be extracted by anyone who downloads it.",
                    r.rec, lm.range.first, if (r.title.startsWith("Firebase") || r.title.startsWith("Cloud")) "CWE-284" else "CWE-798")
                break
            }
        }

        // --- 0.35.1: Firebase Realtime Database / Firestore SDK usage (misconfiguration risk) ---
        // Separate from the secretRules "Firebase Realtime Database URL" pattern above: that one only fires when the
        // literal firebaseio.com/firebasedatabase.app URL is found as a string. This check instead keys off the SDK
        // calls themselves, so it still catches the case the owner hit (the URL isn't a plain string anywhere the
        // scanner looked at - maybe built from google-services.json's generated resource, split into pieces, or the
        // project no longer embeds a live URL) - misconfigured Firebase rules are one of the most common real-world
        // mobile backend bugs (HospitalGown/Comparitech studies found tens of thousands of exposed apps), so "the SDK
        // is here, go check its rules" is still worth flagging even without a URL in hand.
        if (scope != Scope.LIB) {
            val fbType = rx("Lcom/google/firebase/database/FirebaseDatabase;|Lcom/google/firebase/firestore/FirebaseFirestore;").find(text)
            if (fbType != null) {
                val isFirestore = fbType.value.contains("firestore")
                var urlLit: String? = null
                for (lm in literalRe.findAll(text)) {
                    val lit = lm.groupValues[1]
                    if (lit.contains("firebaseio.com") || lit.contains("firebasedatabase.app")) { urlLit = lit; break }
                }
                if (urlLit != null) {
                    add(Severity.MEDIUM, "Firebase Realtime Database URL in code",
                        "This class uses the Firebase SDK with a Realtime Database URL embedded as a string literal (${mask(urlLit)}). Misconfigured Firebase security rules (left in public \"test mode\", or a blanket \".read\"/\".write\": true) are one of the most common real-world mobile-backend vulnerabilities - anyone with this URL can read/write the database directly, bypassing the app and any client-side checks entirely.",
                        "From a browser you control, open \"$urlLit/.json\": if it returns data (or \"null\" instead of \"Permission denied\") with no login, the rules are public. Require auth != null (or a stricter per-field rule) in the Firebase console, and never rely on the app's own logic for access control.",
                        fbType.range.first, "CWE-284")
                } else {
                    add(Severity.LOW, if (isFirestore) "Firebase Firestore SDK used" else "Firebase Realtime Database SDK used",
                        "This class initializes/uses the Firebase ${if (isFirestore) "Firestore" else "Realtime Database"} SDK. No literal database URL turned up nearby in this class (it may come from google-services.json's generated resources, a remote config, or a different class) - but the app does talk to a Firebase backend, so its security rules matter just as much as if the URL were visible here.",
                        "Confirm the project's rules require authentication rather than the default public \"test mode\" (which Firebase itself only allows temporarily, but is often left in place). " +
                            (if (isFirestore) "Review the Firestore rules in the Firebase console (each collection, not just the root)." else "Try https://<project-id>-default-rtdb.<region>.firebasedatabase.app/.json (or the older https://<project>.firebaseio.com/.json) from outside the app: data returned with no login means the rules are public."),
                        fbType.range.first, "CWE-284")
                }
            }
        }

        // --- Client-side protections (informational: they are bypassable) ---
        if (scope != Scope.LIB) {
            val rootKey = listOf("/system/bin/su", "/system/xbin/su", "/sbin/su", "com.topjohnwu.magisk", "eu.chainfire.supersu", "Superuser.apk", "test-keys")
                .firstOrNull { text.contains(it) }
            if (rootKey != null) {
                add(Severity.INFO, "Root detection logic (client-side)",
                    "The class looks for root indicators (\"$rootKey\"). Client-side root checks can be bypassed by hooking or patching the method, so they only slow an attacker down.",
                    "Treat it as one layer: add server-side checks (Play Integrity API) and do not keep secrets on the device.",
                    text.indexOf(rootKey), "CWE-693")
            }
            val emuKey = listOf("goldfish", "ranchu", "sdk_gphone", "Genymotion", "generic_x86", "google_sdk").firstOrNull { text.contains(it) }
            if (emuKey != null) {
                add(Severity.INFO, "Emulator detection logic (client-side)",
                    "The class compares device properties against emulator markers (\"$emuKey\"). Attackers can spoof Build.* values or patch the check.",
                    "Use Play Integrity API verdicts checked on your server instead of trusting a local boolean.",
                    text.indexOf(emuKey), "CWE-693")
            }
            if (text.contains("Landroid/content/pm/PackageManager;->getPackageInfo") &&
                (text.contains("getSigningInfo") || text.contains("Landroid/content/pm/Signature;"))) {
                add(Severity.INFO, "Client-side integrity/signature check",
                    "The app reads its own signing certificate, probably to detect a repackaged/patched build. This check is itself in the APK, so a patcher can remove it (that is exactly what Binary Patching exercises do).",
                    "Verify integrity on the server (Play Integrity API) and keep the check out of a single easy-to-patch method.",
                    text.indexOf("Landroid/content/pm/PackageManager;->getPackageInfo"), "CWE-353")
            }
        }

        // --- WebView XSS ---
        if (scope == Scope.APP) {
            var jsOn = -1
            for (m in rx("Landroid/webkit/WebSettings;->setJavaScriptEnabled\\(Z\\)V").findAll(text)) {
                if (SecurityScanner.argNumber(text, m.range.first, 1) == 1L) { jsOn = m.range.first; break }
            }
            if (jsOn >= 0) {
                var dynamic = -1
                for (m in rx("Landroid/webkit/WebView;->(loadUrl|loadData|loadDataWithBaseURL|evaluateJavascript)\\(").findAll(text)) {
                    val from = maxOf(0, m.range.first - 400)
                    if (text.substring(from, m.range.first).contains("Ljava/lang/StringBuilder;->append")) { dynamic = m.range.first; break }
                }
                if (dynamic >= 0) {
                    add(Severity.MEDIUM, "WebView loads dynamically built content (XSS risk)",
                        "JavaScript is enabled and the WebView is fed a string built with StringBuilder (concatenation). If a part of it comes from user input, an Intent, or a server, script can be injected (XSS).",
                        "Encode/escape untrusted values, avoid building HTML or javascript: URLs from input, and load only fixed https:// pages.",
                        dynamic, "CWE-79")
                } else {
                    add(Severity.LOW, "WebView JavaScript enabled",
                        "setJavaScriptEnabled(true) widens the attack surface of every page this WebView loads.",
                        "Enable it only if needed and only for trusted https:// origins.",
                        jsOn, "CWE-79")
                }
            }

            // --- QR / barcode input ---
            val qr = rx("Lcom/google/zxing/|Lcom/journeyapps/barcodescanner/|Lcom/google/mlkit/vision/barcode/|Lcom/google/android/gms/vision/barcode/").find(text)
            if (qr != null) {
                val sink = rx("Landroid/webkit/WebView;->loadUrl\\(|->rawQuery\\(|->execSQL\\(|Ljava/lang/Runtime;->exec\\(|Landroid/content/Intent;->parseUri\\(|Landroid/content/Context;->startActivity\\(").find(text)
                if (sink != null) {
                    add(Severity.MEDIUM, "QR/barcode input reaches a sensitive sink",
                        "This class scans QR/barcodes and also calls a sensitive API (${sink.value.trim('(')}). A malicious QR code is attacker-controlled input; if it is used unvalidated, it can open arbitrary URLs/intents or inject SQL/commands.",
                        "Treat the scanned text as untrusted: validate scheme/host against an allow-list, never pass it straight to WebView/Intent/SQL.",
                        sink.range.first, "CWE-20")
                } else {
                    add(Severity.INFO, "QR/barcode scanning",
                        "The class reads QR/barcode content. Check where the scanned value is used afterwards.",
                        "Validate the scanned content before using it.", qr.range.first, "CWE-20")
                }
            }
        }

        // --- ContentProvider path traversal ---
        if (text.contains(".super Landroid/content/ContentProvider;") &&
            text.contains(".method public openFile(") && !text.contains("getCanonicalPath")) {
            add(Severity.MEDIUM, "ContentProvider.openFile without path canonicalisation",
                "This provider implements openFile() but never canonicalises the requested path. A caller can try ../ segments to reach files outside the intended folder (path traversal).",
                "Resolve the file with getCanonicalPath() and check it starts with the allowed base directory before opening it.",
                text.indexOf(".method public openFile("), "CWE-22")
        }
        return out
    }

    // ---------- resources (decoded XML): network security config + layouts ----------

    private fun inputIsSafe(v: String): Boolean {
        if (v.contains("assword") || v.contains("NoSuggestions")) return true
        val n = if (v.startsWith("0x")) v.removePrefix("0x").toIntOrNull(16) else v.toIntOrNull()
        if (n == null) return false
        val cls = n and 0xF
        val variation = n and 0xFF0
        return (cls == 1 && (variation == 0x80 || variation == 0x90 || variation == 0xE0)) ||
            (cls == 2 && variation == 0x10) || (n and 0x80000) != 0
    }

    /** 0.75.2: column list of "create table t (...)" / "insert into t (cols) values (...)" (lower-case text), or null when there is none. */
    internal fun sqlColumnPart(sl: String): String? {
        val lp = sl.indexOf('(')
        if (lp < 0) return null
        if (sl.contains("insert into")) {
            val vi = sl.indexOf("values")
            if (vi in 0 until lp) return null
            val rp = sl.indexOf(')', lp)
            return if (rp > lp) sl.substring(lp + 1, rp) else null
        }
        val rp = sl.lastIndexOf(')')
        return if (rp > lp) sl.substring(lp + 1, rp) else sl.substring(lp + 1)
    }

    fun scanResourceXml(path: String, xml: String): List<Finding> {
        val out = ArrayList<Finding>()
        fun add(sev: Severity, title: String, detail: String, rec: String, cwe: String, rule: String = "") {
            val f = Finding(sev, title, detail + "  [$path]", rec, null, -1, -1, cwe, path)
            if (rule.isNotEmpty()) f.ruleId = rule
            out.add(f)
        }
        // 0.43.0: the network_security_config.xml checks moved to ScanRulesResources.kt (res-nsc-* rules, same titles). ResourceScanner calls this function
        // for the two layout checks below only.
        if (xml.contains("EditText")) {
            val fields = rx("<[A-Za-z0-9_.]*EditText\\b[^>]*>").findAll(xml).toList()
            for (m in fields) {
                val tag = m.value
                val idRaw = rx("android:id\\s*=\\s*\"([^\"]*)\"").find(tag)?.groupValues?.get(1) ?: ""
                val idName = idRaw.substringAfterLast('/')
                val hint = rx("android:hint\\s*=\\s*\"([^\"]*)\"").find(tag)?.groupValues?.get(1) ?: ""
                val unresolved = idName.isEmpty() || idName.matches(rx("(0x)?[0-9a-fA-F]{6,8}"))
                val w = (idName + " " + hint).replace(rx("([a-z0-9])([A-Z])"), "\$1 \$2").split(rx("[^A-Za-z0-9]+")).map { it.lowercase() }
                val sensitive = w.any { it in credWords } || w.joinToString("").let { j2 -> credWords.any { c -> c.length > 4 && j2.contains(c) } }
                if (!sensitive && !(unresolved && fields.size <= 2)) continue
                val inputType = rx("android:inputType\\s*=\\s*\"([^\"]*)\"").find(tag)?.groupValues?.get(1)
                if (inputType != null && inputIsSafe(inputType)) continue
                val shown = if (unresolved) "(id not resolved)" else idName
                add(Severity.LOW, "Keyboard cache: sensitive input field",
                    "The field \"$shown\" looks sensitive or is the main input of this screen, but its inputType (${inputType ?: "not set"}) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).",
                    "Use android:inputType=\"textPassword\" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill=\"no\" for secrets.", "CWE-524")
                break
            }
        }
        if (xml.contains("<paths")) {
            var rank = 0
            val bad = ArrayList<String>()
            for (m in rx("<(root-path|external-path|external-files-path|external-cache-path|external-media-path|files-path|cache-path)\\b[^>]*>").findAll(xml)) {
                val kind = m.groupValues[1]
                val p = rx("\\bpath\\s*=\\s*\"([^\"]*)\"").find(m.value)?.groupValues?.get(1) ?: ""
                val broad = p == "" || p == "." || p == "/"
                val r = when {
                    kind == "root-path" -> 2
                    broad && (kind == "files-path" || kind == "cache-path" || kind == "external-files-path") -> 2
                    broad -> 1
                    else -> 0
                }
                if (r == 0) continue
                if (r > rank) rank = r
                bad.add("<" + kind + " path=\"" + p + "\">")
            }
            if (rank > 0) {
                add(if (rank >= 2) Severity.MEDIUM else Severity.LOW, "FileProvider shares too much (" + bad.take(3).joinToString(", ") + ")",
                    "These FileProvider paths cover a whole directory tree (" + (if (rank >= 2) "the root of the file system or the app's private data: databases, shared_prefs, tokens" else "all of shared storage") +
                        "). Any content:// URI the app hands out, or lets a caller choose, can then point at files that were never meant to be shared.",
                    "List only the specific sub-folder to share (for example path=\"shared/\"), never root-path or path=\".\", and keep the provider exported=\"false\" with grantUriPermissions=\"true\".", "CWE-200", "res-fileprovider-paths")
            }
        }
        return out
    }

    /** 0.34.0: strings compiled into resources.arsc (Firebase URL, Google API key and similar live there, not in the dex code). */
    fun scanArsc(b: ByteArray): List<Finding> {
        val out = ArrayList<Finding>()
        val texts = listOf(String(b, Charsets.ISO_8859_1), String(b, Charsets.UTF_16LE))
        val seen = HashSet<String>()
        for (tx in texts) {
            for (r in secretRules) {
                if (r.title in seen) continue
                val hit = r.re.find(tx) ?: continue
                if (SecretFilters.isPlaceholder(hit.value)) continue   // 0.85.2
                seen.add(r.title)
                out.add(Finding(r.sev, r.title,
                    "Found in the compiled resources (${mask(hit.value)}). App resources are readable by anyone who unpacks the APK.  [resources.arsc]",
                    r.rec, null, -1, -1, if (r.title.startsWith("Firebase") || r.title.startsWith("Cloud")) "CWE-284" else "CWE-798", "resources.arsc"))
            }
            if ("Google API key in resources" !in seen) {
                val g = rx("AIza[0-9A-Za-z_-]{35}").find(tx)
                if (g != null) {
                    seen.add("Google API key in resources")
                    out.add(Finding(Severity.MEDIUM, "Google API key in resources",
                        "A Google API key (${mask(g.value)}) is compiled into resources.arsc. Restrict the key in the Google Cloud console (package name + SHA-1, only the APIs you use).  [resources.arsc]",
                        "Restrict the key to this app and to specific APIs, and monitor its usage.", null, -1, -1, "CWE-798", "resources.arsc"))
                }
            }
        }
        return out
    }

    // ---------- AndroGoat benchmark (0.33.1): name -> title fragments that count as "caught" ----------
    private val expected = listOf(
        "Root Detection" to listOf("Root detection"),
        "Emulator Detection" to listOf("Emulator detection"),
        "Shared Prefs (1+2)" to listOf("SharedPreferences"),
        "SQLite storage" to listOf("SQLite"),
        "Temp Files" to listOf("Temp file"),
        "SD Card" to listOf("Shared external storage"),
        "Keyboard Cache" to listOf("Keyboard cache"),
        "Insecure Logging" to listOf("sensitive data in logs", "written to log"),
        "XSS" to listOf("dynamically built content", "JavaScript enabled"),
        "SQLi" to listOf("SQL built by string", "SQL built from"),
        "WebView" to listOf("WebView"),
        "QR Code" to listOf("QR/barcode"),
        "Exported Activity" to listOf("Exported activity"),
        "Exported Service" to listOf("Exported service"),
        "Exported Receiver" to listOf("Exported receiver"),
        "Content Provider" to listOf("Exported provider", "ContentProvider"),
        "Clipboard" to listOf("clipboard"),
        "Hardcoding - AI" to listOf("OpenAI", "Anthropic", "Hugging Face", "API key"),
        "Hardcoding - Cloud" to listOf("AWS", "Firebase", "bucket", "Azure"),
        "Network - HTTP" to listOf("leartext"),
        "Network - HTTPS (user CAs)" to listOf("user-installed CA", "No network security config"),
        "Pinning - OkHttp3" to listOf("certificate pinning"),
        "Pinning - NSC" to listOf("pin-set", "Network Security Config"),
        "Misconfigured NSC" to listOf("Network Security Config"),
        "Debuggable" to listOf("Debuggable"),
        "allowBackup" to listOf("allowBackup"),
        "Custom URL Scheme" to listOf("Deep link"),
        "Broken Crypto" to listOf("Weak", "Hardcoded encryption key", "Static IV"),
        "Firebase DB" to listOf("Firebase"),
        "Biometric" to listOf("Biometric")
    )

    /** Returns (summary, text). [titles] = titles of all current findings. Shopping Cart hardcoding is AI-only (Smart scan). */
    fun benchmark(titles: List<String>): Pair<String, String> {
        val all = titles.joinToString("\n").lowercase()
        val sb = StringBuilder()
        var ok = 0
        for ((name, keys) in expected) {
            val hit = keys.any { all.contains(it.lowercase()) }
            if (hit) ok++
            sb.append(if (hit) "OK    " else "MISS  ").append(name).append('\n')
        }
        sb.append("\nAI only (Smart scan): Shopping Cart hardcoding, Binary Patching\n")
        sb.append("Loose matches (e.g. WebView): confirm the finding is in the AndroGoat class.\n")
        sb.append("\nRes scan: ").append(resStats)
        return Pair("$ok/${expected.size} covered", sb.toString())
    }
}
