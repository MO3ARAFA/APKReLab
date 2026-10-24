package dev.apkrelab

/**
 * 0.40.0: educational knowledge base. One [Entry] per CWE that the scanner can emit.
 * It turns a bare finding into: name -> severity -> risk scenario -> vulnerable vs secure code -> references.
 *
 * How to extend: add one `put(Entry(...))` line in [init]. A CWE without an entry still gets a generic card
 * (CWE link + OWASP index), so a new scanner rule never breaks the report.
 *
 * Text rules: plain strings, no dollar sign and no triple quotes inside raw strings (they are Kotlin raw strings).
 * Links are built from stable patterns only (cwe.mitre.org/data/definitions/N.html, OWASP index pages, cheat sheets).
 */
object VulnKnowledge {

    class Entry(
        val cwe: String,                 // "CWE-798"
        val name: String,                // official CWE name
        val owasp: String,               // OWASP Mobile Top 10 (2024) category
        val masvs: String,               // OWASP MASVS v2 group
        val scenario: String,            // what an attacker can do (short, concrete)
        val bad: String = "",            // vulnerable Kotlin/XML sample
        val good: String = "",           // fixed sample
        val cheatSheets: List<String> = emptyList() // OWASP Cheat Sheet names, e.g. "SQL_Injection_Prevention_Cheat_Sheet"
    )

    private val map = HashMap<String, Entry>()

    fun put(e: Entry) { map[e.cwe] = e }

    fun forCwe(cwe: String): Entry? = map[cwe.trim().uppercase()]

    /** 0.66.4: the CWE-327 card talks about DES / RC4 / ECB; the TLS protocol rule gets its own text. */
    private val tlsProtocolEntry = Entry("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", "M10 Insufficient Cryptography", "MASVS-CRYPTO",
        "A network attacker can push the connection down to SSLv3 / TLSv1.0 / TLSv1.1, which have known attacks, and read or change the traffic.",
        "SSLContext.getInstance(\"TLSv1\")",
        "SSLContext.getInstance(\"TLSv1.3\")   // or omit the protocol and use the platform default on modern Android",
        listOf("Transport_Layer_Security_Cheat_Sheet"))

    fun forFinding(f: SecurityScanner.Finding): Entry? =
        if (f.ruleId == "tls-protocol-version") tlsProtocolEntry else if (f.cwe.isBlank()) null else forCwe(f.cwe)

    /** (label, url) pairs for one finding: the CWE page, the OWASP index pages and the matching cheat sheets. */
    fun references(cwe: String): List<Pair<String, String>> {
        val out = ArrayList<Pair<String, String>>()
        val num = cwe.trim().uppercase().removePrefix("CWE-")
        if (num.isNotEmpty() && num.all { it.isDigit() }) {
            out.add("${cwe.trim().uppercase()} (MITRE)" to "https://cwe.mitre.org/data/definitions/$num.html")
        }
        val e = forCwe(cwe)
        if (e != null) {
            for (c in e.cheatSheets) out.add(c.replace('_', ' ') to "https://cheatsheetseries.owasp.org/cheatsheets/$c.html")
        }
        out.add("OWASP Mobile Top 10" to "https://owasp.org/www-project-mobile-top-10/")
        out.add("OWASP MASVS" to "https://mas.owasp.org/MASVS/")
        out.add("Android security tips" to "https://developer.android.com/privacy-and-security/security-tips")
        return out
    }

    // OWASP Mobile Top 10 (2024) category names
    private const val M1 = "M1 Improper Credential Usage"
    private const val M2 = "M2 Inadequate Supply Chain Security"
    private const val M3 = "M3 Insecure Authentication/Authorization"
    private const val M4 = "M4 Insufficient Input/Output Validation"
    private const val M5 = "M5 Insecure Communication"
    private const val M6 = "M6 Inadequate Privacy Controls"
    private const val M7 = "M7 Insufficient Binary Protections"
    private const val M8 = "M8 Security Misconfiguration"
    private const val M9 = "M9 Insecure Data Storage"
    private const val M10 = "M10 Insufficient Cryptography"

    init {
        put(Entry("CWE-798", "Use of Hard-coded Credentials", M1, "MASVS-STORAGE / MASVS-CRYPTO",
            "Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.",
            """const val API_KEY = "EXAMPLE_ONLY_NOT_A_REAL_KEY"   // shipped inside every APK
val client = Api(API_KEY)
<!-- res/values/strings.xml: this ends up readable inside resources.arsc -->
<string name="api_secret">EXAMPLE_ONLY_NOT_A_REAL_KEY</string>""",
            """// keep the secret on YOUR server; the app only holds a short-lived user token
val token = authRepository.sessionToken()      // issued after login, expires, revocable
val client = Api(token)
// if a client key is unavoidable: restrict it (package name + SHA-256 cert, API scope, quota) and rotate it
// Google / Firebase API key in strings.xml: in the Cloud console restrict it to Android apps (package name + SHA-1) and to the APIs you use
<!-- strings.xml keeps only public identifiers; secrets and long-lived tokens stay on your backend -->""",
            listOf("Secrets_Management_Cheat_Sheet", "Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-295", "Improper Certificate Validation", M5, "MASVS-NETWORK",
            "On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.",
            """object : X509TrustManager {
    override fun checkServerTrusted(c: Array<X509Certificate>, a: String) { }   // accepts everything
    override fun checkClientTrusted(c: Array<X509Certificate>, a: String) { }
    override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
}
<!-- res/xml/network_security_config.xml: trusts any CA the user (or malware) installed -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>""",
            """// use the platform trust store (do not override TrustManager at all)
val client = OkHttpClient.Builder()
    .certificatePinner(CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAA...=")      // optional: pin to your own backend
        .build())
    .build()
// WebView: in onReceivedSslError call handler.cancel(), never handler.proceed()

<!-- network_security_config.xml: system CAs only in release; user CAs only for the debugging proxy -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-06-30">
            <pin digest="SHA-256">CURRENT_KEY_PIN_BASE64=</pin>
            <pin digest="SHA-256">BACKUP_KEY_PIN_BASE64=</pin>
        </pin-set>
    </domain-config>
</network-security-config>""",
            listOf("Transport_Layer_Security_Cheat_Sheet", "Pinning_Cheat_Sheet")))

        put(Entry("CWE-297", "Improper Validation of Certificate with Host Mismatch", M5, "MASVS-NETWORK",
            "A valid certificate issued for ANY site is accepted for your server's name, so an attacker with a cheap certificate can sit between the app and the backend.",
            """HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }""",
            """// keep the default HostnameVerifier; if you must check, compare the real host
HostnameVerifier { host, session -> host == "api.example.com" && HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session) }""",
            listOf("Transport_Layer_Security_Cheat_Sheet")))

        put(Entry("CWE-319", "Cleartext Transmission of Sensitive Information", M5, "MASVS-NETWORK",
            "Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.",
            """<application android:usesCleartextTraffic="true" ...>
val url = "http://api.example.com/login"   // plain HTTP
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />   <!-- every domain may use plain HTTP -->
</network-security-config>""",
            """<application android:usesCleartextTraffic="false" android:networkSecurityConfig="@xml/network_security_config" ...>
val url = "https://api.example.com/login"   // TLS
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
<!-- only if one legacy host really needs HTTP: scope it to that host, never to base-config -->
<domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">legacy.example.com</domain>
</domain-config>""",
            listOf("Transport_Layer_Security_Cheat_Sheet")))

        put(Entry("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm", M10, "MASVS-CRYPTO",
            "DES/RC4/MD5/ECB-mode data can be decrypted or forged much faster than the key length suggests. ECB shows patterns (equal blocks give equal ciphertext) and has no integrity.",
            """Cipher.getInstance("AES/ECB/PKCS5Padding")
MessageDigest.getInstance("MD5")""",
            """val cipher = Cipher.getInstance("AES/GCM/NoPadding")        // authenticated encryption
cipher.init(Cipher.ENCRYPT_MODE, key)                        // let the provider create a fresh random IV
val iv = cipher.iv; val ct = cipher.doFinal(plain)           // store iv next to ct
// hashing: SHA-256 or better; passwords: PBKDF2 / Argon2 / scrypt, never a plain hash""",
            listOf("Cryptographic_Storage_Cheat_Sheet")))

        put(Entry("CWE-328", "Use of Weak Hash", M10, "MASVS-CRYPTO",
            "MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.",
            """MessageDigest.getInstance("SHA-1").digest(data)""",
            """MessageDigest.getInstance("SHA-256").digest(data)
// passwords: use a slow KDF (PBKDF2WithHmacSHA256 with 600000+ iterations, Argon2id, scrypt)""",
            listOf("Cryptographic_Storage_Cheat_Sheet", "Password_Storage_Cheat_Sheet")))

        put(Entry("CWE-916", "Use of Password Hash With Insufficient Computational Effort", M10, "MASVS-CRYPTO",
            "A low iteration count lets an attacker who gets the hash (or the encrypted blob) try billions of guesses per second on a GPU.",
            """PBEKeySpec(password, salt, 1000, 256)""",
            """PBEKeySpec(password, salt, 600_000, 256)   // PBKDF2WithHmacSHA256; or use Argon2id / scrypt""",
            listOf("Password_Storage_Cheat_Sheet")))

        put(Entry("CWE-329", "Generation of Predictable IV with CBC Mode", M10, "MASVS-CRYPTO",
            "A fixed or predictable IV makes equal plaintext prefixes produce equal ciphertext and enables chosen-plaintext attacks on CBC; with GCM, reusing an IV with the same key breaks both secrecy and integrity.",
            """val iv = IvParameterSpec(ByteArray(16))   // all zeros, same every time""",
            """val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }   // new random IV per message (GCM: 12 bytes)""",
            listOf("Cryptographic_Storage_Cheat_Sheet")))

        put(Entry("CWE-321", "Use of Hard-coded Cryptographic Key", M10, "MASVS-CRYPTO",
            "The key is the same for every install and is readable from the APK, so all data protected with it can be decrypted offline by anyone.",
            """SecretKeySpec("MySecretKey12345".toByteArray(), "AES")""",
            """// generate the key on the device inside the Android Keystore (non-exportable)
val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
kg.init(KeyGenParameterSpec.Builder("data_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
val key = kg.generateKey()""",
            listOf("Cryptographic_Storage_Cheat_Sheet", "Secrets_Management_Cheat_Sheet")))

        put(Entry("CWE-336", "Same Seed in Pseudo-Random Number Generator (PRNG)", M10, "MASVS-CRYPTO",
            "A manually seeded or constant-seeded generator produces a sequence the attacker can reproduce, so tokens, keys or IVs derived from it can be guessed.",
            """val r = SecureRandom.getInstance("SHA1PRNG"); r.setSeed(12345L)""",
            """val r = SecureRandom()    // self-seeds from the OS; do not call setSeed with a fixed value""",
            listOf("Cryptographic_Storage_Cheat_Sheet")))

        put(Entry("CWE-338", "Use of Cryptographically Weak PRNG", M10, "MASVS-CRYPTO",
            "java.util.Random is predictable from a few outputs; session ids, OTPs, reset tokens or keys built from it can be guessed.",
            """val otp = Random().nextInt(999999)""",
            """val otp = SecureRandom().nextInt(1_000_000)""",
            listOf("Cryptographic_Storage_Cheat_Sheet")))

        put(Entry("CWE-326", "Inadequate Encryption Strength", M10, "MASVS-CRYPTO",
            "RSA/DSA/DH keys below 2048 bits can be factored or attacked with modest resources, so signatures and key exchange stop being trustworthy.",
            """KeyPairGenerator.getInstance("RSA").apply { initialize(1024) }""",
            """KeyPairGenerator.getInstance("RSA").apply { initialize(3072) }   // 2048 minimum; or use EC (P-256) / Ed25519""",
            listOf("Cryptographic_Storage_Cheat_Sheet")))

        put(Entry("CWE-89", "Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)", M4, "MASVS-PLATFORM / MASVS-CODE",
            "Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.",
            """db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'", null)""",
            """db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(name))   // bound parameter
// ContentProvider.query: pass selection with ? and selectionArgs, never concatenate them""",
            listOf("SQL_Injection_Prevention_Cheat_Sheet", "Input_Validation_Cheat_Sheet")))

        put(Entry("CWE-79", "Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)", M4, "MASVS-PLATFORM",
            "Untrusted text placed into HTML inside a WebView runs as script in that page. With a JavaScript bridge or file access enabled it can reach app data or native methods.",
            """webView.loadData("<h1>Hello " + userName + "</h1>", "text/html", "UTF-8")""",
            """val safe = android.text.Html.escapeHtml(userName)   // or TextUtils.htmlEncode
webView.loadDataWithBaseURL(null, "<h1>Hello " + safe + "</h1>", "text/html", "UTF-8", null)
// plus: keep JavaScript off unless needed, no JS interface on untrusted pages""",
            listOf("Cross_Site_Scripting_Prevention_Cheat_Sheet")))

        put(Entry("CWE-749", "Exposed Dangerous Method or Function", M4, "MASVS-PLATFORM",
            "Every page the WebView loads (including injected ads or a hijacked link) can call the exposed @JavascriptInterface methods, for example to read files, tokens or start activities.",
            """webView.addJavascriptInterface(Bridge(this), "app")
webView.loadUrl(urlFromIntent)""",
            """// load only your own HTTPS origins and expose nothing else
if (Uri.parse(url).host == "app.example.com") webView.loadUrl(url)
// modern alternative with an origin allow-list: WebViewCompat.addWebMessageListener(webView, "app", setOf("https://app.example.com"), listener)""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-502", "Deserialization of Untrusted Data", M4, "MASVS-CODE",
            "A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.",
            """val obj = ObjectInputStream(input).readObject()""",
            """// use a data-only format with a schema (JSON / Protobuf) and validate every field
val dto = Json.decodeFromString<Message>(text)
// if Java serialization is unavoidable: set an ObjectInputFilter allow-list""",
            listOf("Deserialization_Cheat_Sheet")))

        put(Entry("CWE-78", "Improper Neutralization of Special Elements used in an OS Command", M4, "MASVS-CODE",
            "If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).",
            """Runtime.getRuntime().exec("ping " + host)""",
            """// no shell: fixed program, arguments as separate list items, validated input
ProcessBuilder("ping", "-c", "1", validatedHost).redirectErrorStream(true).start()
// better: use an Android API instead of a command""",
            listOf("OS_Command_Injection_Defense_Cheat_Sheet")))

        put(Entry("CWE-94", "Improper Control of Generation of Code (Code Injection)", M4, "MASVS-CODE",
            "Code loaded at runtime from a writable, downloaded or attacker-reachable location executes with the app's permissions, so replacing that file means running the attacker's code.",
            """DexClassLoader(File(getExternalFilesDir(null), "plugin.dex").path, optDir, null, classLoader)""",
            """// ship the code in the APK, or download it over HTTPS, verify a signature, and keep it in app-private storage (read-only after verification)
val f = File(filesDir, "plugin.dex"); verifySignature(f); f.setReadOnly()""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)", M4, "MASVS-PLATFORM / MASVS-STORAGE",
            "A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).",
            """val out = File(dir, entry.name)            // entry.name may contain ../""",
            """val out = File(dir, entry.name).canonicalFile
if (!out.path.startsWith(dir.canonicalPath + File.separator)) throw SecurityException("bad path")""",
            listOf("Input_Validation_Cheat_Sheet")))

        put(Entry("CWE-940", "Improper Verification of Source of a Communication Channel (Intent Redirection)", M4, "MASVS-PLATFORM",
            "An Intent object received from another app is launched as it is, so the attacker chooses which component runs (even a non-exported one) with this app's identity, permissions and URI grants.",
            """val next = intent.getParcelableExtra<Intent>("extra_intent"); startActivity(next)""",
            """val next = intent.getParcelableExtra<Intent>("extra_intent")
val ok = next?.component?.packageName == packageName && next.component?.className in ALLOWED_SCREENS
if (ok) startActivity(Intent(this, Class.forName(next!!.component!!.className))) else finish()""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-73", "External Control of File Name or Path", M4, "MASVS-PLATFORM / MASVS-STORAGE",
            "A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.",
            """val uri = intent.getParcelableExtra<Uri>("uri"); contentResolver.openInputStream(uri!!)""",
            """val uri = intent.getParcelableExtra<Uri>("uri")
if (uri?.scheme == "content" && uri.authority in ALLOWED_AUTHORITIES) contentResolver.openInputStream(uri)""",
            listOf("Input_Validation_Cheat_Sheet")))

        put(Entry("CWE-1021", "Improper Restriction of Rendered UI Layers or Frames (Tapjacking)", M8, "MASVS-PLATFORM",
            "A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.",
            """<EditText android:inputType="textPassword" ... />   <!-- no filterTouchesWhenObscured -->""",
            """<LinearLayout android:filterTouchesWhenObscured="true" ...>
// or, API 31+: window.setHideOverlayWindows(true)  (needs HIDE_OVERLAY_WINDOWS)""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-477", "Use of Obsolete Function", M8, "MASVS-CODE",
            "An API that the platform no longer supports (WebView plugins, setPluginState) shows copied legacy code; on old devices it re-enables a component with known remote-code bugs.",
            """webView.settings.pluginState = WebSettings.PluginState.ON""",
            """// remove it: plugins are unsupported since Android 4.3; review JavaScript / file-access settings of this WebView""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-20", "Improper Input Validation", M4, "MASVS-CODE",
            "Data from an Intent, deep link, QR code or server is trusted without checks, so it can steer the app into unintended screens, URLs or file operations.",
            """val url = intent.getStringExtra("url"); webView.loadUrl(url!!)""",
            """val url = intent.getStringExtra("url")
val u = url?.let { Uri.parse(it) }
if (u?.scheme == "https" && u.host in ALLOWED_HOSTS) webView.loadUrl(url) else finish()""",
            listOf("Input_Validation_Cheat_Sheet")))

        put(Entry("CWE-470", "Use of Externally-Controlled Input to Select Classes or Code (Unsafe Reflection)", M4, "MASVS-CODE",
            "A class or method name coming from outside lets the attacker pick which code runs.",
            """Class.forName(intent.getStringExtra("cls")).newInstance()""",
            """val handlers = mapOf("a" to ::HandlerA, "b" to ::HandlerB)     // explicit allow-list
val h = handlers[intent.getStringExtra("cls")]?.invoke() ?: return""",
            listOf("Input_Validation_Cheat_Sheet")))

        put(Entry("CWE-918", "Server-Side Request Forgery (SSRF)", M4, "MASVS-CODE / MASVS-NETWORK",
            "When a deep link, Intent extra or web page decides which host the app connects to, an attacker can point it at an internal service, a server that logs the app's headers and tokens, or a cleartext endpoint.",
            """val url = intent.getStringExtra("endpoint")
val conn = URL(url).openConnection()      // host chosen by the caller""",
            """val id = intent.getStringExtra("endpoint")
val url = ENDPOINTS[id] ?: return          // fixed allow-list, https only
val conn = URL(url).openConnection()""",
            listOf("Input_Validation_Cheat_Sheet", "Server_Side_Request_Forgery_Prevention_Cheat_Sheet")))

        put(Entry("CWE-1395", "Dependency on Vulnerable Third-Party Component", M2, "MASVS-CODE",
            "A library bundled in the app has a publicly known vulnerability. Attackers do not need to find a bug in your code: they only need your app to reach the vulnerable function with data they control (a crafted JSON, certificate, image or network message).",
            """implementation("com.google.code.gson:gson:2.8.5")      // CVE-2022-25647, denial of service""",
            """implementation("com.google.code.gson:gson:2.10.1")     // fixed release; re-check the list when dependencies change""",
            listOf("Vulnerable_Dependency_Management_Cheat_Sheet")))

        put(Entry("CWE-1104", "Use of Unmaintained Third Party Components", M2, "MASVS-CODE",
            "A component that no longer gets security fixes stays vulnerable forever: every new bug found in it is a permanent hole in the app.",
            """implementation("com.android.support:appcompat-v7:28.0.0")   // ended at 28.0.0""",
            """implementation("androidx.appcompat:appcompat:1.7.0")        // maintained replacement""",
            listOf("Vulnerable_Dependency_Management_Cheat_Sheet")))

        put(Entry("CWE-926", "Improper Export of Android Application Components", M8, "MASVS-PLATFORM",
            "Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.",
            """<activity android:name=".AdminActivity" android:exported="true" />
<permission android:name="com.example.PERM" android:protectionLevel="normal" />   <!-- any app can request it -->
<provider android:name=".Db" android:exported="true" android:readPermission="com.example.READ" />   <!-- writes are open -->""",
            """<activity android:name=".AdminActivity" android:exported="false" />
<!-- if another app must call it: android:permission="com.example.PERM" with protectionLevel="signature", and validate every extra -->
<permission android:name="com.example.PERM" android:protectionLevel="signature" />
<provider android:name=".Db" android:exported="true" android:readPermission="com.example.READ" android:writePermission="com.example.WRITE" />""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-927", "Use of Implicit Intent for Sensitive Communication", M8, "MASVS-PLATFORM",
            "A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.",
            """sendBroadcast(Intent("com.example.TOKEN").putExtra("token", t))
PendingIntent.getActivity(this, 0, intent, 0)""",
            """sendBroadcast(Intent("com.example.TOKEN").setPackage(packageName).putExtra("token", t))
PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-939", "Improper Authorization in Handler for Custom URL Scheme", M3, "MASVS-PLATFORM",
            "Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.",
            """val target = intent.data?.getQueryParameter("redirect"); webView.loadUrl(target!!)""",
            """val target = intent.data?.getQueryParameter("redirect")?.let(Uri::parse)
if (target?.host == "app.example.com") open(target)     // allow-list; require user confirmation for sensitive actions
// prefer verified App Links (https + assetlinks.json) over custom schemes""",
            listOf("Input_Validation_Cheat_Sheet")))

        put(Entry("CWE-312", "Cleartext Storage of Sensitive Information", M9, "MASVS-STORAGE",
            "Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.",
            """prefs.edit().putString("password", password).apply()
db.execSQL("INSERT INTO users(pin) VALUES ('" + pin + "')")""",
            """// store a token (not the password) and encrypt it with a Keystore-backed AES-GCM key
val sealed = keystoreCipher.encrypt(token.toByteArray())     // see CWE-321 sample for the key
prefs.edit().putString("token", Base64.encodeToString(sealed, Base64.NO_WRAP)).apply()
// database: SQLCipher or per-field encryption; never keep the password itself""",
            listOf("Cryptographic_Storage_Cheat_Sheet", "Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-922", "Insecure Storage of Sensitive Information", M9, "MASVS-STORAGE",
            "Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.",
            """File(Environment.getExternalStorageDirectory(), "export.json").writeText(json)
<application android:requestLegacyExternalStorage="true" ...>""",
            """File(filesDir, "export.json").writeText(json)          // app-private storage
// to share: use a FileProvider with a narrow path and grant temporary URI permission
// scoped storage: remove requestLegacyExternalStorage; use MediaStore, the Storage Access Framework or getExternalFilesDir""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-276", "Incorrect Default Permissions", M9, "MASVS-STORAGE",
            "MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE let any other app read or modify the file.",
            """openFileOutput("data.txt", Context.MODE_WORLD_READABLE)""",
            """openFileOutput("data.txt", Context.MODE_PRIVATE)""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-532", "Insertion of Sensitive Information into Log File", M9, "MASVS-STORAGE",
            "On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.",
            """Log.d("Login", "user=" + user + " password=" + password)""",
            """if (BuildConfig.DEBUG) Log.d("Login", "login attempt")      // never log credentials or tokens
// release builds: strip logs with R8 (-assumenosideeffects class android.util.Log { *; })""",
            listOf("Logging_Cheat_Sheet")))

        put(Entry("CWE-524", "Use of Cache Containing Sensitive Information", M9, "MASVS-STORAGE",
            "The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.",
            """<EditText android:inputType="text" />   <!-- password-like field with suggestions on -->""",
            """<EditText android:inputType="textPassword|textNoSuggestions" android:importantForAutofill="no" />""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-377", "Insecure Temporary File", M9, "MASVS-STORAGE",
            "A predictable temp file in a shared folder can be pre-created or replaced by another app.",
            """File("/sdcard/tmp_" + id)""",
            """File.createTempFile("tmp_", ".bin", cacheDir)   // app-private cache""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-200", "Exposure of Sensitive Information to an Unauthorized Actor", M9, "MASVS-STORAGE / MASVS-PLATFORM",
            "Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.",
            """webSettings.allowFileAccessFromFileURLs = true
<provider android:exported="true" android:grantUriPermissions="true" ... />   <!-- every path can be handed out -->""",
            """webSettings.allowFileAccessFromFileURLs = false
webSettings.allowUniversalAccessFromFileURLs = false
<provider android:exported="false" android:grantUriPermissions="false" ...>
    <grant-uri-permission android:pathPrefix="/shared/" />   <!-- only the paths that must be shared -->
</provider>""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-359", "Exposure of Private Personal Information to an Unauthorized Actor", M6, "MASVS-PRIVACY",
            "Hardware identifiers (IMEI, subscriber id) follow the user for life and cannot be reset; collecting or sending them enables tracking and profiling and may need explicit consent.",
            """telephonyManager.deviceId""",
            """// use a resettable, app-scoped id and ask for consent when you track
val id = UUID.randomUUID().toString()   // stored once in app-private storage
// advertising: AdvertisingIdClient, respecting the user's opt-out""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-489", "Active Debug Code", M8, "MASVS-RESILIENCE",
            "A debuggable app lets anyone attach a debugger, run code inside the process and read its private data; WebView debugging exposes pages and JS state over USB. android:testOnly marks a test build that may carry relaxed checks and must not be shipped.",
            """<application android:debuggable="true" android:testOnly="true" ...>
WebView.setWebContentsDebuggingEnabled(true)""",
            """<!-- release builds are not debuggable by default: remove android:debuggable and android:testOnly -->
if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-250", "Execution with Unnecessary Privileges", M8, "MASVS-PLATFORM",
            "Extra privileges (debuggable, test-only, shared user id, legacy storage) widen what a compromise or a malicious app can reach. Powerful permissions (SMS, overlay, install packages) and an AccessibilityService give a compromised app, or overlay and banking malware, far more reach than the feature needs.",
            """<application android:debuggable="true" android:testOnly="true" ...>
<uses-permission android:name="android.permission.READ_SMS" />""",
            """<!-- ship release builds without debuggable / testOnly; request only the permissions you use -->
<!-- OTP codes: SMS Retriever or SMS User Consent API instead of READ_SMS; files: photo picker or the Storage Access Framework -->""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-530", "Exposure of Backup File to an Unauthorized Control Sphere", M9, "MASVS-STORAGE",
            "With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.",
            """<application android:allowBackup="true" ...>""",
            """<application android:allowBackup="false" android:dataExtractionRules="@xml/data_extraction_rules" ...>
<!-- or keep backup and exclude secrets with fullBackupContent / dataExtractionRules -->""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-693", "Protection Mechanism Failure", M3, "MASVS-AUTH",
            "A biometric prompt that is not bound to a Keystore key only returns a boolean; hooking the callback (Frida) skips authentication without knowing the fingerprint.",
            """biometricPrompt.authenticate(promptInfo)   // result is just 'success'""",
            """// bind the unlock to a key that requires user authentication
biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
// the key: setUserAuthenticationRequired(true) in KeyGenParameterSpec""",
            listOf("Authentication_Cheat_Sheet")))

        put(Entry("CWE-287", "Improper Authentication", M3, "MASVS-AUTH",
            "Authentication decisions made on the client can be bypassed by editing the app or replaying requests.",
            """if (pin == "1234") unlock()""",
            """// verify credentials on the server and use short-lived tokens
val ok = api.verifyPin(pinHash)""",
            listOf("Authentication_Cheat_Sheet")))

        put(Entry("CWE-284", "Improper Access Control", M3, "MASVS-AUTH / MASVS-PLATFORM",
            "Data or functions are reachable without a proper check: for example an open Firebase database or a provider anyone can query. A Firebase Realtime Database URL in the resources is not a flaw by itself: the question is whether its rules allow public reads or writes, because the URL is readable by anyone who unpacks the APK.",
            """// Firebase rules: { ".read": true, ".write": true }""",
            """// Firebase rules: only authenticated users, only their own node
{ "rules": { "users": { "uid": { ".read": "auth != null && auth.uid == 'uid'" } } } }
// test your own database from a device you own: open PROJECT-ID.firebaseio.com/.json  -> it must answer Permission denied""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-266", "Incorrect Privilege Assignment", M8, "MASVS-PLATFORM",
            "A component or permission grants more than it needs, so a low-privileged caller can do high-privileged things. android:sharedUserId puts every app signed with the same key into one Linux UID, so the weakest of them exposes the private files and permissions of all the others.",
            """<manifest android:sharedUserId="com.example.shared" ...>
<provider android:exported="true" android:grantUriPermissions="true" ... />""",
            """<!-- remove sharedUserId (deprecated since API 29); share data through explicit, permission-protected providers or services -->
<provider android:exported="false" android:grantUriPermissions="true" ... />   <!-- share single URIs on demand -->""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-780", "Use of RSA Algorithm without OAEP", M10, "MASVS-CRYPTO",
            "PKCS#1 v1.5 padding is vulnerable to padding-oracle attacks (Bleichenbacher) when error behaviour leaks.",
            """Cipher.getInstance("RSA/ECB/PKCS1Padding")""",
            """Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")""",
            listOf("Cryptographic_Storage_Cheat_Sheet")))

        put(Entry("CWE-353", "Missing Support for Integrity Check", M7, "MASVS-RESILIENCE",
            "A client-side integrity check can be removed by anyone who edits the APK, so it is a speed bump, not a security boundary.",
            """if (!signatureOk()) finish()""",
            """// verify on the server: Play Integrity API token checked by your backend""",
            listOf("Mobile_Application_Security_Cheat_Sheet")))

        put(Entry("CWE-324", "Use of a Key Past its Expiration Date", M5, "MASVS-NETWORK",
            "Certificate pinning has a lifecycle. In network_security_config.xml a pin-set can carry an expiration date: after it, Android stops enforcing the pins and falls back to normal CA validation, so the app silently loses the protection it was built to give (an attacker with any trusted-CA certificate can intercept the traffic again). The opposite failure is a pin-set with a single pin: when that key is rotated or lost, every installed copy of the app is locked out until it is updated.",
            """<pin-set expiration="2023-01-01">
    <pin digest="SHA-256">AAAA...=</pin>   <!-- one pin only, and the date has passed -->
</pin-set>""",
            """<domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2027-06-30">
        <pin digest="SHA-256">CURRENT_KEY_PIN_BASE64=</pin>
        <pin digest="SHA-256">BACKUP_KEY_PIN_BASE64=</pin>   <!-- a second key generated in advance and kept offline -->
    </pin-set>
</domain-config>
// keep a calendar reminder: ship an app update with fresh pins well before the expiration date""",
            listOf("Pinning_Cheat_Sheet", "Transport_Layer_Security_Cheat_Sheet")))
    }
}
