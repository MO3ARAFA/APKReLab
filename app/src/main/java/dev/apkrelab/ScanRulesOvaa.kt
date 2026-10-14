package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity

/**
 * 0.48.0: rules written from the OVAA (Oversecured Vulnerable Android App) vulnerability list, for the gaps the
 * existing rules did not cover: unprotected broadcasts, sensitive implicit launches, dangerous Serializable/Parcelable
 * classes, provider openFile path building, code loading from another app or a writable directory, ACTION_PICK
 * results, weak deep link host checks, deep link parameters stored as configuration, and URI-permission grants
 * returned through setResult.
 * All of them are heuristics over one method (or one class) of baksmali text, like the rest of the rule files:
 * a hit means "review this", the AI triage and the call graph decide how much it matters.
 */
internal object OvaaHelpers {
    /** Words that make a string look like a credential/session value (matched on const-strings of one method). */
    val sensitive = Regex("(?i)(passw|token|secret|credential|session|login|username|api[_-]?key|otp)")

    class M(val start: Int, val header: String, val body: String)

    /** Every method of the class text: offset of its ".method" line, the header line, and the whole body. */
    fun methods(text: String): List<M> {
        val out = ArrayList<M>()
        var i = text.indexOf("\n.method")
        while (i >= 0) {
            val e = text.indexOf("\n.end method", i)
            val end = if (e < 0) text.length else e
            var h = text.indexOf('\n', i + 1)
            if (h < 0 || h > end) h = end
            out.add(M(i, text.substring(i + 1, h), text.substring(i, end)))
            i = if (e < 0) -1 else text.indexOf("\n.method", end)
        }
        return out
    }

    fun constStrings(body: String): List<String> =
        rx("const-string(?:/jumbo)?\\s+[vp]\\d+,\\s*\"([^\"]*)\"").findAll(body).map { it.groupValues[1] }.toList()

    fun sensitiveWords(strings: List<String>): List<String> =
        strings.filter { it.length < 60 && !isPlatformConstant(it) && !isCustomAction(it) && sensitive.containsMatchIn(it) }.distinct().take(4)

    /** 0.48.1: an action name such as ...action.UNPROTECTED_CREDENTIALS_DATA says what the Intent carries. */
    fun sensitiveActionName(action: String?): Boolean =
        action != null && !isPlatformConstant(action) && Regex("(?i)(passw|token|secret|credential|session|otp|api[_-]?key)").containsMatchIn(action)

    /**
     * 0.49.2: Android framework action / extra names (android.media.extra.AUDIO_SESSION, android.intent.action.VIEW ...). They are
     * public API constants, not app secrets and not the app's own action, so they neither count as "sensitive" nor as a custom action.
     */
    fun isPlatformConstant(s: String): Boolean = s.startsWith("android.") || s.startsWith("androidx.") || s.startsWith("com.android.")

    fun isCustomAction(s: String): Boolean = !isPlatformConstant(s) && rx("^[A-Za-z0-9_.]+\\.action\\.[A-Za-z0-9_.]+$").matches(s)
}

/** OVAA 7: a broadcast carrying credentials that any app can receive. */
/**
 * OVAA 7 / intent sniffing. 0.75.0: the decision is made on the IR (IrRules.intentSends): the Intent passed to sendBroadcast / startService /
 * bindService is traced back in SSA to its `new Intent` and every instruction touching that object is checked (setPackage / setComponent /
 * setClass(Name), receiver-permission argument, extras). The old text heuristic below ([legacy]) runs only when the class cannot be parsed.
 */
object BroadcastUnprotectedSendRule : ScanRule {
    override val id = "broadcast-unprotected-send"
    override val title = "Broadcast sent without a receiver permission"
    override val cwes = listOf("CWE-927")
    override val confidence = "MEDIUM"

    private const val REC = "Use sendBroadcast(intent, permission) with a signature-level permission, or setPackage(getPackageName()) / an explicit component / LocalBroadcastManager. Never put credentials in a broadcast."

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val t = ctx.text
        if (!t.contains("->sendBroadcast") && !t.contains("->sendOrderedBroadcast") && !t.contains("->sendStickyBroadcast") &&
            !t.contains("->startService") && !t.contains("->startForegroundService") && !t.contains("->bindService")) return emptyList()
        val c = ctx.ir ?: return legacy(ctx)
        return IrHits.toFindings(ctx, dev.apkrelab.ir.IrRules.intentSends(c), REC)
    }

    /** The 0.48 text heuristic, kept only as the fallback for a class the IR parser cannot read. */
    fun legacy(ctx: RuleContext): List<Finding> {
        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(ctx.text)) {
            val call = rx("->(?:sendBroadcast|sendStickyBroadcast)\\(Landroid/content/Intent;\\)V").find(m.body) ?: continue
            if (rx("Landroid/content/Intent;->(?:setPackage|setComponent|setClass|setClassName)\\(").containsMatchIn(m.body)) continue
            val strings = OvaaHelpers.constStrings(m.body)
            val words = OvaaHelpers.sensitiveWords(strings)
            val action = strings.firstOrNull { OvaaHelpers.isCustomAction(it) }
            if (words.isEmpty() && action == null) continue
            val sev = if (words.isNotEmpty() || OvaaHelpers.sensitiveActionName(action)) Severity.HIGH else Severity.LOW
            val detail = "This method sends a broadcast with no receiver permission and no explicit package/component, so ANY app that registers a receiver for the action gets it" +
                (if (action != null) " (custom action \"$action\")" else "") +
                (if (words.isNotEmpty()) ". Strings that look sensitive in the same method: " + words.joinToString(", ") else "") + "."
            out.add(ctx.finding(sev, title, detail,
                "Use sendBroadcast(intent, permission) with a signature-level permission, or setPackage(getPackageName()) / LocalBroadcastManager. Never put credentials in a broadcast.",
                m.start + call.range.first, "CWE-927"))
        }
        return out
    }
}

/** OVAA 8: an implicit Intent with the app's own action that carries a token/credential in the data or extras. */
object ImplicitIntentSensitiveRule : ScanRule {
    override val id = "implicit-intent-sensitive"
    override val title = "Sensitive data in an implicit Intent"
    override val cwes = listOf("CWE-927")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(ctx.text)) {
            val launch = rx("->(?:startActivity|startActivityForResult|startService)\\(Landroid/content/Intent;").find(m.body) ?: continue
            val hasAction = rx("Landroid/content/Intent;-><init>\\(Ljava/lang/String;|Landroid/content/Intent;->setAction\\(").containsMatchIn(m.body)
            if (!hasAction) continue
            if (rx("Landroid/content/Intent;->(?:setPackage|setComponent|setClass|setClassName)\\(|Landroid/content/Intent;-><init>\\(Landroid/content/Context;Ljava/lang/Class;").containsMatchIn(m.body)) continue
            val strings = OvaaHelpers.constStrings(m.body)
            val action = strings.firstOrNull { OvaaHelpers.isCustomAction(it) } ?: continue
            val words = OvaaHelpers.sensitiveWords(strings)
            if (words.isEmpty()) continue
            out.add(ctx.finding(Severity.HIGH, title,
                "An implicit Intent with the custom action \"$action\" is launched while the same method handles " + words.joinToString(", ") +
                    ". Any app that declares an intent-filter for that action can receive the Intent and read its data/extras.",
                "Make the Intent explicit (setClass / setComponent / setPackage) or keep the secret out of the Intent and fetch it from your own storage in the target component.",
                m.start + launch.range.first, "CWE-927"))
        }
        return out
    }
}

/** OVAA 9, 10, 11: Serializable/Parcelable classes that delete files or hide native code in their (de)serialisation. */
object DangerousSerializableRule : ScanRule {
    override val id = "serializable-dangerous"
    override val title = "Dangerous Serializable/Parcelable class"
    override val cwes = listOf("CWE-502")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val text = ctx.text
        val isTransferable = rx("^\\.implements\\s+L(?:java/io/Serializable|java/io/Externalizable|android/os/Parcelable(?:[$]Creator)?);", RegexOption.MULTILINE)
            .containsMatchIn(text)
        if (!isTransferable) return emptyList()
        val out = ArrayList<Finding>()
        var nativeReported = false
        for (m in OvaaHelpers.methods(text)) {
            if (!nativeReported && rx("^\\.method\\b[^\\n]*\\bnative\\b").containsMatchIn(m.header)) {
                nativeReported = true
                out.add(ctx.finding(Severity.HIGH, "Native method in a Serializable/Parcelable class",
                    "This class can be rebuilt from attacker-controlled bytes (Intent extras, Binder, ObjectInputStream) and declares a native method (${m.header.trim()}). A native routine that trusts a deserialised length or pointer is a memory corruption bug waiting for a crafted Parcel.",
                    "Keep native code out of data classes, validate every deserialised size and index, and reject unexpected classes (ObjectInputFilter / explicit component checks).",
                    m.start, "CWE-502"))
            }
            val hookName = rx("\\s(?:readObject|readResolve|finalize|createFromParcel|readFromParcel|writeToParcel|<init>)\\(").containsMatchIn(m.header)
            val isHook = hookName && !(m.header.contains("<init>") && !m.header.contains("Landroid/os/Parcel;") && !m.header.contains("ObjectInputStream"))
            val del = rx("Ljava/io/File;->(?:delete|deleteOnExit)\\(\\)|Ljava/nio/file/Files;->delete|->(?:deleteRecursive|deleteRecursively|deleteDir\\w*|deleteFile\\w*|removeFiles?|wipe\\w*|purge\\w*)\\(").find(m.body) ?: continue
            out.add(ctx.finding(if (isHook) Severity.HIGH else Severity.MEDIUM, "File deleted while deserialising an object",
                "${m.header.trim()} deletes a file" + (if (isHook) "." else " (not a deserialisation hook, but the class is Serializable/Parcelable, so check who calls it after the object is rebuilt).") +
                    " Whoever can hand this object to the app (Intent extra, bound service, saved state) chooses the path that gets deleted.",
                "Do not touch the file system from readObject / createFromParcel / constructors that read a Parcel; validate paths against an allow-list in the code that uses the object.",
                m.start + del.range.first, "CWE-502"))
        }
        return out
    }
}

/** OVAA 12: openFile() of a provider that builds the file from the last path segment (read AND write theft). */
object ProviderOpenFileSegmentRule : ScanRule {
    override val id = "provider-openfile-segment"
    override val title = "ContentProvider.openFile builds a path from the URI"
    override val cwes = listOf("CWE-22")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(ctx.text)) {
            if (!rx("\\sopenFile\\(Landroid/net/Uri;Ljava/lang/String;").containsMatchIn(m.header)) continue
            val seg = rx("Landroid/net/Uri;->(?:getLastPathSegment|getPath|getEncodedPath)\\(").find(m.body) ?: continue
            if (!rx("Ljava/io/File;-><init>").containsMatchIn(m.body)) continue
            if (m.body.contains("->getCanonicalPath(") || m.body.contains("->getCanonicalFile(") || m.body.contains("->normalize(")) continue
            val writable = rx("const-string(?:/jumbo)?\\s+[vp]\\d+,\\s*\"[rwat]*w[rwat]*\"").containsMatchIn(m.body) || !m.body.contains("\"r\"")
            out.add(ctx.finding(Severity.HIGH, title,
                "openFile() creates a File from the URI (${seg.value.substringAfter("->").substringBefore("(")}) without canonicalising it. A caller can pass an encoded ../ in the URI to reach any file the app can open" +
                    (if (writable) ", and the mode argument is not restricted to read-only, so the same bug can overwrite files." else "."),
                "Resolve the file inside a fixed directory, call getCanonicalPath() and check it still starts with that directory, and reject modes other than \"r\" unless writing is intended.",
                m.start + seg.range.first, "CWE-22"))
        }
        return out
    }
}

/** OVAA 15: the app loads code or classes from another installed app with no check of who that app is. */
object PackageContextCodeRule : ScanRule {
    override val id = "package-context-code"
    override val title = "Code loaded from another app's package context"
    override val cwes = listOf("CWE-94")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(ctx.text)) {
            val call = rx("->createPackageContext\\(Ljava/lang/String;I\\)Landroid/content/Context;").find(m.body) ?: continue
            val flagsIncludeCode = rx("const(?:/4|/16|/high16)?\\s+v\\d+,\\s*(-?0x[0-9a-fA-F]+)").findAll(m.body).any {
                val v = it.groupValues[1].removePrefix("-").removePrefix("0x").toLongOrNull(16) ?: -1L
                v in 2L..7L && (v and 2L) != 0L
            }
            val loads = rx("->getClassLoader\\(\\)|->loadClass\\(|Ldalvik/system/(?:DexClassLoader|PathClassLoader);-><init>").containsMatchIn(m.body)
            if (!loads && !flagsIncludeCode) continue
            val signatureCheck = m.body.contains("->checkSignatures(") || m.body.contains("->getPackageInfo(") && m.body.contains("Landroid/content/pm/Signature;")
            if (signatureCheck) continue
            val sev = if (loads) Severity.HIGH else Severity.MEDIUM
            out.add(ctx.finding(sev, title,
                "createPackageContext() is called" + (if (flagsIncludeCode) " with CONTEXT_INCLUDE_CODE" else "") +
                    (if (loads) " and the resulting context's class loader is used" else "") +
                    ", and no signature check of the target package is visible. Any app installed under that package name runs its code inside this process.",
                "Do not load code from other apps. If you must, verify the package signature with PackageManager.checkSignatures / signing certificates first and drop CONTEXT_IGNORE_SECURITY.",
                m.start + call.range.first, "CWE-94"))
        }
        return out
    }
}

/** OVAA 18: a dex/jar loaded from a directory other apps can write to. */
object DexLoadWritableDirRule : ScanRule {
    override val id = "dex-load-writable-dir"
    override val title = "Dex code loaded from a shared or world-accessible directory"
    override val cwes = listOf("CWE-94")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val text = ctx.text
        val loader = rx("Ldalvik/system/(?:DexClassLoader|PathClassLoader|InMemoryDexClassLoader);-><init>").find(text) ?: return emptyList()
        val why = ArrayList<String>()
        if (text.contains("Landroid/os/Environment;->getExternalStorageDirectory(")) why.add("a path under shared external storage")
        if (text.contains("->getExternalFilesDir(") || text.contains("->getExternalCacheDir(") || text.contains("->getExternalMediaDirs(")) why.add("a path under the external app directory")
        if (rx("const-string(?:/jumbo)?\\s+[vp]\\d+,\\s*\"(?:/sdcard|/storage/|/mnt/sdcard|/data/local/tmp)[^\"]*\"").containsMatchIn(text)) why.add("a hardcoded /sdcard or /data/local/tmp path")
        for (m in OvaaHelpers.methods(text)) {
            if (rx("->getDir\\(Ljava/lang/String;I\\)").containsMatchIn(m.body) && rx("const/4\\s+v\\d+,\\s*0x[12]\\b").containsMatchIn(m.body)) {
                why.add("getDir() with a world-readable/writable mode")
                break
            }
        }
        if (why.isEmpty()) return emptyList()
        return listOf(ctx.finding(Severity.HIGH, title,
            "A class loader is created in a class that also builds " + why.joinToString(" and ") +
                ". If the dex/jar sits there, another app (or a rooted user) can replace it and run code with this app's permissions.",
            "Copy the dex into app-private storage (filesDir, mode private), make it read-only (File.setReadOnly) before loading, and verify a hash or signature, or ship the code inside the APK.",
            loader.range.first, "CWE-94"))
    }
}

/** OVAA 6: an implicit ACTION_PICK / GET_CONTENT whose result Uri is opened as a file. */
object PickResultFileRule : ScanRule {
    override val id = "pick-result-file"
    override val title = "Result of an implicit PICK/GET_CONTENT Intent is trusted"
    override val cwes = listOf("CWE-927")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val text = ctx.text
        // The PICK Intent is often built in an inner class (MainActivity$1 click listener) while
        // onActivityResult lives in the outer class, so the string may be absent here.
        val pick = rx("const-string(?:/jumbo)?\\s+[vp]\\d+,\\s*\\\"android\\.intent\\.action\\.(?:PICK|GET_CONTENT|OPEN_DOCUMENT)\\\"").find(text)
        for (m in OvaaHelpers.methods(text)) {
            if (!rx("\\sonActivityResult\\(IILandroid/content/Intent;\\)V").containsMatchIn(m.header)) continue
            val data = rx("Landroid/content/Intent;->getData\\(\\)").find(m.body) ?: continue
            val use = rx("->openInputStream\\(|->openFileDescriptor\\(|Ljava/io/FileInputStream;-><init>|Landroid/net/Uri;->getPath\\(").find(m.body) ?: continue
            val what = pick?.value?.substringAfter("action.")?.trim('"') ?: "PICK/GET_CONTENT"
            val sev = if (pick != null) Severity.MEDIUM else Severity.LOW
            return listOf(ctx.finding(sev, title,
                "onActivityResult() opens the Uri returned by an implicit $what Intent (${use.value.substringAfter("->").substringBefore("(")})" +
                    (if (pick == null) " (the Intent itself is built in another class, so this is a lead)" else "") +
                    ". The app that answers the Intent is chosen by the system, so a malicious app can answer with a file:// or content:// Uri that points at this app's private files.",
                "Treat the returned Uri as untrusted: accept only content:// from the expected authority, never file://, copy through ContentResolver into a new file, and do not follow a Uri that resolves into your own data directory.",
                m.start + data.range.first, "CWE-927"))
        }
        return emptyList()
    }
}

/** OVAA 3: a deep link host that is validated with endsWith/contains/startsWith instead of an exact match. */
object DeeplinkHostValidationRule : ScanRule {
    override val id = "deeplink-host-validation"
    override val title = "Weak host validation of a Uri"
    override val cwes = listOf("CWE-939")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(ctx.text)) {
            val host = rx("Landroid/net/Uri;->getHost\\(\\)|Ljava/net/URL;->getHost\\(\\)").find(m.body) ?: continue
            val weak = rx("Ljava/lang/String;->(endsWith|startsWith|contains|indexOf)\\(").find(m.body.substring(host.range.first)) ?: continue
            out.add(ctx.finding(Severity.MEDIUM, title,
                "The host of a Uri is read and then compared with String.${weak.groupValues[1]}(). Checks like that accept hosts such as evil-example.com or example.com.evil.com, so a deep link can point the app (WebView, login, download) at an attacker's server.",
                "Compare the whole host with an allow-list using equals(), or require host == \"example.com\" || host.endsWith(\".example.com\") (note the leading dot) after parsing with a real URI parser.",
                m.start + host.range.first, "CWE-939"))
        }
        return out
    }
}

/** OVAA 1: a deep link query parameter written to SharedPreferences (a server URL the app will trust later). */
object DeeplinkConfigPoisoningRule : ScanRule {
    override val id = "deeplink-config-poisoning"
    override val title = "Deep link parameter stored as configuration"
    override val cwes = listOf("CWE-939")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(ctx.text)) {
            val q = rx("Landroid/net/Uri;->getQueryParameter\\(").find(m.body) ?: continue
            val prefs = rx("Landroid/content/SharedPreferences\\\$Editor;->putString\\(").containsMatchIn(m.body)
            // 0.48.2: the usual shape is a helper: loginUtils.setLoginUrl(uri.getQueryParameter("url"))
            val setter = rx("->((?:set|save|store|put|update)\\w*(?:Url|Host|Server|Endpoint|Domain|Config)\\w*)\\(Ljava/lang/String;\\)V").find(m.body)
            if (!prefs && setter == null) continue
            val urlish = setter != null || OvaaHelpers.constStrings(m.body).any { rx("(?i)(url|host|server|endpoint|domain)").containsMatchIn(it) }
            out.add(ctx.finding(if (urlish) Severity.HIGH else Severity.MEDIUM, title,
                (if (setter != null) "A query parameter of an incoming Uri is passed to " + setter.groupValues[1] + "()" else "A query parameter of an incoming Uri is saved to SharedPreferences") +
                    (if (urlish && setter == null) " under a URL/server-like key" else "") +
                    ". A crafted link can overwrite a setting such as the login URL, so later requests (with the user's credentials) go to the attacker.",
                "Never let a link change configuration. Ignore the parameter, or accept it only after matching it against a fixed allow-list of values.",
                m.start + q.range.first, "CWE-939"))
        }
        return out
    }
}

/** OVAA 2: setResult() returning an Intent built from outside data - the caller gets URI permission on the provider. */
object UriGrantViaResultRule : ScanRule {
    override val id = "uri-grant-via-result"
    override val title = "Intent returned with setResult() may grant URI permissions"
    override val cwes = listOf("CWE-284")
    override val confidence = "LOW"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val out = ArrayList<Finding>()
        for (m in OvaaHelpers.methods(ctx.text)) {
            val res = rx("->setResult\\(ILandroid/content/Intent;\\)V").find(m.body) ?: continue
            val grantFlag = rx("Landroid/content/Intent;->(?:addFlags|setFlags)\\(I\\)").containsMatchIn(m.body) &&
                rx("const/4\\s+v\\d+,\\s*0x[123]\\b").containsMatchIn(m.body)
            val direct = m.body.contains("->grantUriPermission(")
            val external = rx("Landroid/content/Intent;->(?:getData|getDataString|getParcelableExtra|getStringExtra)\\(|Landroid/net/Uri;->parse\\(").containsMatchIn(m.body)
            // 0.48.2: onActivityResult(requestCode, resultCode, data) hands the data Intent of ANOTHER app's result straight to setResult()
            val forwards = rx("\\sonActivityResult\\(IILandroid/content/Intent;\\)V").containsMatchIn(m.header) &&
                rx("invoke-virtual(?:/range)?\\s*\\{p0,\\s*\\w+,\\s*p3\\}[^\\n]*->setResult\\(ILandroid/content/Intent;\\)V").containsMatchIn(m.body) &&
                !rx("Landroid/content/Intent;->(?:setFlags|removeFlags)\\(").containsMatchIn(m.body)
            if (!direct && !forwards && !(grantFlag && external)) continue
            out.add(ctx.finding(Severity.MEDIUM, title,
                if (forwards) "onActivityResult() passes the result Intent it received (from an activity chosen by an implicit Intent) straight to setResult(). That Intent can carry FLAG_GRANT_READ/WRITE_URI_PERMISSION and a content:// Uri of this app's own providers (including ones that are not exported but declare grantUriPermissions=true), so whoever started this activity, and the app that answered, gets access to that data"
                else "The method returns an Intent through setResult()" + (if (direct) " after grantUriPermission()" else " that carries FLAG_GRANT_*_URI_PERMISSION") +
                    (if (external) " and the Uri comes from outside data" else "") +
                    ". The app that started this activity receives temporary access to the content:// Uri, including providers that are not exported but declare grantUriPermissions=\"true\".",
                "Grant only the one Uri you intend to share, never a Uri taken from the incoming Intent, and use android:grantUriPermissions=\"false\" with <grant-uri-permission> for specific paths.",
                m.start + res.range.first, "CWE-284"))
        }
        return out
    }
}

/** OVAA 13: Log.d("...", "Processing " + loginData) - an object that holds the password ends up in logcat. */
object LogCredentialObjectRule : ScanRule {
    override val id = "log-credential-object"
    override val title = "Credentials may be written to the log"
    override val cwes = listOf("CWE-532")
    override val confidence = "MEDIUM"

    override fun scan(ctx: RuleContext): List<Finding> {
        if (ctx.scope == SecurityScanner.Scope.LIB) return emptyList()
        val out = ArrayList<Finding>()
        val logRe = rx("Landroid/util/Log;->[dviwe]\\(Ljava/lang/String;Ljava/lang/String;\\)I")
        val credClassRe = rx("new-instance\\s+v\\d+,\\s*L[^;]*(?:Login|Credential|Password|Passwd|Token|Auth|Account|Session)[A-Za-z]*;")
        val namesRe = rx("\\.(?:param|local)\\s+[vp]\\d+,\\s*\"([A-Za-z_]*(?:passw|passwd|pwd|token|secret|credential|otp|pin)[A-Za-z_]*)\"", RegexOption.IGNORE_CASE)
        // 0.50.2 (InsecureBankv2 DoLogin): Log.d("Successful Login:", ", account=" + username + ":" + password) where username / password
        // are FIELDS, so neither a credential class nor debug .local names exist. A String field with a strong credential word in its
        // name that is read into a log message built with a StringBuilder.
        val fieldRe = rx("[is]get-object\\s+[vp]\\d+,\\s*(?:[vp]\\d+,\\s*)?L[^;]*;->([A-Za-z0-9_]*(?:passw|pwd|token|secret|credential)[A-Za-z0-9_]*):Ljava/lang/String;", RegexOption.IGNORE_CASE)
        for (m in OvaaHelpers.methods(ctx.text)) {
            // 0.51.3: the message, the StringBuilder and the credential object must sit NEAR the Log call (the last 2500 chars before it).
            // Before, any Log + any StringBuilder + any Token/Login-named object anywhere in the method matched: NewPipe's huge
            // MainActivity.onCreate (a locale-migration Log.e and an unrelated TokenData object) was a false MEDIUM.
            val names = namesRe.findAll(m.body).map { it.groupValues[1] }.distinct().take(3).toList()
            for (log in logRe.findAll(m.body)) {
                val win = m.body.substring(maxOf(0, log.range.first - 2500), log.range.first)
                val builds = win.contains("Ljava/lang/StringBuilder;->append(") || win.contains("Ljava/lang/String;->valueOf(")
                if (!builds) continue
                val credClass = credClassRe.find(win)
                val objAppend = win.contains("->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;")
                val fieldNames = fieldRe.findAll(win).map { it.groupValues[1] }.distinct().take(3).toList()
                if (credClass == null && names.isEmpty() && fieldNames.isEmpty()) continue
                val sev = if (credClass != null && objAppend) Severity.HIGH else Severity.MEDIUM
                out.add(ctx.finding(sev, title,
                    "This method builds a log message with a StringBuilder and writes it with Log." + log.value.substringAfter("Log;->").substringBefore("(") + "()" +
                        (if (credClass != null) ", and it creates a " + credClass.value.substringAfterLast("/").trim(';') + " object" + (if (objAppend) " that is appended to the message (its toString() usually prints every field, including the password)" else "") else "") +
                        (if (names.isNotEmpty()) ". Credential-like variable names in the method: " + names.joinToString(", ") else "") +
                        (if (fieldNames.isNotEmpty()) ". Credential-like field(s) read into the message: " + fieldNames.joinToString(", ") else "") +
                        ". Logcat can be read over adb and, on older Android versions, by other apps.",
                    "Remove the log call or log only a non-sensitive id; never put a login/credential object in a message, and strip debug logging from release builds (R8 -assumenosideeffects).",
                    m.start + log.range.first, "CWE-532"))
                break
            }
        }

        return out
    }
}
