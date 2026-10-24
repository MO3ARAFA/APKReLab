package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity

/**
 * 0.42.0: the AndroidManifest.xml checks as plugin rules (the former body of SecurityScanner.scanManifest).
 *
 * Same architecture as the code rules (ScanRules.kt, ScanRulesLegacy.kt) with a different input: a manifest rule receives a
 * [ManifestContext] (the decoded XML parsed ONCE into application facts and a list of [ManifestComponent]) instead of the
 * baksmali text of one class. Rules are registered with RuleRegistry.registerManifest and run by RuleRegistry.runManifest;
 * a rule that throws is skipped and counted (RuleRegistry.errorReport()), the other rules still run.
 *
 * Detection code, regexes, severities, titles and texts are the originals, line for line.
 * Why regex over the decoded text and not a DOM: the decoder returns text that is not always well formed (edited or obfuscated
 * APKs); the regexes tolerate that and keep the results identical to 0.41.0.
 *
 * To add a rule: write the object, add `registerManifest(MyRule)` in RuleRegistry init, one line in Capabilities.SCANNER,
 * and a VulnKnowledge entry if the CWE is new.
 */

/** One <activity|activity-alias|service|receiver|provider> element. */
class ManifestComponent(
    val tag: String,
    val headerAttrs: String,   // the attributes of the opening tag
    val body: String,          // everything between the opening and the closing tag ("" for a self-closing element)
    val name: String,          // android:name or "(unnamed)"
    val exported: Boolean,     // explicit android:exported, else true when the element has an <intent-filter>
    val isLauncher: Boolean,
    val permission: String? = null,        // 0.69.0: android:permission on the tag (all component kinds)
    val readPermission: String? = null,    // 0.69.0: provider only
    val writePermission: String? = null,   // 0.69.0: provider only
    val targetActivity: String? = null     // 0.69.0: activity-alias only: the real class behind the alias
)

/** The manifest, parsed once and shared by all manifest rules (lazy: a rule pays only for what it reads). */
class ManifestContext(val xml: String) {

    /** android:usesCleartextTraffic="true" (two rules use it: the network-security-config rule only applies when this is false). */
    val cleartextTrafficTrue: Boolean by lazy { rx("android:usesCleartextTraffic\\s*=\\s*\"true\"").containsMatchIn(xml) }

    /** Custom <permission> declarations: name -> protectionLevel ("normal" when unspecified). */
    val declaredPerms: Map<String, String> by lazy {
        rx("<permission(?![\\w-])([^>]*?)/?>").findAll(xml).mapNotNull { pm ->
            val attrs = pm.groupValues[1]
            val nm = rx("android:name\\s*=\\s*\"([^\"]+)\"").find(attrs)?.groupValues?.get(1) ?: return@mapNotNull null
            val level = rx("android:protectionLevel\\s*=\\s*\"([^\"]+)\"").find(attrs)?.groupValues?.get(1) ?: "normal"
            nm to level
        }.toMap()
    }

    /** 0.92.1: the smali types of the declared components ("Lcom/x/Main;"); a name starting with "." or without a dot is relative to the manifest package. */
    fun componentTypes(manifestPkg: String): List<String> = components.mapNotNull { c ->
        val n = c.name
        if (n == "(unnamed)" || n.isEmpty()) return@mapNotNull null
        val full = if (n.startsWith(".")) manifestPkg + n else if (!n.contains('.')) "$manifestPkg.$n" else n
        "L" + full.replace('.', '/') + ";"
    }

    /** 0.106.0: the smali types of the launcher activities (MAIN + LAUNCHER; an alias counts as its target activity). */
    fun launcherTypes(manifestPkg: String): List<String> = components.filter { it.isLauncher }.mapNotNull { c ->
        val n = c.targetActivity ?: c.name
        if (n == "(unnamed)" || n.isEmpty()) return@mapNotNull null
        val full = if (n.startsWith(".")) manifestPkg + n else if (!n.contains('.')) "$manifestPkg.$n" else n
        "L" + full.replace('.', '/') + ";"
    }

    /** Requested permissions, short names (READ_SMS ...). */
    val permissions: Set<String> by lazy {
        rx("<uses-permission(?:-sdk-23)?\\b[^>]*android:name\\s*=\\s*\"([^\"]+)\"").findAll(xml)
        .map { it.groupValues[1].substringAfterLast('.') }.toSet()
    }

    /**
     * Every component element. Self-closing (<service ... />) and paired tags are both handled; activity-alias must be tried before activity.
     * One malformed element is skipped and counted under "manifest-parse"; it never costs the other components.
     */
    val components: List<ManifestComponent> by lazy {
        val res = ArrayList<ManifestComponent>()
        val compRe = rx("<(activity-alias|activity|service|receiver|provider)(?![\\w-])([^>]*?)(?:/>|>([\\s\\S]*?)</\\1>)")
        for (m in compRe.findAll(xml)) {
            try {
                val tag = m.groupValues[1]
                val headerAttrs = m.groupValues[2]
                val body = m.groupValues[3]
                val name = rx("android:name\\s*=\\s*\"([^\"]+)\"").find(headerAttrs)?.groupValues?.get(1) ?: "(unnamed)"
                val exportedM = rx("android:exported\\s*=\\s*\"(true|false)\"").find(headerAttrs)
                val exported = if (exportedM != null) exportedM.groupValues[1] == "true" else body.contains("<intent-filter")
                val isLauncher = body.contains("android.intent.action.MAIN") && body.contains("android.intent.category.LAUNCHER")
                fun attr(a: String) = rx("android:$a\\s*=\\s*\"([^\"]+)\"").find(headerAttrs)?.groupValues?.get(1)
                res.add(ManifestComponent(tag, headerAttrs, body, name, exported, isLauncher,
                    attr("permission"), attr("readPermission"), attr("writePermission"), attr("targetActivity")))
            } catch (_: Throwable) {
                RuleRegistry.noteError("manifest-parse")
            }
        }
        res
    }

    val exportedComponents: List<ManifestComponent> by lazy { components.filter { it.exported } }

    /** 0.69.0: the <manifest package="..."> value ("" when absent). */
    val packageName: String by lazy {
        rx("<manifest(?![\\w-])[^>]*?\\bpackage\\s*=\\s*\"([^\"]+)\"").find(xml)?.groupValues?.get(1) ?: ""
    }

    /** 0.69.0: "Lcom/x/Foo;" for a manifest class name (".Foo", "Foo" or fully qualified); "" when it cannot be resolved. */
    fun smaliType(name: String): String {
        if (name.isEmpty() || name == "(unnamed)") return ""
        val fq = when {
            name.startsWith(".") -> if (packageName.isEmpty()) return "" else packageName + name
            '.' in name -> name
            else -> if (packageName.isEmpty()) return "" else "$packageName.$name"
        }
        return "L" + fq.replace('.', '/') + ";"
    }

    /** 0.69.0: smali type of the class that actually runs (an activity-alias resolves to its targetActivity). */
    fun smaliTypeOf(c: ManifestComponent): String = smaliType(if (c.tag == "activity-alias") (c.targetActivity ?: "") else c.name)
}

interface ManifestRule {
    val id: String
    val title: String
    /** Weaknesses this rule can report; every one must have an entry in VulnKnowledge (see RuleRegistry.audit). */
    val cwes: List<String> get() = emptyList()
    /** HIGH = explicit structural setting, MEDIUM = inferred from a combination, LOW = informational. */
    val confidence: String get() = "HIGH"
    fun scan(ctx: ManifestContext): List<Finding>
}

/** Base class of the rules that look at exported components one by one; one malformed component is skipped and counted, the rest still run. */
abstract class ManifestComponentRule : ManifestRule {
    protected abstract fun checkComponent(ctx: ManifestContext, c: ManifestComponent, out: MutableList<Finding>)

    final override fun scan(ctx: ManifestContext): List<Finding> {
        val out = ArrayList<Finding>()
        for (c in ctx.exportedComponents) {
            try {
                checkComponent(ctx, c, out)
            } catch (_: Throwable) {
                RuleRegistry.noteError(id)
            }
        }
        return out
    }
}

/** android:debuggable="true" on the application element. */
object ManifestDebuggableRule : ManifestRule {
    override val id = "manifest-debuggable"
    override val title = "Debuggable build"
    override val cwes = listOf("CWE-489")
    override val confidence = "HIGH"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        if (rx("android:debuggable\\s*=\\s*\"true\"").containsMatchIn(xml)) {
            out.add(Finding(Severity.CRITICAL, "Debuggable build",
                "android:debuggable=\"true\" is set. Anyone with the APK (or USB access to the device) can attach a debugger, set breakpoints, dump memory, or step through the logic - including past client-side checks.",
                "Remove android:debuggable, or make sure it is only true in debug build variants and never in what you ship/test for release.",
                cwe = "CWE-489"))
        }
        return out
    }
}

/** android:testOnly="true" (test build marker). 0.42.0: now tagged CWE-489 (it had no CWE before). */
object ManifestTestOnlyRule : ManifestRule {
    override val id = "manifest-test-only"
    override val title = "testOnly flag set"
    override val cwes = listOf("CWE-489")
    override val confidence = "HIGH"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        if (xml.contains("android:testOnly=\"true\"")) {
            out.add(Finding(Severity.MEDIUM, "testOnly flag set",
                "android:testOnly=\"true\" marks this as a test build. Some installers refuse it, and it can carry relaxed, test-only checks.",
                "Remove android:testOnly for anything meant to look/behave like a production build.",
                cwe = "CWE-489"))
        }
        return out
    }
}

/** allowBackup is not explicitly "false" (the default is true). */
object ManifestAllowBackupRule : ManifestRule {
    override val id = "manifest-allow-backup"
    override val title = "Backup allowed (allowBackup)"
    override val cwes = listOf("CWE-530")
    override val confidence = "HIGH"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        if (!rx("android:allowBackup\\s*=\\s*\"false\"").containsMatchIn(xml)) {
            out.add(Finding(Severity.MEDIUM, "Backup allowed (allowBackup)",
                "android:allowBackup is not explicitly \"false\" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.",
                "Set android:allowBackup=\"false\", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.",
                cwe = "CWE-530"))
        }
        return out
    }
}

/** android:usesCleartextTraffic="true". */
object ManifestCleartextTrafficRule : ManifestRule {
    override val id = "manifest-cleartext-traffic"
    override val title = "Cleartext (plain HTTP) traffic allowed"
    override val cwes = listOf("CWE-319")
    override val confidence = "HIGH"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        if (ctx.cleartextTrafficTrue) {
            // 0.81.0: MEDIUM by default (a configuration; real-app sets 4-6: 13 HIGH cards were self-hosted / opt-in setups);
            // FindingPolish.applyNetworkEvidence raises it to HIGH when the app's own code uses a plain-HTTP URL
            out.add(Finding(Severity.MEDIUM, "Cleartext (plain HTTP) traffic allowed",
                "android:usesCleartextTraffic=\"true\" lets the app make plain HTTP requests. Anyone sharing the network (public Wi-Fi, a compromised router) can read or tamper with that traffic.",
                "Set usesCleartextTraffic to \"false\" and use HTTPS everywhere; if a few hosts genuinely need HTTP, scope that with a network security config instead of a blanket allow.",
                cwe = "CWE-319"))
        }
        return out
    }
}

/** No android:networkSecurityConfig (only when cleartext is not already flagged). The risk is inferred from API < 28 defaults, hence MEDIUM. */
object ManifestNetworkSecurityConfigRule : ManifestRule {
    override val id = "manifest-network-security-config"
    override val title = "No network security config referenced"
    override val cwes = listOf("CWE-319")
    override val confidence = "MEDIUM"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        if (!ctx.cleartextTrafficTrue && !xml.contains("networkSecurityConfig")) {
            out.add(Finding(Severity.LOW, "No network security config referenced",
                "No android:networkSecurityConfig is set. On devices running API < 28, cleartext HTTP is allowed by default unless a config says otherwise, so this app's real cleartext posture on older phones is unverified here.",
                "Add a network_security_config.xml with cleartextTrafficPermitted=\"false\" as the base config (and certificate pinning if the app always talks to the same backend).",
                cwe = "CWE-319"))
        }
        return out
    }
}

/** Exported activities reachable through BROWSABLE or custom-scheme links. */
object ManifestDeepLinksRule : ManifestComponentRule() {
    override val id = "manifest-deep-links"
    override val title = "Deep link entry point"
    override val cwes = listOf("CWE-939")
    override val confidence = "MEDIUM"

    override fun checkComponent(ctx: ManifestContext, c: ManifestComponent, out: MutableList<Finding>) {
        val tag = c.tag
        val body = c.body
        val name = c.name
        val dlSchemes = rx("android:scheme\\s*=\\s*\"([^\"]*)\"").findAll(body).map { it.groupValues[1] }.toSet()
        if ((tag == "activity" || tag == "activity-alias") &&
            (body.contains("android.intent.category.BROWSABLE") || dlSchemes.any { it.isNotEmpty() && it != "http" && it != "https" })) {
            val schemes = rx("android:scheme\\s*=\\s*\"([^\"]*)\"").findAll(body).map { it.groupValues[1] }.toSet()
            val hosts = rx("android:host\\s*=\\s*\"([^\"]*)\"").findAll(body).map { it.groupValues[1] }.toSet()
            val web = schemes.any { it == "http" || it == "https" }
            val custom = schemes.any { it != "http" && it != "https" && it.isNotEmpty() }
            val sev = when {
                custom && hosts.isEmpty() -> Severity.MEDIUM
                web && !body.contains("autoVerify") -> Severity.LOW
                else -> Severity.INFO
            }
            out.add(Finding(sev, "Deep link entry point: $name",
                "This activity can be opened from a browser/other apps via ${schemes.joinToString(", ").ifEmpty { "(no scheme listed)" }}://${hosts.joinToString("|")}. " +
                    "Anything in the link (path, query, fragment) is attacker-controlled input" +
                    (if (custom && hosts.isEmpty()) ", and a custom scheme with no host can be claimed by any other installed app (link hijacking)." else ".") +
                    (if (web && !body.contains("autoVerify")) " No android:autoVerify, so the link is not verified as belonging to this app." else ""),
                "Validate every parameter taken from the incoming Intent data (host allow-list, type checks), never load it into a WebView or use it as a file path unchecked; for web links use verified App Links (autoVerify + assetlinks.json).",
                cwe = "CWE-939"))
        }
    }
}

/** Exported activity with a custom taskAffinity and singleTask / singleInstance. */
object ManifestTaskHijackingRule : ManifestComponentRule() {
    override val id = "manifest-task-hijacking"
    override val title = "Task hijacking risk (StrandHogg-style)"
    override val cwes = listOf("CWE-926")
    override val confidence = "MEDIUM"

    override fun checkComponent(ctx: ManifestContext, c: ManifestComponent, out: MutableList<Finding>) {
        val tag = c.tag
        val headerAttrs = c.headerAttrs
        val name = c.name
        if (tag == "activity" || tag == "activity-alias") {
            val launchMode = rx("android:launchMode\\s*=\\s*\"([^\"]+)\"").find(headerAttrs)?.groupValues?.get(1)
            val taskAffinity = rx("android:taskAffinity\\s*=\\s*\"([^\"]*)\"").find(headerAttrs)?.groupValues?.get(1)
            if (!taskAffinity.isNullOrEmpty() && (launchMode == "singleTask" || launchMode == "singleInstance")) {
                out.add(Finding(Severity.MEDIUM, "Task hijacking risk (StrandHogg-style): $name",
                    "This exported activity declares android:taskAffinity=\"$taskAffinity\" together with android:launchMode=\"$launchMode\". A malicious app can declare a matching taskAffinity for one of its own activities and get the system to place it in (or in front of) this app's task, letting it show a convincing fake UI (e.g. a login screen) that the user believes belongs to this app.",
                    "Remove the custom taskAffinity (let it default to the app's own package) unless there is a specific, reviewed reason for it; prefer launchMode=\"standard\" or \"singleTop\" for activities reachable from outside the app.",
                    cwe = "CWE-926"))
            }
        }
    }
}

/** Custom <permission> with protectionLevel normal / dangerous guarding an exported component. */
object ManifestPermissionProtectionRule : ManifestComponentRule() {
    override val id = "manifest-permission-protection"
    override val title = "Exported component guarded by a weak custom permission"
    override val cwes = listOf("CWE-926")
    override val confidence = "HIGH"

    override fun checkComponent(ctx: ManifestContext, c: ManifestComponent, out: MutableList<Finding>) {
        val tag = c.tag
        val headerAttrs = c.headerAttrs
        val name = c.name
        val declaredPerms = ctx.declaredPerms
        val permUsed = rx("android:(?:permission|readPermission|writePermission)\\s*=\\s*\"([^\"]+)\"").find(headerAttrs)?.groupValues?.get(1)
        if (permUsed != null && declaredPerms.containsKey(permUsed)) {
            val lvl = declaredPerms.getValue(permUsed)
            if (lvl == "normal" || lvl == "dangerous") {
                out.add(Finding(Severity.MEDIUM, "Exported $tag guarded by a weak custom permission: $name",
                    "The permission protecting this $tag (\"$permUsed\") is declared with android:protectionLevel=\"$lvl\". Unlike \"signature\", a normal/dangerous permission is not tied to the app's signing key - any other app can request it in its own manifest (a dangerous one may need a one-time user grant, a normal one is silent) and then use this component freely.",
                    "Declare the permission with android:protectionLevel=\"signature\" if only your own apps (same signing key) should use this component, or review whether exporting it at all is necessary.",
                    cwe = "CWE-926"))
            }
        }
    }
}

/** Exported activity / service / receiver / provider with no permission (exported = explicit android:exported, else an <intent-filter> is present); the launcher is skipped. */
object ManifestExportedComponentsRule : ManifestComponentRule() {
    override val id = "manifest-exported-components"
    override val title = "Exported component without a permission"
    override val cwes = listOf("CWE-926")
    override val confidence = "HIGH"

    override fun checkComponent(ctx: ManifestContext, c: ManifestComponent, out: MutableList<Finding>) {
        val tag = c.tag
        val headerAttrs = c.headerAttrs
        val name = c.name
        val isLauncher = c.isLauncher
        val protectedBy = if (tag == "provider") rx("android:(permission|readPermission|writePermission)\\b") else rx("android:permission\\b")
        if (!protectedBy.containsMatchIn(headerAttrs) && !isLauncher) {
            var sev = if (tag == "provider") Severity.HIGH else Severity.MEDIUM
            // 0.49.1: a component whose ONLY intent-filter actions are public entry points (VIEW/SEND/EDIT/PICK/widget/...) must be
            // exported by design. Lowered, never dropped; the reason goes into Finding.adjusted below.
            var why = ""
            if (tag != "provider") {
                val acts = rx("<action\\s+android:name\\s*=\\s*\"([^\"]+)\"").findAll(c.body).map { it.groupValues[1].substringAfterLast('.') }.toSet()
                if (acts.isNotEmpty() && acts.all { it in SYSTEM_ONLY_ACTIONS }) {
                    sev = Severity.INFO; why = "Lowered to INFO: only system-sent broadcast actions (other apps cannot forge them on modern Android)."
                } else if (acts.isNotEmpty() && acts.all { it in SYSTEM_ONLY_ACTIONS || it in PUBLIC_ENTRY_ACTIONS }) {
                    sev = Severity.LOW; why = "Lowered to LOW: exported by design (public entry action: ${acts.joinToString(", ")})."
                }
            }
            val extra = if (tag == "provider")
                " A ContentProvider exported with no permission can let any app on the device query/insert/update/delete its data; if it builds file paths or SQL from the incoming Uri, that's also a path-traversal / SQL-injection surface."
            else " Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller."
            out.add(Finding(sev, "Exported $tag without a permission: $name",
                "This $tag is exported (usable by other apps) and declares no android:permission.$extra",
                "Add android:permission=\"...\" (a signature-level permission for same-app-only access is often right), or set android:exported=\"false\" if other apps never need to use it.",
                cwe = "CWE-926").also { if (why.isNotEmpty()) it.adjusted = why })
        }
    }

    private val SYSTEM_ONLY_ACTIONS = setOf(
        "BOOT_COMPLETED", "QUICKBOOT_POWERON", "APPWIDGET_UPDATE", "APPWIDGET_ENABLED", "APPWIDGET_DELETED", "APPWIDGET_DISABLED",
        "MY_PACKAGE_REPLACED", "LOCKED_BOOT_COMPLETED", "TIMEZONE_CHANGED"
    )
    private val PUBLIC_ENTRY_ACTIONS = setOf(
        "MAIN", "VIEW", "SEND", "SEND_MULTIPLE", "EDIT", "PICK", "GET_CONTENT", "PROCESS_TEXT", "ATTACH_DATA", "SET_WALLPAPER",
        "REVIEW", "CROP", "APPLICATION_PREFERENCES", "APPWIDGET_CONFIGURE", "QS_TILE", "MEDIA_BUTTON", "MediaBrowserService",
        "MEDIA_PLAY_FROM_SEARCH", "NDEF_DISCOVERED", "DOCUMENTS_PROVIDER", "SEARCH", "WEB_SEARCH", "OPEN_DOCUMENT"
    )
}

/** Exported provider with readPermission XOR writePermission. */
object ManifestProviderPartialPermissionRule : ManifestComponentRule() {
    override val id = "manifest-provider-partial-permission"
    override val title = "Exported provider protects only reads or writes"
    override val cwes = listOf("CWE-926")
    override val confidence = "HIGH"

    override fun checkComponent(ctx: ManifestContext, c: ManifestComponent, out: MutableList<Finding>) {
        val tag = c.tag
        val headerAttrs = c.headerAttrs
        val name = c.name
        if (tag == "provider" && !rx("android:permission\\b").containsMatchIn(headerAttrs)) {
            val hasR = headerAttrs.contains("android:readPermission")
            val hasW = headerAttrs.contains("android:writePermission")
            if (hasR != hasW) {
                out.add(Finding(Severity.MEDIUM, "Exported provider protects only " + (if (hasR) "reads" else "writes") + ": $name",
                    "This exported provider declares " + (if (hasR) "android:readPermission but no writePermission, so any app can insert / update / delete its data."
                        else "android:writePermission but no readPermission, so any app can read its data."),
                    "Declare both readPermission and writePermission (signature level if only your own apps need it), or use android:permission for both.",
                    cwe = "CWE-926"))
            }
        }
    }
}

/** Exported provider with grantUriPermissions="true" on the whole provider. */
object ManifestProviderGrantUriRule : ManifestComponentRule() {
    override val id = "manifest-exported-provider-grant-uri"
    override val title = "Provider grants URI permissions broadly"
    override val cwes = listOf("CWE-200")
    override val confidence = "MEDIUM"

    override fun checkComponent(ctx: ManifestContext, c: ManifestComponent, out: MutableList<Finding>) {
        val tag = c.tag
        val headerAttrs = c.headerAttrs
        val name = c.name
        if (tag == "provider" && headerAttrs.contains("grantUriPermissions=\"true\"")) {
            out.add(Finding(Severity.MEDIUM, "Provider grants URI permissions broadly: $name",
                "android:grantUriPermissions=\"true\" on the whole provider lets any Intent that carries a content:// Uri of it hand temporary access to the receiving app, for every path of the provider.",
                "Limit it with <grant-uri-permission android:path/pathPrefix=...> to only the paths that must be shared, and check the FileProvider paths XML does not expose root-path or the whole external storage.",
                cwe = "CWE-200"))
        }
    }
}

/** Requested permissions from the powerful list (SMS, overlay, install packages ...). */
object ManifestPowerfulPermissionsRule : ManifestRule {
    override val id = "manifest-powerful-permissions"
    override val title = "Powerful permissions requested"
    override val cwes = listOf("CWE-250")
    override val confidence = "HIGH"

    private val mediumPerms = mapOf(
        "SYSTEM_ALERT_WINDOW" to "draws over other apps (overlay / tapjacking / phishing UI)",
        "MANAGE_EXTERNAL_STORAGE" to "all-files access to shared storage",
        "READ_SMS" to "reads SMS (OTP codes can be stolen)",
        "RECEIVE_SMS" to "receives SMS (OTP codes can be stolen)",
        "SEND_SMS" to "sends SMS (premium-rate fraud)",
        "READ_CALL_LOG" to "reads the call log",
        "PROCESS_OUTGOING_CALLS" to "intercepts outgoing calls",
        "REQUEST_INSTALL_PACKAGES" to "can install other APKs",
        "BIND_ACCESSIBILITY_SERVICE" to "accessibility service (can read the screen / inject taps)",
        "BIND_DEVICE_ADMIN" to "device admin",
        "WRITE_SECURE_SETTINGS" to "changes secure system settings",
        "READ_PHONE_NUMBERS" to "reads the phone number",
        "ACCESS_BACKGROUND_LOCATION" to "tracks location in the background"
    )

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        val perms = ctx.permissions
        val risky = perms.filter { it in mediumPerms }
        if (risky.isNotEmpty()) {
            out.add(Finding(Severity.MEDIUM, "Powerful permissions requested (${risky.size})",
                risky.joinToString("\n") { "- $it: ${mediumPerms[it]}" },
                "Request only what the feature really needs, and prefer the narrower alternative (photo picker, SAF, SMS Retriever / User Consent API instead of READ_SMS).",
                cwe = "CWE-250"))
        }
        return out
    }
}

/** Requested permissions from the sensitive-data list (INFO, informational). */
object ManifestSensitivePermissionsRule : ManifestRule {
    override val id = "manifest-sensitive-permissions"
    override val title = "Sensitive-data permissions"
    override val cwes = emptyList<String>()
    override val confidence = "LOW"

    private val infoPerms = setOf(
        "READ_CONTACTS", "WRITE_CONTACTS", "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION",
        "READ_PHONE_STATE", "GET_ACCOUNTS", "READ_CALENDAR", "BODY_SENSORS", "QUERY_ALL_PACKAGES",
        "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE", "READ_MEDIA_IMAGES", "READ_MEDIA_VIDEO"
    )

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        val perms = ctx.permissions
        val dangerous = perms.filter { it in infoPerms }
        if (dangerous.isNotEmpty()) {
            out.add(Finding(Severity.INFO, "Sensitive-data permissions (${dangerous.size})",
                dangerous.joinToString(", "),
                "Make sure each one is justified in the privacy policy and requested at the moment of use, not at startup."))
        }
        return out
    }
}

/** minSdkVersion below 23. */
object ManifestMinSdkRule : ManifestRule {
    override val id = "manifest-min-sdk"
    override val title = "Low minSdkVersion"
    override val cwes = emptyList<String>()
    override val confidence = "LOW"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        val minSdk = (rx("minSdkVersion\\s*=\\s*\"?(\\d+)").find(xml) ?: rx("minSdk\\s*=\\s*\"?(\\d+)").find(xml))
            ?.groupValues?.get(1)?.toIntOrNull()
        if (minSdk != null && minSdk < 23) {
            out.add(Finding(Severity.LOW, "Low minSdkVersion ($minSdk)",
                "Supporting API < 23 (Android 6) means the app can run on devices without runtime permission prompts and with older TLS/cipher defaults.",
                "Raise minSdkVersion if the user base allows it; otherwise double check that sensitive permissions and network calls are still handled safely on the oldest supported devices."))
        }
        return out
    }
}

/** targetSdkVersion 30 or lower. */
object ManifestTargetSdkRule : ManifestRule {
    override val id = "manifest-target-sdk"
    override val title = "Old targetSdkVersion"
    override val cwes = emptyList<String>()
    override val confidence = "LOW"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        // 0.39.0: app-level flags
        val targetSdk = rx("targetSdkVersion\\s*=\\s*\"?(\\d+)").find(xml)?.groupValues?.get(1)?.toIntOrNull()
        if (targetSdk != null && targetSdk in 1..30) {
            out.add(Finding(if (targetSdk < 24) Severity.MEDIUM else Severity.LOW, "Old targetSdkVersion ($targetSdk)",
                "The app targets API $targetSdk, so Android keeps legacy behaviour for it" +
                    (if (targetSdk < 24) ": user-installed CAs are trusted by default (easier HTTPS interception)" else "") +
                    (if (targetSdk < 28) ", cleartext HTTP is allowed by default" else "") +
                    (if (targetSdk < 31) ", components with an intent-filter are exported by default and PendingIntents are mutable by default" else "") +
                    ", and newer privacy / storage protections do not apply to it.",
                "Raise targetSdkVersion to a current API level and re-test; this is the cheapest way to get many OS-level protections."))
        }
        return out
    }
}

/** android:sharedUserId declared. */
object ManifestSharedUserIdRule : ManifestRule {
    override val id = "manifest-shared-user-id"
    override val title = "sharedUserId set"
    override val cwes = listOf("CWE-266")
    override val confidence = "HIGH"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        rx("android:sharedUserId\\s*=\\s*\"([^\"]+)\"").find(xml)?.let {
            out.add(Finding(Severity.LOW, "sharedUserId set (${it.groupValues[1]})",
                "Apps signed with the same key that declare this sharedUserId run under one Linux UID: they can read each other's private files and share permissions, so one weak app weakens all of them. The attribute is deprecated since API 29.",
                "Remove sharedUserId and share data through explicit, permission-protected providers/services.",
                cwe = "CWE-266"))
        }
        return out
    }
}

/** android:requestLegacyExternalStorage="true". */
object ManifestLegacyExternalStorageRule : ManifestRule {
    override val id = "manifest-legacy-external-storage"
    override val title = "Legacy external storage requested"
    override val cwes = listOf("CWE-922")
    override val confidence = "HIGH"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        if (rx("android:requestLegacyExternalStorage\\s*=\\s*\"true\"").containsMatchIn(xml)) {
            out.add(Finding(Severity.LOW, "Legacy external storage requested",
                "android:requestLegacyExternalStorage=\"true\" opts out of scoped storage, so files the app writes to shared storage stay readable (and replaceable) by other apps that hold the storage permission.",
                "Migrate to scoped storage (MediaStore / SAF / getExternalFilesDir) and remove the flag.",
                cwe = "CWE-922"))
        }
        return out
    }
}

/** An AccessibilityService is declared (legitimate for accessibility tools, abused by overlay malware). */
object ManifestAccessibilityServiceRule : ManifestRule {
    override val id = "manifest-accessibility-service"
    override val title = "Accessibility service declared"
    override val cwes = listOf("CWE-250")
    override val confidence = "LOW"

    override fun scan(ctx: ManifestContext): List<Finding> {
        val xml = ctx.xml
        val out = ArrayList<Finding>()
        if (xml.contains("android.accessibilityservice.AccessibilityService")) {
            out.add(Finding(Severity.LOW, "Accessibility service declared",
                "The app declares an AccessibilityService. It is legitimate for accessibility tools, but it can read everything shown on screen (passwords excluded only partly) and perform taps, which is why overlay / banking malware abuses it.",
                "Confirm the app really needs it, keep its configuration (accessibility_service_config) as narrow as possible and never act on content from other apps unchecked.",
                cwe = "CWE-250"))
        }
        return out
    }
}
