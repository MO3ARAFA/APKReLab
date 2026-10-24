package dev.apkrelab

import android.app.Activity
import android.app.AlertDialog
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInstaller
import android.os.Build
import android.provider.Settings
import android.view.WindowManager
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.view.ViewGroup
import android.widget.FrameLayout
import android.net.Uri
import android.os.Bundle
import android.text.Editable
import android.text.InputType
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.TextWatcher
import android.text.style.BackgroundColorSpan
import android.text.style.ForegroundColorSpan
import android.text.style.RelativeSizeSpan
import android.text.style.StyleSpan
import android.text.style.TypefaceSpan
import android.view.Gravity
import android.view.View
import android.view.inputmethod.InputMethodManager
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ListView
import android.widget.ScrollView
import android.widget.Toast
import android.widget.TextView
import com.android.tools.smali.baksmali.Adaptors.ClassDefinition
import com.android.tools.smali.baksmali.BaksmaliOptions
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.reandroid.apk.ApkModule
import org.json.JSONArray
import org.json.JSONObject
import java.io.StringWriter
import java.io.File
import java.util.zip.ZipFile

class MainActivity : Activity() {

    private class Row(
        val label: String,
        val folder: String? = null,
        val isUp: Boolean = false,
        val file: String? = null,
        val cls: Int = -1,
        val at: Int = -1   // 0.13.0: char offset to scroll to (code-search hits)
    )

    private class Result(
        val info: String,
        val manifest: String,
        val entries: List<Pair<String, Long>>,
        val module: ApkModule
    )

    private val pickRequest = 1001
    private val exportRequest = 1002
    private val exportKeyRequest = 1003
    private val importKeyRequest = 1004
    private val reportRequest = 1005
    private val stringsRequest = 1007                                  // 0.102.0: decoded-strings dump (StringOverlay)
    private val attachRequest = 1006                                   // 0.37.5: AI Hub chat attachments
    private var attachCallback: ((List<Uri>) -> Unit)? = null          // set by the open AI Hub dialog, cleared when it closes
    private var pendingReport: String? = null
    private class ReportItem(val title: String, val subject: String, val text: String)
    private val reportItems = ArrayList<ReportItem>()
    private var pendingKeyPwd: CharArray? = null
    private val installAction = "dev.apkrelab.INSTALL_RESULT"
    @Volatile private var lastInstall = ""            // 0.30.0: result of the last install, read by the AI Hub tool
    private var selTabFn: (Int) -> Unit = { }          // 0.30.0: lets the AI Hub switch the bottom tab highlight

    private lateinit var info: TextView
    // 0.24.0: hero header
    private lateinit var heroTitle: TextView
    private lateinit var heroTag: TextView
    private lateinit var heroNote: TextView
    private lateinit var heroArt: Ui.HeroArt
    private lateinit var navBar: LinearLayout
    private lateinit var heroBox: FrameLayout
    private lateinit var heroCol: LinearLayout
    private lateinit var heroSpacer: View
    private lateinit var ctaBtn: Button
    private lateinit var pickChip: Button
    private lateinit var aiHubChip: Button
    private lateinit var sheetRoot: LinearLayout
    private var heroCompact = false
    private val MATCH = ViewGroup.LayoutParams.MATCH_PARENT
    private val WRAP = ViewGroup.LayoutParams.WRAP_CONTENT
    private lateinit var pathView: TextView
    private lateinit var list: ListView
    private lateinit var contentScroll: ScrollView
    private lateinit var contentText: TextView

    private var entries: List<Pair<String, Long>> = emptyList()
    private var currentPath = ""
    private var rows: List<Row> = emptyList()
    private var manifestFull = ""
    private var viewingFile = false
    private var apkModule: ApkModule? = null

    private lateinit var search: EditText
    private lateinit var codeSearchBtn: Button
    @Volatile private var codeSearching = false
    @Volatile private var codeSearchCancel = false
    private var listTitle = ""
    // 0.101.0: the long scan diagnostics (groups, timings, taint losses ...) used to fill half of the Security screen under the counters; they stay in the report, and here one tap shows them
    private var scanDetail = ""
    private var scanDetailOpen = false
    private fun scanTail(): String =
        if (scanDetail.isEmpty()) ""
        else if (scanDetailOpen) "\n[" + scanDetail + "]  (tap to hide)"
        else "  ·  " + scanDetail.substringBefore(" (").take(70) + "  (tap for scan details)"
    private var classDefs: List<ClassDef> = emptyList()
    private var inClasses = false
    private var indexing = false
    // 0.36.0 background indexing: apkGen changes for every APK load, so work started for an old APK drops its result
    @Volatile private var apkGen = 0
    @Volatile private var bgIndexCancel = false
    private var infoBase = ""
    private var deepAfterIndex = false
    private val indexLock = Any()

    // ---------- security scan (0.18.0) ----------
    private var inSecurity = false
    private var secFindings: List<SecurityScanner.Finding> = emptyList()
    private var currentFinding: SecurityScanner.Finding? = null
    private lateinit var secScanBtn: Button
    private lateinit var secActions: LinearLayout
    @Volatile private var secScanning = false
    @Volatile private var secScanCancel = false
    // 0.21.0: filters, AI triage, jump-from-finding context
    private lateinit var secBar: LinearLayout
    private lateinit var secCmpBar: LinearLayout   // 0.71.0: Save baseline / Compare
    private lateinit var secFilterBtn: Button
    private lateinit var secLibBtn: Button
    private lateinit var secTriageBtn: Button
    // 0.46.0: INFO is hidden by default (alert fatigue); the chip row and the "ALL" filter step still reach it for auditing
    private var secMinRank = 3            // 4 = everything, 3 = LOW and up (default), 2 = MEDIUM and up, 1 = HIGH and up
    private var secOnly = -1              // 0.37.13: >= 0 = only this severity rank (set by the counter chips)
    private lateinit var secChips: LinearLayout
    private var secShowLibs = false       // findings inside known third-party library packages
    private var jumpFinding: SecurityScanner.Finding? = null
    @Volatile private var triageRunning = false
    @Volatile private var triageCancel = false
    // 0.22.0: Smart scan (manifest + deep scan + AI triage in one go) and the Top-5 summary
    private lateinit var secSmartBtn: Button
    private lateinit var secBenchBtn: Button
    private lateinit var secTopBtn: Button
    @Volatile private var smartRunning = false
    @Volatile private var smartStopped = false
    private var smartStep = ""
    private var scanDoneCb: (() -> Unit)? = null
    private var triageDoneCb: (() -> Unit)? = null
    private var secSummary = false
    // 0.23.0: call graph (reverse index) built during Deep scan, exported-component map
    @Volatile private var callIdx: SecurityScanner.CallIndex? = null
    private var entryMap: Map<String, String>? = null
    private var actionMap: Map<String, List<String>>? = null   // 0.50.0: component type -> custom intent-filter actions

    private lateinit var actions: LinearLayout
    private lateinit var actions2: LinearLayout
    private lateinit var actions3: LinearLayout
    private lateinit var javaBtn: Button
    private var javaMode = false           // 0.37.0: the content area shows the jadx Java view (read-only); currentRaw stays smali
    private var currentJava = ""
    private val javaLock = Any()
    private lateinit var manifestActions: LinearLayout
    private var currentRaw = ""

    // 0.7.0 editing state
    private lateinit var editScroll: ScrollView
    private lateinit var editor: EditText
    private lateinit var editActions: LinearLayout
    private var editing = false
    private var currentClassIndex = -1
    private var currentOrig = ""
    private var currentEditable = false
    private val modified = HashSet<String>()
    private val classDex = HashMap<String, String>()

    // 0.8.0 build state
    private lateinit var buildActions: LinearLayout
    private lateinit var buildActions2: LinearLayout
    private lateinit var buildScroll: ScrollView
    private lateinit var buildStatus: TextView
    private lateinit var clsRow: LinearLayout
    private lateinit var clsLibBtn: Button
    private var clsAppOnly = true             // 0.37.15: Classes tab hides known library packages by default
    private lateinit var buildLog: TextView
    private val buildText: StringBuilder get() = BuildService.text
    private var building: Boolean
        get() = BuildService.running
        set(v) { BuildService.running = v }
    private val wsDir: File get() = File(filesDir, "workspaces/p1")
    private val signedFile: File get() = File(wsDir, "out/signed.apk")
    private val splitsDir: File get() = File(wsDir, "out/splits")

    private val installReceiver = object : BroadcastReceiver() {
        @Suppress("DEPRECATION")
        override fun onReceive(c: Context, i: Intent) {
            val status = i.getIntExtra(PackageInstaller.EXTRA_STATUS, -999)
            val msg = i.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
            when (status) {
                PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                    val confirm = i.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                    if (confirm != null) startActivity(confirm)
                }
                PackageInstaller.STATUS_SUCCESS -> { lastInstall = "SUCCESS"; blog("Install: SUCCESS - open the app from your launcher.") }
                else -> {
                    lastInstall = "FAILED (status $status): $msg"
                    blog("Install failed (status $status): $msg")
                    if (msg.contains("INCOMPATIBLE", true) || msg.contains("signatures", true) || status == PackageInstaller.STATUS_FAILURE_CONFLICT) {
                        blog("Signature differs from the installed app. Tap 'Uninstall original' first (the app's data will be deleted), then Install.")
                    }
                }
            }
        }
    }

    /**
     * 0.60.1: opening animation. A black layer sits over the app for about a second: the cobra pops in with a small overshoot, a soft green glow
     * grows and pulses once, then the layer fades out into the app. A tap skips it. Cold start only (savedInstanceState == null). No library.
     */
    private fun playIntro() {
        val root = window.decorView as? android.view.ViewGroup ?: return
        val dn = resources.displayMetrics.density
        // 0.96.0: dark system bars under the black intro (a light look left a white strip under the logo); setupWindow() restores them when the intro closes
        window.statusBarColor = 0xFF060A09.toInt(); window.navigationBarColor = 0xFF060A09.toInt()
        if (Build.VERSION.SDK_INT >= 29) { window.isNavigationBarContrastEnforced = false; window.isStatusBarContrastEnforced = false }
        if (Build.VERSION.SDK_INT >= 30) window.insetsController?.setSystemBarsAppearance(0,
            android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS)
        val overlay = FrameLayout(this)
        overlay.setBackgroundColor(android.graphics.Color.BLACK)
        val glowSize = (320 * dn).toInt()
        val gd = android.graphics.drawable.GradientDrawable()
        gd.gradientType = android.graphics.drawable.GradientDrawable.RADIAL_GRADIENT
        gd.gradientRadius = glowSize / 2f
        gd.colors = intArrayOf(0x5546E57A, 0x00000000)
        val glow = android.view.View(this)
        glow.background = gd
        overlay.addView(glow, FrameLayout.LayoutParams(glowSize, glowSize, Gravity.CENTER))
        val logo = android.widget.ImageView(this)
        logo.setImageResource(dev.apkrelab.R.mipmap.ic_launcher_foreground)
        val logoSize = (220 * dn).toInt()
        overlay.addView(logo, FrameLayout.LayoutParams(logoSize, logoSize, Gravity.CENTER))
        // 0.60.2: signature at the bottom, like "from Meta" on the WhatsApp start screen
        val brand = LinearLayout(this)
        brand.orientation = LinearLayout.VERTICAL
        brand.gravity = Gravity.CENTER_HORIZONTAL
        val by = TextView(this)
        by.text = "CRAFTED BY"
        by.textSize = 10f
        by.setTextColor(0xFF6E8F82.toInt())
        by.letterSpacing = 0.25f
        by.gravity = Gravity.CENTER_HORIZONTAL
        val name = TextView(this)
        name.text = "D U C C A"
        name.textSize = 14f
        name.typeface = Typeface.DEFAULT_BOLD
        name.setTextColor(0xFFF0FDF4.toInt())
        name.letterSpacing = 0.38f
        name.gravity = Gravity.CENTER_HORIZONTAL
        brand.addView(by, LinearLayout.LayoutParams(WRAP, WRAP).apply { gravity = Gravity.CENTER_HORIZONTAL })
        brand.addView(name, LinearLayout.LayoutParams(WRAP, WRAP).apply { gravity = Gravity.CENTER_HORIZONTAL; topMargin = (4 * dn).toInt() })
        val bp = FrameLayout.LayoutParams(WRAP, WRAP, Gravity.BOTTOM or Gravity.CENTER_HORIZONTAL)
        bp.bottomMargin = (36 * dn).toInt()
        overlay.addView(brand, bp)
        // above the navigation bar: 36 dp plus the bottom inset
        overlay.setOnApplyWindowInsetsListener { _, ins ->
            @Suppress("DEPRECATION") val bottomInset = ins.systemWindowInsetBottom
            bp.bottomMargin = (36 * dn).toInt() + bottomInset
            brand.layoutParams = bp
            ins
        }
        brand.alpha = 0f
        brand.animate().alpha(1f).setStartDelay(250).setDuration(600).start()
        var closed = false
        fun close() {
            if (closed) return
            closed = true
            setupWindow()      // 0.96.0: the system bars of the chosen look
            overlay.animate().cancel()
            logo.animate().cancel()
            glow.animate().cancel()
            logo.animate().scaleX(1.12f).scaleY(1.12f).setDuration(320).start()
            overlay.animate().alpha(0f).setDuration(320).withEndAction { root.removeView(overlay) }.start()
        }
        overlay.setOnClickListener { close() }
        root.addView(overlay, android.view.ViewGroup.LayoutParams(android.view.ViewGroup.LayoutParams.MATCH_PARENT, android.view.ViewGroup.LayoutParams.MATCH_PARENT))
        logo.alpha = 0f
        logo.scaleX = 0.55f
        logo.scaleY = 0.55f
        logo.translationY = 28 * dn
        glow.alpha = 0f
        glow.scaleX = 0.5f
        glow.scaleY = 0.5f
        glow.animate().alpha(1f).scaleX(1f).scaleY(1f).setDuration(700)
            .setInterpolator(android.view.animation.DecelerateInterpolator()).start()
        logo.animate().alpha(1f).scaleX(1f).scaleY(1f).translationY(0f).setStartDelay(60).setDuration(560)
            .setInterpolator(android.view.animation.OvershootInterpolator(1.5f))
            .withEndAction {
                glow.animate().scaleX(1.25f).scaleY(1.25f).setDuration(380)
                    .withEndAction { overlay.postDelayed({ close() }, 120) }.start()
            }.start()
        overlay.postDelayed({ close() }, 2500)      // safety: never keep the layer longer than this
    }

    private val apkFile: File get() = File(filesDir, "workspaces/p1/original.apk")

    override fun onCreate(savedInstanceState: Bundle?) {
        setTheme(Ui.themeRes(this))
        super.onCreate(savedInstanceState)
        Ui.init(this)
        SigningKey.init(this)
        AiCache.init(this)
        val d = resources.displayMetrics.density
        val pad = (16 * d).toInt()

        val outer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = Ui.AmbientDrawable()
        }
        heroBox = FrameLayout(this)
        heroArt = Ui.HeroArt(this)
        heroBox.addView(heroArt, FrameLayout.LayoutParams(MATCH, MATCH))
        heroCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, Ui.dp(34), pad, Ui.dp(10))
        }
        heroBox.addView(heroCol, FrameLayout.LayoutParams(MATCH, WRAP))
        heroTitle = TextView(this).apply {
            text = "APK ReLab"
            textSize = 34f
            setTextColor(Ui.p.heroInk)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER_HORIZONTAL
        }
        heroTag = TextView(this).apply {
            text = "Reverse engineering & security review"
            textSize = 13f
            setTextColor(Ui.alpha(Ui.p.heroInk, 0xCC))
            gravity = Gravity.CENTER_HORIZONTAL
        }
        heroNote = TextView(this).apply {
            text = "For educational use on apps you own or are authorized to analyze only."
            textSize = 11f
            setTextColor(Ui.alpha(Ui.p.heroInk, 0xB3))
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(Ui.dp(12), Ui.dp(6), Ui.dp(12), 0)
        }
        info = TextView(this).apply {
            text = "Select an APK to analyze"
            textSize = 13f
            setTextColor(Ui.p.heroInk)
            gravity = Gravity.CENTER_HORIZONTAL
            maxLines = 2
            setPadding(Ui.dp(2), Ui.dp(10), Ui.dp(2), Ui.dp(6))
        }
        heroCol.addView(heroTitle, LinearLayout.LayoutParams(MATCH, WRAP))
        heroCol.addView(heroTag, LinearLayout.LayoutParams(MATCH, WRAP))
        heroCol.addView(heroNote, LinearLayout.LayoutParams(MATCH, WRAP))
        heroSpacer = View(this)
        heroCol.addView(heroSpacer, LinearLayout.LayoutParams(MATCH, 0, 1f))
        heroCol.addView(info, LinearLayout.LayoutParams(MATCH, WRAP))
        ctaBtn = Button(this).apply {
            text = "Select APK"
            textSize = 16f
            setOnClickListener { openPicker() }
        }
        heroCol.addView(ctaBtn, LinearLayout.LayoutParams(MATCH, WRAP).apply { topMargin = Ui.dp(6) })
        Ui.cta(ctaBtn)
        val chips = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        fun chip(label: String, main: Boolean, weight: Float, onClick: () -> Unit): Button {
            val b = Button(this@MainActivity).apply {
                text = label
                textSize = 12f
                setOnClickListener { onClick() }
            }
            chips.addView(b, LinearLayout.LayoutParams(0, WRAP, weight))
            if (main) Ui.accent(b) else Ui.glass(b)
            return b
        }
        pickChip = chip("Select APK", true, 1.4f) { openPicker() }
        chip("Installed", false, 1f) { openPicker { showInstalledApps() } }   // 0.102.0: pick an installed app (base + splits) instead of a file
        chip("Last APK", false, 1f) { guardEdit { openLast() } }
        aiHubChip = chip("AI Hub", false, 1f) { showAgentChat() }
        chip("⚙ AI", false, 0.8f) { showSettings() }
        chip("Report", false, 1f) { exportReport() }
        heroCol.addView(chips, LinearLayout.LayoutParams(MATCH, WRAP))

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = Ui.glassBg(Ui.p.glass, 30)
            setPadding(Ui.dp(14), Ui.dp(16), Ui.dp(14), Ui.dp(10))
        }
        sheetRoot = root
        outer.addView(heroBox, LinearLayout.LayoutParams(MATCH, WRAP))
        outer.addView(root, LinearLayout.LayoutParams(MATCH, 0, 1f).apply { setMargins(Ui.dp(10), Ui.dp(2), Ui.dp(10), 0) })
        outer.setOnApplyWindowInsetsListener { _, ins ->
            var top = 0
            var bottom = 0
            if (Build.VERSION.SDK_INT >= 30) {
                val bars = ins.getInsets(android.view.WindowInsets.Type.systemBars() or android.view.WindowInsets.Type.ime())
                top = bars.top
                bottom = bars.bottom
            } else {
                top = ins.systemWindowInsetTop
                bottom = ins.systemWindowInsetBottom
            }
            heroArt.bottomInset = bottom
            heroCol.setPadding(pad, top + (if (heroCompact) Ui.dp(10) else Ui.dp(24)), pad,
                if (heroCompact) Ui.dp(10) else bottom + Ui.dp(20))
            val imeUp = bottom > Ui.dp(120)
            navBar.visibility = if (imeUp || !heroCompact) View.GONE else View.VISIBLE
            navBar.setPadding(Ui.dp(14), Ui.dp(8), Ui.dp(14), bottom + Ui.dp(8))
            root.setPadding(Ui.dp(14), Ui.dp(16), Ui.dp(14), if (imeUp) bottom + Ui.dp(10) else Ui.dp(10))
            ins
        }

        val tabs = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val filesBtn = Button(this).apply { text = "Files"; textSize = 11f; isAllCaps = false; setPadding(2, 0, 2, 0) }
        val manifestBtn = Button(this).apply { text = "Manifest"; textSize = 11f; isAllCaps = false; setPadding(2, 0, 2, 0) }
        val classesBtn = Button(this).apply { text = "Classes"; textSize = 11f; isAllCaps = false; setPadding(2, 0, 2, 0) }
        val buildBtn = Button(this).apply { text = "Build"; textSize = 11f; isAllCaps = false; setPadding(2, 0, 2, 0) }
        val securityBtn = Button(this).apply { text = "Security"; textSize = 11f; isAllCaps = false; setPadding(2, 0, 2, 0) }
        val tabBtns = listOf(filesBtn, manifestBtn, classesBtn, buildBtn, securityBtn)
        val navKinds = listOf("folder", "doc", "code", "cube", "shield")
        val navNames = listOf("Files", "Manifest", "Classes", "Build", "Security")
        val sheetTitle = TextView(this).apply {
            textSize = 26f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Ui.p.ink)
            setPadding(Ui.dp(4), 0, Ui.dp(4), Ui.dp(4))
        }
        root.addView(sheetTitle, LinearLayout.LayoutParams(MATCH, WRAP))
        // 0.37.9: floating glass pill (5 tabs) + a separate round glass button for the AI Hub; transparent holder keeps the system-bar inset
        navBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(Ui.dp(14), Ui.dp(8), Ui.dp(14), Ui.dp(8))
        }
        val navPill = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            background = Ui.GlassDrawable(40, Ui.p.glassHi)
            setPadding(Ui.dp(5), Ui.dp(5), Ui.dp(5), Ui.dp(5))
        }
        val navItems = ArrayList<Ui.NavItem>()
        for (k in 0 until 5) {
            val ni = Ui.NavItem(this, navKinds[k], navNames[k])
            val tb = tabBtns[k]
            ni.setOnClickListener { tb.performClick() }
            navItems.add(ni)
            navPill.addView(ni, LinearLayout.LayoutParams(0, WRAP, 1f))
        }
        navBar.addView(navPill, LinearLayout.LayoutParams(0, WRAP, 1f))
        val aiNav = Ui.IconView(this)
        aiNav.scale = 0.42f
        aiNav.setup("spark", Ui.p.hi, 0)
        aiNav.background = Ui.ripple(if (Ui.p.outline != 0) Ui.rr(0xFF0F2920.toInt(), 40, Ui.p.hi, 1) else Ui.GlassDrawable(40, Ui.p.glassHi), 40)
        aiNav.setOnClickListener { showAgentChat() }
        navBar.addView(aiNav, LinearLayout.LayoutParams(Ui.dp(62), Ui.dp(62)).apply { leftMargin = Ui.dp(10) })
        outer.addView(navBar, LinearLayout.LayoutParams(MATCH, WRAP))
        fun selTab(i: Int) {
            for ((k, ni) in navItems.withIndex()) ni.select(k == i)
            sheetTitle.text = navNames[i]
            root.alpha = 0.55f
            root.animate().alpha(1f).setDuration(200).start()
        }
        selTabFn = { i -> selTab(i) }

        search = EditText(this).apply {
            hint = "search class (e.g. MainActivity)"
            textSize = 13f
            setSingleLine()
            visibility = View.GONE
            addTextChangedListener(object : TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, st: Int, c: Int, a: Int) {}
                override fun onTextChanged(s: CharSequence?, st: Int, b: Int, c: Int) {}
                override fun afterTextChanged(s: Editable?) { if (inClasses && classDefs.isNotEmpty() && !codeSearching) showClasses() }
            })
        }
        root.addView(search)
        codeSearchBtn = Button(this).apply {
            text = "Code search (all classes)"
            textSize = 12f
            visibility = View.GONE
            setOnClickListener { if (codeSearching) codeSearchCancel = true else startCodeSearch() }
        }
        clsLibBtn = Button(this).apply {
            text = "App only"
            textSize = 12f
            visibility = View.GONE
            setOnClickListener {
                clsAppOnly = !clsAppOnly
                if (inClasses && classDefs.isNotEmpty() && !codeSearching) showClasses()
            }
        }
        clsRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        clsRow.addView(codeSearchBtn, LinearLayout.LayoutParams(0, WRAP, 2f))
        clsRow.addView(clsLibBtn, LinearLayout.LayoutParams(0, WRAP, 1f))
        root.addView(clsRow)
        secSmartBtn = Button(this).apply {
            text = "Smart scan"
            tag = "accent"
            textSize = 14f
            visibility = View.GONE
            setOnClickListener { smartScan() }
        }
        root.addView(secSmartBtn)
        secScanBtn = Button(this).apply {
            text = "Deep scan (code)"
            textSize = 12f
            visibility = View.GONE
            setOnClickListener { if (smartRunning) smartCancelAll() else runDeepScan() }
        }
        val secScanRow = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        secScanRow.addView(secScanBtn, LinearLayout.LayoutParams(0, WRAP, 1f))
        root.addView(secScanRow)
        secBenchBtn = Button(this).apply {
            text = "AndroGoat check"
            textSize = 12f
            visibility = View.GONE
            setOnClickListener { showBenchmark() }
        }
        secScanRow.addView(secBenchBtn, LinearLayout.LayoutParams(0, WRAP, 1f))
        secBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        secFilterBtn = Button(this).apply {
            text = "Filter: ALL"; textSize = 12f
            setOnClickListener {
                secOnly = -1
                secMinRank = when (secMinRank) { 3 -> 2; 2 -> 1; 1 -> 4; else -> 3 }
                if (inSecurity) showSecurityList()
            }
        }
        secLibBtn = Button(this).apply {
            text = "Libs: hidden"; textSize = 12f
            setOnClickListener { secShowLibs = !secShowLibs; if (inSecurity) showSecurityList() }
        }
        secTriageBtn = Button(this).apply {
            text = "AI triage"; textSize = 12f
            setOnClickListener { triageWithAi() }
        }
        secTopBtn = Button(this).apply {
            text = "Top 5"; textSize = 12f
            setOnClickListener { if (inSecurity) showSummary() }
        }
        secBar.addView(secTopBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        secBar.addView(secFilterBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        secBar.addView(secLibBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        secBar.addView(secTriageBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(secBar)
        secCmpBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        secCmpBar.addView(Button(this).apply {
            text = "Save baseline"; textSize = 12f
            setOnClickListener { saveBaseline() }
        }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        secCmpBar.addView(Button(this).apply {
            text = "Compare with baseline"; textSize = 12f
            setOnClickListener { compareWithBaseline() }
        }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        secCmpBar.addView(Button(this).apply {
            text = "Strings"; textSize = 12f
            setOnClickListener { launchStringsPicker() }       // 0.102.0: import a decoded-strings dump
        }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.6f))
        root.addView(secCmpBar)
        secChips = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
            setPadding(Ui.dp(1), Ui.dp(2), Ui.dp(1), Ui.dp(4))
        }
        root.addView(secChips)

        pathView = TextView(this).apply {
            textSize = 12f
            typeface = Typeface.MONOSPACE
            setTextColor(Ui.p.sub)
            setPadding(Ui.dp(4), Ui.dp(6), Ui.dp(4), Ui.dp(6))
            setOnClickListener { if (inSecurity && scanDetail.isNotEmpty()) { scanDetailOpen = !scanDetailOpen; showSecurityList() } }   // 0.101.0
        }
        root.addView(pathView)

        list = ListView(this).apply {
            divider = null
            dividerHeight = 0
            selector = android.graphics.drawable.ColorDrawable(0)
            isVerticalScrollBarEnabled = false
            clipToPadding = false
            setPadding(0, 0, 0, Ui.dp(16))      // 0.96.0: the last card is not cut by the edge of the panel
        }
        root.addView(list, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        actions = object : LinearLayout(this) {
            override fun setVisibility(visibility: Int) {
                super.setVisibility(visibility)
                if (this@MainActivity::actions2.isInitialized) actions2.visibility = visibility
                if (this@MainActivity::actions3.isInitialized) actions3.visibility = visibility
            }
        }.apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        val explainBtn = Button(this).apply { text = "Explain (AI)"; tag = "primary"; textSize = 12f; setOnClickListener { explainWithAi() } }
        // 0.37.13: ONE slim bar (Explain / Edit / Suggest / More) instead of three rows; the rest lives in the More sheet
        val editBtn = Button(this).apply { text = "Edit"; textSize = 12f; setOnClickListener { startEdit() } }
        val suggestBtn = Button(this).apply { text = "Suggest"; textSize = 12f; setOnClickListener { suggestWithAi() } }
        val moreBtn = Button(this).apply { text = "More"; textSize = 12f; setOnClickListener { showClassMore() } }
        actions.addView(explainBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1.5f))
        actions.addView(editBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(suggestBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions.addView(moreBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(actions)
        actions2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        actions2.addView(Button(this).apply { text = "Rename (AI)"; textSize = 12f; setOnClickListener { renameWithAi() } },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions2.addView(Button(this).apply { text = "Patterns (AI)"; textSize = 12f; setOnClickListener { patternsWithAi() } },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions2.addView(Button(this).apply { text = "Sec review (AI)"; textSize = 12f; setOnClickListener { securityReviewWithAi() } },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions2.addView(Button(this).apply { text = "Fix vuln (AI)"; textSize = 12f; setOnClickListener { fixVulnWithAi() } },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions3 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        javaBtn = Button(this).apply { text = "Java view"; textSize = 12f; setOnClickListener { toggleJava() } }
        actions3.addView(javaBtn, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        actions3.addView(Button(this).apply { text = "Explain Java (AI)"; textSize = 12f; setOnClickListener { explainJavaWithAi() } },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        manifestActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        manifestActions.addView(Button(this).apply { text = "Review manifest (AI)"; textSize = 12f; setOnClickListener { reviewManifest() } },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        manifestActions.addView(Button(this).apply { text = "Quick fixes"; textSize = 12f; setOnClickListener { showManifestFixes() } },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.8f))
        manifestActions.addView(Button(this).apply {
            text = "Copy"; textSize = 12f
            setOnClickListener {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("manifest", manifestFull))
                Toast.makeText(this@MainActivity, "Manifest copied", Toast.LENGTH_SHORT).show()
            }
        }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 0.5f))
        root.addView(manifestActions)
        secActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        secActions.addView(Button(this).apply { text = "Explain finding (AI)"; textSize = 12f; setOnClickListener { explainFinding() } },
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(secActions)

        contentText = TextView(this).apply {
            setPadding(Ui.dp(12), Ui.dp(12), Ui.dp(12), Ui.dp(12))
            setTextColor(Ui.p.ink)
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        contentScroll = ScrollView(this).apply {
            background = Ui.GlassDrawable(18, Ui.p.well, false, false)
            addView(contentText)
            visibility = View.GONE
        }
        root.addView(contentScroll, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        // ---- edit mode UI (0.7.0) ----
        fun mkBtn(label: String, onClick: () -> Unit): Button = Button(this@MainActivity).apply {
            text = label
            textSize = 12f
            setOnClickListener { onClick() }
        }
        editActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        editActions.addView(mkBtn("Save") { saveEdit() }.also { it.tag = "primary" }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        editActions.addView(mkBtn("Diff") { showDiff() }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        editActions.addView(mkBtn("Revert") { revertEdit() }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        editActions.addView(mkBtn("Done") { finishEdit() }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(editActions)
        editor = EditText(this).apply {
            textSize = 11f
            typeface = Typeface.MONOSPACE
            gravity = Gravity.TOP or Gravity.START
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setHorizontallyScrolling(false)
        }
        editScroll = ScrollView(this).apply {
            addView(editor)
            isFillViewport = true
            visibility = View.GONE
        }
        root.addView(editScroll, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        // ---- build UI (0.8.0) ----
        buildActions = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        buildActions.addView(mkBtn("Build") { startBuild() }.also { it.tag = "primary" }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        buildActions.addView(mkBtn("Install") { installApk() }.also { it.tag = "primary" }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        buildActions.addView(mkBtn("Uninstall") { uninstallOriginal() }.also { it.tag = "danger" }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        buildActions.addView(mkBtn("Export") { exportApk() }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(buildActions)
        buildActions2 = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            visibility = View.GONE
        }
        buildActions2.addView(mkBtn("Export key") { exportKey() }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        buildActions2.addView(mkBtn("Import key") { importKeyPick() }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        buildActions2.addView(mkBtn("New key") { newKey() }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        buildActions2.addView(mkBtn("Rename pkg") { renameDialog() }, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        root.addView(buildActions2)
        buildLog = TextView(this).apply {
            setPadding(Ui.dp(12), Ui.dp(12), Ui.dp(12), Ui.dp(12))
            setTextColor(Ui.p.ink)
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setTextIsSelectable(true)
        }
        buildStatus = TextView(this).apply {
            text = "Ready"
            textSize = 12.5f
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.CENTER_VERTICAL
            setPadding(Ui.dp(14), Ui.dp(7), Ui.dp(14), Ui.dp(7))
            setTextColor(Ui.p.sub)
            background = Ui.rr(Ui.alpha(Ui.p.sub, 0x22), 16)
            visibility = View.GONE
        }
        root.addView(buildStatus, LinearLayout.LayoutParams(WRAP, WRAP).apply { setMargins(Ui.dp(3), Ui.dp(4), Ui.dp(3), Ui.dp(6)) })
        buildScroll = ScrollView(this).apply {
            background = Ui.GlassDrawable(18, Ui.p.well, false, false)
            addView(buildLog)
            visibility = View.GONE
        }
        root.addView(buildScroll, LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))

        filesBtn.setOnClickListener { guardEdit { selTab(0); inClasses = false; inSecurity = false; showTree(); showList() } }
        classesBtn.setOnClickListener { guardEdit { selTab(2); openClassesTab() } }
        buildBtn.setOnClickListener { guardEdit { selTab(3); openBuildTab() } }
        securityBtn.setOnClickListener { guardEdit { selTab(4); openSecurityTab() } }
        manifestBtn.setOnClickListener {
            guardEdit {
                selTab(1)
                viewingFile = false
                inClasses = false
                inSecurity = false
                showManifestTab()
                manifestActions.visibility = View.VISIBLE
            }
        }

        list.setOnItemClickListener { _, _, position, _ ->
            val row = rows[position]
            when {
                row.isUp -> goUp()
                row.folder != null -> { currentPath = row.folder; showTree() }
                row.file == "top:all" -> { secSummary = false; showSecurityList() }
                row.file != null && row.file.startsWith("top:") -> showFindingDialog(row.file.removePrefix("top:").toIntOrNull() ?: -1)
                row.file != null && row.file.startsWith("sec:") -> openFinding(row.file.removePrefix("sec:").toInt())
                row.file != null -> openFile(row.file)
                row.cls >= 0 -> openClass(row.cls, row.at)
            }
        }
        Ui.skin(root)
        for (b in listOf(secTopBtn, secFilterBtn, secLibBtn, secTriageBtn)) Ui.compact(b)    // 0.96.0: one line, one height
        selTab(0)
        setHeroCompact(false)
        setContentView(outer)
        setupWindow()
        outer.requestApplyInsets()
        if (savedInstanceState == null) playIntro()      // 0.60.1: opening animation (cold start only)
        val f = IntentFilter(installAction)
        if (Build.VERSION.SDK_INT >= 33) registerReceiver(installReceiver, f, Context.RECEIVER_NOT_EXPORTED)
        else registerReceiver(installReceiver, f)
    }

    override fun onDestroy() {
        try { unregisterReceiver(installReceiver) } catch (_: Throwable) { }
        super.onDestroy()
    }

    /** Big header on the welcome screen, slim one (status line + buttons) once an APK is loaded. */
    private fun setHeroCompact(c: Boolean) {
        heroCompact = c
        val v = if (c) View.GONE else View.VISIBLE
        heroTitle.visibility = v
        heroTag.visibility = v
        heroNote.visibility = v
        heroSpacer.visibility = v
        ctaBtn.visibility = v
        pickChip.visibility = if (c) View.VISIBLE else View.GONE
        aiHubChip.visibility = if (c) View.GONE else View.VISIBLE   // the nav bar has the AI button once an APK is loaded
        sheetRoot.visibility = if (c) View.VISIBLE else View.GONE
        navBar.visibility = if (c) View.VISIBLE else View.GONE
        info.gravity = if (c) Gravity.START else Gravity.CENTER_HORIZONTAL
        heroBox.layoutParams = LinearLayout.LayoutParams(MATCH, if (c) WRAP else 0, if (c) 0f else 1f)
        heroCol.layoutParams = FrameLayout.LayoutParams(MATCH, if (c) WRAP else MATCH)
        heroArt.showArt = !c
        heroArt.invalidate()
        heroBox.requestLayout()
        heroBox.requestApplyInsets()
    }

    /** Edge-to-edge + transparent system bars (insets are applied by the listener on the root view). */
    private fun setupWindow() {
        window.statusBarColor = Color.TRANSPARENT
        window.navigationBarColor = Color.TRANSPARENT
        if (Build.VERSION.SDK_INT >= 30) {
            window.setDecorFitsSystemWindows(false)
            val ic = window.insetsController
            if (ic != null) {
                ic.setSystemBarsAppearance(
                    if (Ui.p.dark) 0 else android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS,
                    android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS)
                ic.setSystemBarsAppearance(
                    if (Ui.p.dark) 0 else android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,
                    android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS)
            }
        } else {
            window.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LAYOUT_STABLE or
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION or
                (if (Ui.p.dark) 0 else (View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR))
        }
    }

    private fun showList() {
        hideEditUi()
        viewingFile = false
        contentScroll.visibility = View.GONE
        actions.visibility = View.GONE
        secActions.visibility = View.GONE
        list.visibility = View.VISIBLE
        setSearchUi(if (inClasses) View.VISIBLE else View.GONE)
        secScanBtn.visibility = if (inSecurity) View.VISIBLE else View.GONE
        secSmartBtn.visibility = if (inSecurity) View.VISIBLE else View.GONE
        secBenchBtn.visibility = if (inSecurity) View.VISIBLE else View.GONE
        secBar.visibility = if (inSecurity) View.VISIBLE else View.GONE
        secCmpBar.visibility = if (inSecurity) View.VISIBLE else View.GONE
        secChips.visibility = if (inSecurity) View.VISIBLE else View.GONE
        if (!inClasses && !inSecurity) pathView.text = "/$currentPath"
        else if (listTitle.isNotEmpty()) pathView.text = listTitle
    }

    private fun showContent(text: CharSequence) {
        hideEditUi()
        list.visibility = View.GONE
        setSearchUi(View.GONE)
        secScanBtn.visibility = View.GONE
        secSmartBtn.visibility = View.GONE
        secBenchBtn.visibility = View.GONE
        secBar.visibility = View.GONE
        secCmpBar.visibility = View.GONE
        secChips.visibility = View.GONE
        actions.visibility = if (viewingFile && !inSecurity) View.VISIBLE else View.GONE
        secActions.visibility = if (inSecurity && viewingFile) View.VISIBLE else View.GONE
        contentScroll.visibility = View.VISIBLE
        contentText.text = text
        contentScroll.scrollTo(0, 0)
    }

    private fun openPicker(go: () -> Unit = { launchPicker() }) {
        val edited = Rebuilder(wsDir) { }.editedFiles().values.sumOf { it.size }
        if (edited > 0) {
            AlertDialog.Builder(this)
                .setTitle("Replace current project?")
                .setMessage("You have $edited edited class(es). Picking a new APK deletes them and the built files. (Use 'Export' first if you want to keep the built APK.)")
                .setPositiveButton("Pick new APK") { _, _ -> go() }
                .setNegativeButton("Cancel", null)
                .show()
        } else {
            go()
        }
    }

    private class InstalledApp(val pkg: String, val label: String, val sourceDir: String, val splits: List<String>, val system: Boolean)

    /**
     * 0.102.0: list the installed apps and scan the one the user taps: its base APK and its splits are read straight from ApplicationInfo (sourceDir, splitSourceDirs),
     * so a Play Store app arrives with its native-code split and no PC or adb is needed. Seeing other apps needs QUERY_ALL_PACKAGES (declared in the manifest); on a
     * device that still hides them the list is short and the dialog says so. Parse-checked only until the owner builds it.
     */
    private fun showInstalledApps() {
        Toast.makeText(this, "Reading installed apps...", Toast.LENGTH_SHORT).show()
        Thread {
            val apps: List<InstalledApp> = try {
                val pm = packageManager
                pm.getInstalledApplications(0).filter { it.sourceDir != null }.map { ai ->
                    val system = (ai.flags and ApplicationInfo.FLAG_SYSTEM) != 0 && (ai.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) == 0
                    InstalledApp(ai.packageName, ai.loadLabel(pm).toString(), ai.sourceDir, ai.splitSourceDirs?.toList() ?: emptyList(), system)
                }.sortedWith(compareBy({ it.system }, { it.label.lowercase() }))
            } catch (t: Throwable) { emptyList() }
            runOnUiThread { showInstalledDialog(apps) }
        }.start()
    }

    private fun showInstalledDialog(apps: List<InstalledApp>) {
        if (apps.isEmpty()) { Toast.makeText(this, "Could not list installed apps", Toast.LENGTH_LONG).show(); return }
        val pad = Ui.dp(12)
        val filter = EditText(this).apply { hint = "Filter by name or package"; setSingleLine() }
        val list = ListView(this)
        var shown: List<InstalledApp> = apps
        fun line(a: InstalledApp) = a.label + (if (a.splits.isNotEmpty()) "  [+${a.splits.size} splits]" else "") + (if (a.system) "  (system)" else "") + "\n" + a.pkg
        fun refill() {
            val q = filter.text.toString().trim().lowercase()
            shown = if (q.isEmpty()) apps else apps.filter { it.label.lowercase().contains(q) || it.pkg.lowercase().contains(q) }
            list.adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, shown.map { line(it) })
        }
        filter.addTextChangedListener(object : TextWatcher {
            override fun afterTextChanged(s: Editable?) { refill() }
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        })
        refill()
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
            addView(filter, LinearLayout.LayoutParams(MATCH, WRAP))
            addView(list, LinearLayout.LayoutParams(MATCH, Ui.dp(380)))
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Installed apps (${apps.size})")
            .setView(box)
            .setNegativeButton("Cancel", null)
            .create()
        list.setOnItemClickListener { _, _, pos, _ ->
            if (pos in shown.indices) { dialog.dismiss(); analyzeInstalledApp(shown[pos]) }
        }
        dialog.show()
    }

    private fun analyzeInstalledApp(app: InstalledApp) {
        apkGen++
        info.text = "Copying ${app.label} (${1 + app.splits.size} APK file(s))..."
        Thread {
            try {
                val copied = SplitApks.copyInstalled(app.sourceDir, app.splits, File(filesDir, "workspaces/p1"))
                if (copied.skipped.isNotEmpty()) blog("Installed app: could not read split(s): " + copied.skipped.joinToString(", "))
                val r = analyzeFile(copied.original)
                runOnUiThread { applyResult(r) }
            } catch (t: Throwable) {
                runOnUiThread { info.text = "Error: ${t.javaClass.simpleName}: ${t.message}" }
            }
        }.start()
    }

    /** 0.37.5: system file picker for the AI Hub chat (several files at once; images, PDF and text / code files are accepted, others are rejected by Attachments.load). */
    private fun launchAttachPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)
        }
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, attachRequest)
        } catch (t: Throwable) {
            Toast.makeText(this, "No file picker available", Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * 0.102.0: import a decoded-strings dump (`index<TAB>"plaintext"` lines, or JSON) for an app that decrypts its strings through one method (see StringOverlay). The dump is kept in the
     * workspace next to the APK (so "Last APK" keeps it) and applied to every class text the scans read; run the Deep scan again to see its effect.
     */
    private fun launchStringsPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply { addCategory(Intent.CATEGORY_OPENABLE); type = "*/*" }
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, stringsRequest)
        } catch (t: Throwable) {
            Toast.makeText(this, "No file picker available", Toast.LENGTH_SHORT).show()
        }
    }

    private fun importStringsDump(uri: Uri) {
        Thread {
            val msg = try {
                val raw = contentResolver.openInputStream(uri)!!.use { it.readBytes().take(48_000_000).toByteArray().toString(Charsets.UTF_8) }
                val fallback = PostureScanner.dominantDecryptor()
                val ov = StringOverlay.from(raw, fallback)
                if (ov == null) "Not imported: no strings found, or the dump does not name its method (a '#decryptor' line) and no deep scan has found the app's decryptor yet. Run the Deep scan first, or use the Frida snippet of the report."
                else {
                    val saved = if (StringOverlay.parse(raw).method != null) raw else "#decryptor\t" + ov.method + "\n" + raw
                    File(filesDir, "workspaces/p1/strings.overlay").writeText(saved)
                    ov.resetStats()
                    StringOverlay.current = ov
                    "Imported ${ov.strings.size} strings for ${ov.method}. Run the Deep scan again: the string rules now read the plaintext."
                }
            } catch (t: Throwable) {
                "Import failed: ${t.javaClass.simpleName}: ${t.message}"
            }
            runOnUiThread { Toast.makeText(this, msg, Toast.LENGTH_LONG).show() }
        }.start()
    }

    private fun launchPicker() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true)      // 0.99.0: a base APK together with its split_config.*.apk files (or one .apks / .xapk bundle)
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, pickRequest)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        if (requestCode == attachRequest) {
            if (resultCode == RESULT_OK && data != null) {
                val uris = ArrayList<Uri>()
                val cd = data.clipData
                if (cd != null) {
                    for (i in 0 until cd.itemCount) cd.getItemAt(i).uri?.let { uris.add(it) }
                } else if (uri != null) {
                    uris.add(uri)
                }
                attachCallback?.invoke(uris)
            }
            return
        }
        if (requestCode == stringsRequest) {
            if (resultCode == RESULT_OK && uri != null) importStringsDump(uri)
            return
        }
        if (requestCode == exportKeyRequest) {
            val pw = pendingKeyPwd
            pendingKeyPwd = null
            if (resultCode == RESULT_OK && uri != null && pw != null) {
                Thread {
                    try {
                        SigningKey.exportTo(contentResolver.openOutputStream(uri)!!, pw)
                        blog("Key exported (.p12, protected by your password). Keep it safe.")
                    } catch (t: Throwable) {
                        blog("Key export failed: ${t.javaClass.simpleName}: ${t.message}")
                    }
                }.start()
            }
            return
        }
        if (requestCode == importKeyRequest) {
            if (resultCode == RESULT_OK && uri != null) {
                askPassword("Import key", "Password of the .p12 file:") { pw ->
                    Thread {
                        try {
                            SigningKey.importFrom(contentResolver.openInputStream(uri)!!, pw)
                            blog("Key imported. SHA-256: " + (SigningKey.fingerprint()?.take(23) ?: "?") + "...")
                        } catch (t: Throwable) {
                            blog("Key import failed (wrong password or not a PKCS12 key?): ${t.javaClass.simpleName}: ${t.message}")
                        }
                    }.start()
                }
            }
            return
        }
        if (requestCode == reportRequest) {
            val md = pendingReport
            pendingReport = null
            if (resultCode == RESULT_OK && uri != null && md != null) {
                Thread {
                    try {
                        contentResolver.openOutputStream(uri)!!.use { it.write(md.toByteArray(Charsets.UTF_8)) }
                        runOnUiThread { Toast.makeText(this, "Report saved", Toast.LENGTH_SHORT).show() }
                    } catch (t: Throwable) {
                        runOnUiThread { Toast.makeText(this, "Report failed: ${t.message}", Toast.LENGTH_LONG).show() }
                    }
                }.start()
            }
            return
        }
        if (requestCode == exportRequest && resultCode == RESULT_OK && uri != null) {
            Thread {
                try {
                    contentResolver.openOutputStream(uri)!!.use { o -> signedFile.inputStream().use { it.copyTo(o) } }
                    blog("Exported signed.apk")
                } catch (t: Throwable) {
                    blog("Export failed: ${t.javaClass.simpleName}: ${t.message}")
                }
            }.start()
            return
        }
        val pickedUris = ArrayList<Uri>()
        if (requestCode == pickRequest && resultCode == RESULT_OK && data != null) {
            data.clipData?.let { cd -> for (i in 0 until cd.itemCount) cd.getItemAt(i).uri?.let { pickedUris.add(it) } }
            if (pickedUris.isEmpty() && uri != null) pickedUris.add(uri)
        }
        if (requestCode == pickRequest && resultCode == RESULT_OK && pickedUris.isNotEmpty()) {
            apkGen++
            info.text = "Analyzing..."
            Thread {
                try {
                    val r = analyzeMany(this, pickedUris)
                    runOnUiThread { applyResult(r) }
                } catch (t: Throwable) {
                    runOnUiThread { info.text = "Error: ${t.javaClass.simpleName}: ${t.message}" }
                }
            }.start()
        }
    }

    /**
     * 0.99.0: one or several picked files: a single APK as before; a base APK with its split_config.*.apk files; or one .apks / .xapk / .apkm bundle. The base becomes original.apk
     * (everything else in the app uses that path); the splits are kept in workspaces/p1/splits and read by the native scanner (and again by "Last APK").
     */
    private fun analyzeMany(context: Context, uris: List<Uri>): Result {
        val dir = File(context.filesDir, "workspaces/p1")
        dir.deleteRecursively()
        dir.mkdirs()
        val inDir = File(dir, "picked"); inDir.mkdirs()
        val files = ArrayList<File>()
        for ((i, u) in uris.withIndex()) {
            val shown = try { context.contentResolver.query(u, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c -> if (c.moveToFirst()) c.getString(0) else null } } catch (_: Throwable) { null }
            var name = (shown ?: "picked$i.apk").replace(Regex("[^A-Za-z0-9._-]"), "_")
            if (files.any { it.name == name }) name = "${i}_$name"
            val f = File(inDir, name)
            context.contentResolver.openInputStream(u)!!.use { input -> f.outputStream().use { input.copyTo(it) } }
            files.add(f)
        }
        var apks: List<File> = files
        if (files.size == 1 && SplitApks.isBundle(files[0])) apks = SplitApks.extractApks(files[0], File(inDir, "bundle"))
        val (base, splits) = SplitApks.partition(apks)
        val baseFile = base ?: apks.first()
        val original = File(dir, "original.apk")
        baseFile.copyTo(original, true)
        val splitDir = File(dir, "splits"); splitDir.mkdirs()
        for (sp in (if (base == null) apks.drop(1) else splits)) sp.copyTo(File(splitDir, sp.name), true)
        inDir.deleteRecursively()
        return analyzeFile(original)
    }

    private fun analyze(context: Context, uri: Uri): Result {
        val dir = File(context.filesDir, "workspaces/p1")
        dir.deleteRecursively()
        dir.mkdirs()
        val apk = File(dir, "original.apk")
        context.contentResolver.openInputStream(uri)!!.use { input ->
            apk.outputStream().use { input.copyTo(it) }
        }
        return analyzeFile(apk)
    }

    private fun analyzeFile(apk: File): Result {
        scanDetail = ""; scanDetailOpen = false   // 0.101.0: another APK, another scan
        StringOverlay.current = try { StringOverlay.load(File(apk.parentFile, "strings.overlay")) } catch (_: Throwable) { null }   // 0.102.0: the decoded-strings dump of THIS workspace (null for a freshly picked APK)
        // 0.99.0: the split archives kept next to the base (empty for any other APK)
        NativeScanner.extraArchives = File(apk.parentFile, "splits").listFiles()?.filter { it.name.endsWith(".apk", true) }?.sortedBy { it.name } ?: emptyList()
        val all = ArrayList<Pair<String, Long>>()
        ZipFile(apk).use { zip ->
            val e = zip.entries()
            while (e.hasMoreElements()) {
                val entry = e.nextElement()
                if (!entry.isDirectory) all.add(entry.name to entry.size)
            }
        }

        val module = ApkModule.loadApkFile(apk)
        val manifest = module.androidManifest
        val dex = all.filter { it.first.matches(rx("classes\\d*\\.dex")) }
        val summary = buildString {
            append("Package: ${manifest.packageName}\n")
            append("Size: ${fmt(apk.length())} | Files: ${all.size}\n")
            append("DEX: ${dex.size}")
            if (dex.isNotEmpty()) append(" (" + dex.joinToString(", ") { "${it.first} ${fmt(it.second)}" } + ")")
            val sp = NativeScanner.extraArchives
            if (sp.isNotEmpty()) append("\nSplits: ${sp.size} (" + sp.joinToString(", ") { it.name } + ")")
        }
        val xml = dumpXml(manifest, tableBlockOf(module))
        val full = buildString {
            append("Package: ${manifest.packageName}\n\n")
            append(xml ?: ("(full XML dump not available)\n\n" + manifest.toString() + "\n\n" + apiHints(manifest)))
        }
        return Result(summary, full, all, module)
    }

    // ---------- XML decoding (ARSCLib API accessed via reflection until verified) ----------

    private fun tableBlockOf(module: ApkModule): Any? =
        try { module.javaClass.getMethod("getTableBlock").invoke(module) } catch (t: Throwable) { null }

    private fun dumpXml(doc: Any, store: Any?): String? {
        for (s in listOf(store, null)) {
            try {
                val m = doc.javaClass.methods.firstOrNull {
                    it.name == "decodeToXml" && it.parameterTypes.size == 2
                }
                if (m != null) {
                    val r = m.invoke(doc, s, 0)
                    if (r != null) {
                        val t = r.javaClass.methods.firstOrNull {
                            it.name == "toText" && it.parameterTypes.isEmpty()
                        }
                        val text = (t?.invoke(r) ?: r.toString()).toString()
                        if (text.length > 20) return text
                    }
                }
            } catch (_: Throwable) { }
        }
        for (name in listOf("toXml", "toText", "serializeToXml", "toXmlString")) {
            try {
                val m = doc.javaClass.methods.firstOrNull { it.name == name && it.parameterTypes.isEmpty() }
                val text = m?.invoke(doc)?.toString()
                if (text != null && text.length > 20) return text
            } catch (_: Throwable) { }
        }
        return null
    }

    private fun apiHints(doc: Any): String {
        val names = doc.javaClass.methods.map { it.name }
            .filter { rx("xml|text|string|decode|serial|dump", RegexOption.IGNORE_CASE).containsMatchIn(it) }
            .distinct().sorted()
        return "[debug] ${doc.javaClass.name} methods: " + names.joinToString(", ")
    }

    private fun decodeBinaryXml(bytes: ByteArray): String {
        val doc = Class.forName("com.reandroid.arsc.chunk.xml.ResXmlDocument")
            .getDeclaredConstructor().newInstance()
        val read = doc.javaClass.methods.firstOrNull {
            it.name == "readBytes" && it.parameterTypes.size == 1 && it.parameterTypes[0] == ByteArray::class.java
        } ?: doc.javaClass.methods.firstOrNull {
            it.name == "readBytes" && it.parameterTypes.size == 1 &&
                it.parameterTypes[0] == java.io.InputStream::class.java
        } ?: return "(readBytes not found)\n" + apiHints(doc)
        if (read.parameterTypes[0] == ByteArray::class.java) read.invoke(doc, bytes)
        else read.invoke(doc, java.io.ByteArrayInputStream(bytes))
        val store = apkModule?.let { tableBlockOf(it) }
        return dumpXml(doc, store) ?: ("(XML dump not available)\n" + apiHints(doc))
    }

    // ---------- file viewer ----------

    private fun readEntry(name: String, limit: Int): ByteArray {
        ZipFile(apkFile).use { zip ->
            val entry = zip.getEntry(name) ?: return ByteArray(0)
            zip.getInputStream(entry).use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(8192)
                while (out.size() < limit) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, minOf(n, limit - out.size()))
                }
                return out.toByteArray()
            }
        }
    }

    private fun openFile(path: String) {
        currentClassIndex = -1
        currentEditable = false
        viewingFile = true
        pathView.text = "/$path"
        showContent("Opening...")
        Thread {
            val text = try {
                val bytes = readEntry(path, 300_000)
                val isBinXml = bytes.size > 8 && bytes[0].toInt() == 0x03 && bytes[1].toInt() == 0x00
                val head = bytes.take(1024)
                when {
                    isBinXml && path.endsWith(".xml") -> decodeBinaryXml(bytes)
                    head.none { it.toInt() == 0 } -> String(bytes, Charsets.UTF_8)
                    else -> "Binary file (${fmt(bytes.size.toLong())} read)\n\n" + hex(bytes, 512)
                }
            } catch (t: Throwable) {
                "Error: ${t.javaClass.simpleName}: ${t.message}"
            }
            runOnUiThread { if (viewingFile) present(text) }
        }.start()
    }

    private fun hex(b: ByteArray, n: Int): String = buildString {
        val len = minOf(b.size, n)
        var i = 0
        while (i < len) {
            append(String.format("%04X  ", i))
            val end = minOf(i + 16, len)
            for (j in i until end) append(String.format("%02X ", b[j]))
            for (j in end until i + 16) append("   ")
            append(" ")
            for (j in i until end) {
                val c = b[j].toInt() and 0xFF
                append(if (c in 32..126) c.toChar() else '.')
            }
            append('\n')
            i += 16
        }
    }

    // ---------- classes / smali (baksmali) ----------

    private fun openClassesTab() {
        inClasses = true
        inSecurity = false
        showList()
        if (classDefs.isNotEmpty()) { showClasses(); return }
        if (entries.isEmpty()) { pathView.text = "Select an APK first"; return }
        if (indexing) { pathView.text = "Indexing classes..."; list.adapter = Ui.RowAdapter(this, emptyList<String>()); return }
        indexing = true
        pathView.text = "Indexing classes..."
        list.adapter = Ui.RowAdapter(this, emptyList<String>())
        Thread {
            try {
                buildIndex()
                runOnUiThread { indexing = false; if (inClasses) showClasses(); onIndexReady() }
            } catch (t: Throwable) {
                runOnUiThread { indexing = false; pathView.text = "Error: ${t.javaClass.simpleName}: ${t.message}" }
            }
        }.start()
    }

    private fun buildIndex() {
        // 0.36.0: one build at a time (Classes tab, Deep scan, agent and the background index may all ask); a second caller waits and then finds it ready
        synchronized(indexLock) {
            if (classDefs.isNotEmpty()) return
            val gen = apkGen
            val dir = File(filesDir, "workspaces/p1/dex")
            dir.mkdirs()
            val defs = ArrayList<ClassDef>()
            val dexOf = HashMap<String, String>()
            val dexNames = entries.map { it.first }.filter { it.matches(rx("classes\\d*\\.dex")) }
            for (name in dexNames) {
                if (gen != apkGen) return        // a different APK was loaded meanwhile: drop this work
                val f = File(dir, name)
                ZipFile(apkFile).use { zip ->
                    zip.getInputStream(zip.getEntry(name)).use { i -> f.outputStream().use { o -> i.copyTo(o) } }
                }
                val dex = DexFileFactory.loadDexFile(f, Opcodes.getDefault())
                defs.addAll(dex.classes)
                for (c in dex.classes) dexOf[c.type] = name
            }
            defs.sortBy { it.type }
            if (gen != apkGen) return
            classDex.putAll(dexOf)
            loadModified()
            classDefs = defs
        }
    }

    // ---------- background indexing (0.36.0) ----------
    // After an APK is loaded: (1) build the class index, (2) disassemble every class once into the gzipped text index (the same cache search_code
    // and the Deep scan read), so the first search / scan is fast. Low priority, pauses while a scan/build/agent run is active, resumes where it
    // stopped (files already in the cache are skipped), can be turned off in AI settings.

    private fun bgIndexEnabled() = prefs().getBoolean("bg_index", true)

    private fun setIdxStatus(gen: Int, s: String) {          // UI thread only
        if (gen != apkGen) return
        info.text = if (s.isEmpty()) infoBase else infoBase + "\n" + s
    }

    /** UI thread. Continues a Deep scan that was requested while the class index was still being built. */
    private fun onIndexReady() {
        if (!deepAfterIndex) return
        deepAfterIndex = false
        secScanBtn.text = "Deep scan (code)"
        if (classDefs.isEmpty()) { if (smartRunning) smartFinish(); return }
        if (inSecurity && !(smartRunning && smartStopped)) runDeepScan() else if (smartRunning) smartFinish()
    }

    /** 0.37.6: true when the phone is NOT charging and (battery below 20% or battery saver is on): the background index waits then. */
    private fun lowPower(): Boolean {
        try {
            val i = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            if (i == null) return false
            val lvl = i.getIntExtra(android.os.BatteryManager.EXTRA_LEVEL, -1)
            val scale = i.getIntExtra(android.os.BatteryManager.EXTRA_SCALE, 100).coerceAtLeast(1)
            val st = i.getIntExtra(android.os.BatteryManager.EXTRA_STATUS, -1)
            val charging = (st == android.os.BatteryManager.BATTERY_STATUS_CHARGING) || (st == android.os.BatteryManager.BATTERY_STATUS_FULL)
            if (charging) return false
            val pm = getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
            val lowLevel = lvl >= 0 && (lvl * 100 / scale) < 20
            return lowLevel || pm.isPowerSaveMode
        } catch (_: Throwable) {
            return false
        }
    }

    private fun startBackgroundIndex() {
        if (!bgIndexEnabled() || entries.isEmpty()) return
        val gen = apkGen
        bgIndexCancel = false
        val needClasses = classDefs.isEmpty()
        if (needClasses) indexing = true
        setIdxStatus(gen, "⏳ Index: reading classes...")
        Thread {
            try { Thread.currentThread().priority = Thread.MIN_PRIORITY } catch (_: Throwable) { }
            try {
                if (needClasses) {
                    buildIndex()
                    runOnUiThread {
                        if (gen == apkGen) {
                            indexing = false
                            if (inClasses) showClasses()
                            onIndexReady()
                        }
                    }
                }
                val defs = classDefs
                if (gen != apkGen || defs.isEmpty()) return@Thread
                var done = 0
                var errors = 0
                var lastUi = 0L
                var lastPwr = 0L
                var lowCached = false
                var pausedShown = false
                for (def in defs) {
                    if (bgIndexCancel || gen != apkGen) return@Thread
                    // 0.37.6: battery check at most every 10 s
                    val nowP = System.currentTimeMillis()
                    if (nowP - lastPwr > 10_000L) { lastPwr = nowP; lowCached = lowPower() }
                    // stay out of the way of the user's own work, and of a low battery / battery saver
                    while (!bgIndexCancel && gen == apkGen) {
                        val busy = secScanning || smartRunning || building || agentBusy
                        if (!busy && !lowCached) break
                        if (!busy && !pausedShown) {
                            pausedShown = true
                            val n = done
                            runOnUiThread { setIdxStatus(gen, "⏸ Index paused at $n/${defs.size} (low battery or battery saver)") }
                        }
                        Thread.sleep(if (busy) 800L else 5000L)
                        if (!busy) lowCached = lowPower()
                    }
                    pausedShown = false
                    if (bgIndexCancel || gen != apkGen) return@Thread
                    if (idxBytes >= 400_000_000L) {
                        val n = done
                        runOnUiThread { setIdxStatus(gen, "⚠ Index stopped at $n/${defs.size} (cache limit reached)") }
                        return@Thread
                    }
                    try {
                        val have = smaliFile("smali", def.type).exists() || idxFile(def).exists()
                        if (!have) agentIndexedTextRaw(def)
                    } catch (_: Throwable) { errors++ }
                    done++
                    val now = System.currentTimeMillis()
                    if (now - lastUi > 700) {
                        lastUi = now
                        val n = done
                        runOnUiThread { setIdxStatus(gen, "⏳ Index $n/${defs.size}") }
                    }
                }
                val total = defs.size
                val mb = idxBytes / 1_000_000L
                runOnUiThread {
                    setIdxStatus(gen, "✅ Index ready: $total classes, ~$mb MB" + (if (errors > 0) " ($errors failed)" else ""))
                    info.postDelayed({ setIdxStatus(gen, "") }, 10_000)
                }
            } catch (t: Throwable) {
                runOnUiThread {
                    if (gen == apkGen) {
                        indexing = false
                        deepAfterIndex = false
                        secScanBtn.text = "Deep scan (code)"
                        setIdxStatus(gen, "⚠ Index failed: ${t.javaClass.simpleName}")
                    }
                }
            }
        }.start()
    }

    private fun showClasses() {
        val q = search.text.toString().trim().lowercase()
        val out = ArrayList<Row>()
        var matches = 0
        var hiddenLibs = 0
        val appPkg = packageNameOrNull() ?: ""
        clsLibBtn.text = if (clsAppOnly) "Libs: hidden" else "Libs: shown"
        for ((i, c) in classDefs.withIndex()) {
            val name = c.type.removePrefix("L").removeSuffix(";").replace('/', '.')
            if (q.isNotEmpty() && !name.lowercase().contains(q)) continue
            if (clsAppOnly && SecurityScanner.scopeOf(c.type, appPkg) == SecurityScanner.Scope.LIB) { hiddenLibs++; continue }
            matches++
            if (out.size < 500) out.add(Row((if (c.type in modified) "✏ " else "") + name, cls = i))
        }
        rows = out
        listTitle = "Classes: $matches / ${classDefs.size}" + (if (hiddenLibs > 0) " | $hiddenLibs library classes hidden" else "") + (if (matches > 500) " (showing 500)" else "")
        pathView.text = listTitle + scanTail()
        list.adapter = Ui.RowAdapter(this, out.map { it.label })
    }

    // 0.37.6: the reflective lookups (class, writer constructor, writeTo) were repeated for EVERY class; they are resolved once now.
    private val bakWriterCtor: java.lang.reflect.Constructor<*> by lazy {
        val wcls = Class.forName("com.android.tools.smali.baksmali.formatter.BaksmaliWriter")
        wcls.constructors.firstOrNull { it.parameterTypes.size == 1 && it.parameterTypes[0] == java.io.Writer::class.java }
            ?: wcls.constructors.first { it.parameterTypes.size == 2 }
    }
    private val bakWriteTo: java.lang.reflect.Method by lazy {
        ClassDefinition::class.java.methods.first { it.name == "writeTo" && it.parameterTypes.size == 1 }
    }

    private fun disassemble(def: ClassDef): String {
        val sw = StringWriter()
        // baksmali 3.x expects a BaksmaliWriter (not IndentingWriter); created via reflection to stay robust
        val ctor = bakWriterCtor
        val w = if (ctor.parameterTypes.size == 1) ctor.newInstance(sw) else ctor.newInstance(sw, def.type)
        val cd = ClassDefinition(BaksmaliOptions(), def)
        bakWriteTo.invoke(cd, w)
        (w as java.io.Writer).flush()
        return sw.toString()
    }

    private fun openClass(index: Int, at: Int = -1) {
        val def = classDefs[index]
        javaMode = false
        currentJava = ""
        if (::javaBtn.isInitialized) { javaBtn.text = "Java view"; javaBtn.isEnabled = true }
        currentClassIndex = index
        currentEditable = false
        viewingFile = true
        pathView.text = def.type
        showContent("Disassembling...")
        Thread {
            var orig = ""
            var editable = false
            val text = try {
                val ef = smaliFile("smali", def.type)
                if (ef.exists()) {
                    val of = smaliFile("smali_orig", def.type)
                    orig = if (of.exists()) of.readText() else ""
                    editable = true
                    ef.readText()
                } else {
                    val full = disassemble(def)
                    if (full.length > 200_000) {
                        full.substring(0, 200_000) + "\n# ... truncated (view only)"
                    } else {
                        orig = full
                        editable = true
                        full
                    }
                }
            } catch (t: Throwable) {
                "Error: ${t.javaClass.simpleName}: ${t.message}"
            }
            runOnUiThread {
                if (viewingFile && currentClassIndex == index) {
                    currentOrig = orig
                    currentEditable = editable
                    present(text)
                    showClassTitle()
                    if (at >= 0) contentText.post { scrollToOffset(at) }
                }
            }
        }.start()
    }

    // ---------- global code search (0.13.0) ----------

    private fun setSearchUi(v: Int) {
        search.visibility = v
        if (::codeSearchBtn.isInitialized) codeSearchBtn.visibility = v
        if (::clsLibBtn.isInitialized) clsLibBtn.visibility = v
    }

    private fun startCodeSearch() {
        val q = search.text.toString().trim()
        if (classDefs.isEmpty()) {
            Toast.makeText(this, "Open the Classes tab and wait for indexing first", Toast.LENGTH_SHORT).show()
            return
        }
        if (q.length < 3) {
            Toast.makeText(this, "Type at least 3 characters in the search box", Toast.LENGTH_SHORT).show()
            return
        }
        hideKeyboard()
        val defs = classDefs
        val needle = q.lowercase()
        val maxHits = 300
        codeSearching = true
        codeSearchCancel = false
        codeSearchBtn.text = "Stop search"
        pathView.text = "Searching \"$q\" ... 0 / ${defs.size}"
        Thread {
            val out = ArrayList<Row>()
            var hits = 0
            var classesWithHits = 0
            var scanned = 0
            var errors = 0
            try {
                for ((i, def) in defs.withIndex()) {
                    if (codeSearchCancel || hits >= maxHits) break
                    scanned = i + 1
                    val text = try {
                        val ef = smaliFile("smali", def.type)
                        if (ef.exists()) ef.readText() else disassemble(def)
                    } catch (_: Throwable) { errors++; "" }
                    if (text.isNotEmpty() && text.lowercase().contains(needle)) {
                        var pos = 0
                        var lineNo = 0
                        var any = false
                        val name = def.type.removePrefix("L").removeSuffix(";").replace('/', '.')
                        for (line in text.split("\n")) {
                            lineNo++
                            if (line.lowercase().contains(needle)) {
                                if (hits >= maxHits) break
                                hits++
                                any = true
                                val shown = line.trim().let { if (it.length > 90) it.take(90) + "…" else it }
                                out.add(Row((if (def.type in modified) "✏ " else "") + name + "\n   :$lineNo  $shown", cls = i, at = pos))
                            }
                            pos += line.length + 1
                        }
                        if (any) classesWithHits++
                    }
                    if (i % 100 == 0) {
                        val n = i + 1
                        val h = hits
                        runOnUiThread { if (codeSearching) pathView.text = "Searching \"$q\" ... $n / ${defs.size}  ($h hits)" }
                    }
                }
            } catch (t: Throwable) {
                errors++
            }
            val stopped = codeSearchCancel
            runOnUiThread {
                codeSearching = false
                codeSearchCancel = false
                codeSearchBtn.text = "Code search (all classes)"
                if (classDefs !== defs) return@runOnUiThread   // a different APK was loaded meanwhile
                rows = out
                listTitle = "Code search \"$q\": $hits hits in $classesWithHits classes" +
                    (if (hits >= maxHits) " (limit $maxHits - narrow the query)" else "") +
                    (if (stopped) " (stopped at $scanned / ${defs.size})" else "") +
                    (if (errors > 0) " ($errors classes failed)" else "")
                if (inClasses && list.visibility == View.VISIBLE) pathView.text = listTitle
                list.adapter = Ui.RowAdapter(this, out.map { it.label })
            }
        }.start()
    }

    // ---------- security scan (0.18.0) ----------

    private fun openSecurityTab() {
        inClasses = false
        inSecurity = true
        showList()
        if (manifestFull.isBlank()) { pathView.text = "Select an APK first"; return }
        runManifestScan()
    }

    // ---------- 0.71.0: Before / After compare ----------

    private fun baselineFileOrNull(): File? {
        val pkg = packageNameOrNull() ?: return null
        return File(filesDir, "baselines/" + pkg.replace(Regex("[^A-Za-z0-9._-]"), "_") + ".json")
    }

    /** versionName of the loaded APK, read from the decoded manifest text (the same text the scanner uses). */
    private fun apkVersionOrEmpty(): String =
        try { Regex("android:versionName\\s*=\\s*\"([^\"]*)\"").find(manifestFull)?.groupValues?.get(1) ?: "" } catch (_: Throwable) { "" }

    private fun scanSnapshot(label: String): ScanCompare.Snapshot =
        ScanCompare.snapshot(packageNameOrNull() ?: "", apkVersionOrEmpty(), label, System.currentTimeMillis(), secFindings)

    /** A baseline needs the code scan too, otherwise "fixed" would just mean "not scanned yet". */
    private fun hasCodeScanOrToast(): Boolean {
        if (secFindings.any { it.clsIndex >= 0 }) return true
        Toast.makeText(this, "Run Deep scan (code) first, so the comparison includes code findings", Toast.LENGTH_LONG).show()
        return false
    }

    private fun saveBaseline() {
        val f = baselineFileOrNull()
        if (f == null) { Toast.makeText(this, "Pick an APK first", Toast.LENGTH_SHORT).show(); return }
        if (!hasCodeScanOrToast()) return
        val stamp = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US).format(java.util.Date())
        val ver = apkVersionOrEmpty()
        val snap = scanSnapshot("baseline " + stamp + (if (ver.isNotEmpty()) " (v$ver)" else ""))
        try {
            f.parentFile?.mkdirs()
            f.writeText(ScanCompare.toJson(snap))
            Toast.makeText(this, "Baseline saved: ${snap.entries.size} findings. Fix / edit, scan again, then tap Compare.", Toast.LENGTH_LONG).show()
        } catch (e: Throwable) {
            Toast.makeText(this, "Could not save the baseline: " + (e.message ?: e.javaClass.simpleName), Toast.LENGTH_LONG).show()
        }
    }

    private fun compareWithBaseline() {
        val f = baselineFileOrNull()
        if (f == null) { Toast.makeText(this, "Pick an APK first", Toast.LENGTH_SHORT).show(); return }
        val base = try { if (f.exists()) ScanCompare.fromJson(f.readText()) else null } catch (_: Throwable) { null }
        if (base == null) {
            Toast.makeText(this, "No baseline for this app yet. Scan, then tap Save baseline.", Toast.LENGTH_LONG).show()
            return
        }
        if (!hasCodeScanOrToast()) return
        val d = ScanCompare.diff(base, scanSnapshot("current scan"))
        val md = ScanCompare.markdown(d)
        AlertDialog.Builder(this)
            .setTitle("Before / After: " + d.verdict)
            .setMessage(md)
            .setPositiveButton("OK", null)
            .setNeutralButton("Copy") { _, _ ->
                (getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager)
                    .setPrimaryClip(android.content.ClipData.newPlainText("before-after", md))
            }
            .show()
    }

    /** 0.33.1: compares the current findings with the AndroGoat (MASTG-APP-0001) expected list, fully on device. */
    private fun showBenchmark() {
        val r = AndroGoatChecks.benchmark(secFindings.filter { it.verdict != "FP" }.map { it.title })
        AlertDialog.Builder(this)
            .setTitle("AndroGoat: " + r.first)
            .setMessage(r.second)
            .setPositiveButton("OK", null)
            .setNeutralButton("Copy") { _, _ ->
                (getSystemService(CLIPBOARD_SERVICE) as android.content.ClipboardManager)
                    .setPrimaryClip(android.content.ClipData.newPlainText("androgoat", r.second))
            }
            .show()
    }

    /**
     * 0.43.0: resource scan once per loaded APK. The work (decode one res/ XML file at a time, resource rules, resources.arsc string
     * pool) lives in ResourceScanner (ScanRulesResources.kt); this function only runs it off the UI thread and publishes the result.
     * Stats go to AndroGoatChecks.resStats.
     */
    private fun scanResourcesAsync() {
        val module = apkModule
        if (!SecretFormats.loaded()) try {   // 0.103.0: the asset scan reads the vendor formats too (they were only loaded for the Deep scan)
            SecretFormats.load(assets.open("secret_formats.json").use { it.readBytes() }.toString(Charsets.UTF_8))
        } catch (_: Throwable) { RuleRegistry.noteError("secret-formats") }
        AndroGoatChecks.resStats = "running..."
        Thread {
            val res = try {
                ResourceScanner.scanApk(apkFile)
            } catch (t: Throwable) {
                ResourceScanResult(emptyList(), "failed: " + t.javaClass.simpleName + ": " + t.message)
            }
            // 0.45.0: software composition analysis (libraries inside the built APK); its findings carry a file, so they travel with the resource ones
            val sca = try {
                LibraryScanner.loadDb(applicationContext)   // 0.47.2: vulnerability table from assets/vulns.json
                LibraryScanner.scanApk(apkFile)
            } catch (t: Throwable) {
                LibraryScanner.inventory = emptyList()
                LibScanResult(emptyList(), "failed: " + t.javaClass.simpleName + ": " + t.message)
            }
            // 0.47.0: second SCA layer - package-path heuristics over the class type list (already in memory,
            // no dex re-read). Merged into the inventory, then findings are regenerated over the full list.
            var scaFindings = sca.findings
            var scaStats = sca.stats
            try {
                // 0.102.0: applyResult empties classDefs and starts this thread at once; the class index is built lazily, so a thread that got here first saw NO classes and silently
                // skipped the package-path layer and the version probes (the SCA table then differed from run to run). buildIndex() is idempotent and locked: wait for it.
                if (classDefs.isEmpty()) try { buildIndex() } catch (_: Throwable) { RuleRegistry.noteError("sca-index") }
                val types = classDefs.map { it.type }
                if (types.isEmpty()) scaStats = sca.stats + "; package-path SKIPPED (class index not available)"
                if (types.isNotEmpty()) {
                    val pathLibs = ScaScanner.scanPackages(types, packageNameOrNull() ?: "")
                    // 0.88.0: a path-only library ("?") whose version is a CONSTANT in its own classes (Gson, Kotlin stdlib, a library's root BuildConfig) gets that version;
                    // only the 2-6 carrier classes are read, merged BEFORE the path rows so mergeInventory drops their version-less twins
                    try {
                        val typeSet = types.toHashSet()
                        val wanted = VersionProbes.wanted(typeSet, pathLibs).toHashSet()
                        val byType = if (wanted.isEmpty()) emptyMap() else classDefs.filter { it.type in wanted }.associateBy { it.type }
                        val probed = VersionProbes.resolve(typeSet, pathLibs) { t -> byType[t]?.let { agentIndexedText(it) } }
                        if (probed.isNotEmpty()) LibraryScanner.mergeInventory(probed)
                    } catch (_: Throwable) {
                        RuleRegistry.noteError("sca-probe")
                    }
                    val merged = LibraryScanner.mergeInventory(pathLibs)
                    scaFindings = LibraryScanner.findingsFor(merged)
                    ScaScanner.summaryFinding(pathLibs, merged.size - pathLibs.size)?.let { scaFindings = scaFindings + it }
                    scaStats = sca.stats + "; package-path " + pathLibs.size
                }
            } catch (_: Throwable) {
                RuleRegistry.noteError("sca-package")
            }
            AndroGoatChecks.resStats = res.stats + "; SCA: " + scaStats
            runOnUiThread {
                if (apkModule !== module) return@runOnUiThread   // another APK was loaded meanwhile
                val resMerged = try { SecurityScanner.aggregate(res.findings) } catch (_: Throwable) { res.findings }
                secFindings = secSorted(secFindings.filter { it.file.isEmpty() } + resMerged + scaFindings)
                if (inSecurity) showSecurityList()
            }
        }.start()
    }

    private fun runManifestScan() {
        val mOnly = SecurityScanner.scanManifest(manifestFull)
        secFindings = secSorted(secFindings.filter { it.clsIndex >= 0 || it.file.isNotEmpty() } + mOnly)
        showSecurityList()
    }

    private fun scopeRank(sc: SecurityScanner.Scope): Int = when (sc) {
        SecurityScanner.Scope.APP -> 0
        SecurityScanner.Scope.OBF -> 1
        SecurityScanner.Scope.OTHER -> 2
        SecurityScanner.Scope.LIB -> 3
    }

    /** AI-judged false positives sink to the bottom, then severity, then app code before libraries, then biggest group first. */
    private fun secSorted(l: List<SecurityScanner.Finding>): List<SecurityScanner.Finding> =
        l.sortedWith(compareBy<SecurityScanner.Finding>(
            { if (it.verdict == "FP") 1 else 0 }, { it.severity.rank }, { scopeRank(it.scope) }, { -it.count }))

    /**
     * 0.46.0: obfuscated-package findings (single-letter paths, mu.h, obfuscated io.ably internals) are treated like library
     * findings when the Libs filter hides libraries - they are almost always R8-obfuscated SDK code. The exception: exact,
     * high-severity hits (rank <= 1, i.e. CRITICAL/HIGH) stay visible even in OBF classes, so a real addJavascriptInterface
     * in the app's obfuscated core is never hidden.
     */
    private fun secObfHidden(f: SecurityScanner.Finding): Boolean =
        f.scope == SecurityScanner.Scope.OBF && f.severity.rank > 1

    private fun secIsVisible(f: SecurityScanner.Finding): Boolean =
        f.severity.rank <= secMinRank && (secOnly < 0 || f.severity.rank == secOnly) &&
            (secShowLibs || (f.scope != SecurityScanner.Scope.LIB && !secObfHidden(f)))

    private fun showSecurityList() {
        secSummary = false
        val out = ArrayList<Row>()
        val c = IntArray(5)
        val tot = IntArray(5)
        var hiddenLib = 0
        var shown = 0
        for ((i, f) in secFindings.withIndex()) {
            if (secShowLibs || (f.scope != SecurityScanner.Scope.LIB && !secObfHidden(f))) tot[f.severity.rank]++
            if (!secShowLibs && (f.scope == SecurityScanner.Scope.LIB || secObfHidden(f)) && f.severity.rank <= secMinRank) hiddenLib++
            if (!secIsVisible(f)) continue
            shown++
            c[f.severity.rank]++
            val sc = if (f.scope == SecurityScanner.Scope.OTHER) "" else "  [" + f.scope.tag + "]"
            val v = when (f.verdict) { "TP" -> "  ✔ TP"; "FP" -> "  ✘ FP"; "REVIEW" -> "  ? review"; else -> "" }
            val n = if (f.count > 1) " (x${f.count})" else ""
            if (out.size < 800) out.add(Row("[${f.severity.label}] ${f.title}$n$v\n   ${f.location}$sc", file = "sec:$i"))
        }
        rows = out
        val hasCodeScan = secFindings.any { it.clsIndex >= 0 }
        refreshSecChips(tot)
        listTitle = "Security: $shown shown / ${secFindings.size} total" +
            (if (hiddenLib > 0) " | $hiddenLib in libraries/obfuscated hidden" else "") +
            (if (shown > 800) " | showing 800" else "") +
            (if (!hasCodeScan) " - tap 'Deep scan (code)' to also check the code" else "")
        secFilterBtn.text = if (secOnly >= 0) "Only " + arrayOf("CRIT", "HIGH", "MED", "LOW", "INFO")[secOnly]
            else when (secMinRank) { 1 -> "Filter: HIGH+"; 2 -> "Filter: MED+"; 4 -> "Filter: +INFO"; else -> "Filter: LOW+" }
        secLibBtn.text = if (secShowLibs) "Libs: shown" else "Libs: hidden"
        pathView.text = listTitle
        list.adapter = Ui.RowAdapter(this, out.map { it.label })
    }

    /** 0.37.13: one coloured counter chip per severity above the list; tap = show only that level (tap again = all). */
    private fun refreshSecChips(tot: IntArray) {
        secChips.removeAllViews()
        val names = arrayOf("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        val shortNames = arrayOf("C", "H", "M", "L", "I")
        for (r in 0 until 5) {
            val sc = Ui.sevColor(names[r])
            val on = secOnly == r
            val tv = TextView(this)
            tv.text = shortNames[r] + "  " + tot[r]
            tv.textSize = 12.5f
            tv.gravity = Gravity.CENTER
            tv.typeface = Typeface.DEFAULT_BOLD
            tv.setTextColor(if (on) Color.WHITE else if (tot[r] == 0) Ui.p.sub else sc)
            tv.background = Ui.rr(if (on) sc else Ui.alpha(sc, if (tot[r] == 0) 0x12 else 0x2E), 16)
            tv.setPadding(Ui.dp(4), Ui.dp(7), Ui.dp(4), Ui.dp(7))
            tv.setOnClickListener {
                secMinRank = 3
                secOnly = if (secOnly == r) -1 else r
                if (inSecurity) showSecurityList()
            }
            secChips.addView(tv, LinearLayout.LayoutParams(0, WRAP, 1f).apply { setMargins(Ui.dp(2), 0, Ui.dp(2), 0) })
        }
    }

    private fun openFinding(idx: Int) {
        val f = secFindings.getOrNull(idx) ?: return
        if (f.clsIndex >= 0) {
            // jump straight to the vulnerable line in the normal Smali viewer (Classes-tab style)
            inSecurity = false
            inClasses = true
            jumpFinding = f
            openClass(f.clsIndex, f.at)
            return
        }
        currentFinding = f
        viewingFile = true
        pathView.text = f.title
        showContent("[${f.severity.label}] ${f.title}\n\n${f.detail}\n\nRecommendation:\n${f.recommendation}")
    }

    private fun explainFinding() {
        val f = currentFinding ?: return
        val prompt = "You are a security-focused reverse-engineering tutor doing educational static analysis of an app the user owns or is allowed to analyze.\n" +
            "Explain this security finding in depth: what the real risk is, a realistic attack scenario, and concrete fix steps the developer could take.\n" +
            "Finding: ${f.title} (severity ${f.severity.label})\n" +
            "Detail: ${f.detail}\n" +
            "Suggested direction: ${f.recommendation}\n" +
            "Answer in plain English with short headings and bullets. Keep identifiers in English. Start directly with the content: no greeting, no intro sentence, no closing remarks."
        runAiText("Security finding", prompt, f.title)
    }

    // ---------- 0.21.0: AI secure code review, triage and fix ----------

    /** Secure code review of the open class: scanner hints + AI verdicts + extra issues + fixes. */
    private fun securityReviewWithAi() {
        if (currentClassIndex !in classDefs.indices || currentRaw.isBlank()) {
            Toast.makeText(this, "Open a class first", Toast.LENGTH_SHORT).show()
            return
        }
        val ct = classDefs[currentClassIndex].type
        val idx = currentClassIndex
        val raw = currentRaw
        val pkg = packageNameOrNull() ?: ""
        Thread {
            val hits = try { SecurityScanner.scanSmali(ct, idx, raw, pkg) } catch (_: Throwable) { emptyList() }
            val hint = if (hits.isEmpty()) "(The static scanner found nothing in this class.)"
            else hits.sortedBy { it.severity.rank }.take(12).joinToString("\n") {
                "- [${it.severity.label}] ${it.title}" + (if (it.cwe.isNotEmpty()) " (${it.cwe})" else "") + ": " + it.detail.take(260)
            }
            val prompt = "You are a senior mobile application security engineer doing a secure code review (SAST triage) of ONE smali class from an Android app the user owns or is allowed to analyze.\n" +
                "Scanner hints (heuristic, may be false positives - verify each against the actual code):\n$hint\n\n" +
                "Do:\n1. For each hint: verdict TRUE POSITIVE / FALSE POSITIVE / NEEDS CONTEXT with a one-line reason based on the code (is the data attacker-controlled? is the call reachable? is it library boilerplate?).\n" +
                "2. List additional vulnerabilities you see that the scanner missed (injection, insecure storage, broken crypto, auth/logic flaws, intent/WebView issues): method name, severity, why.\n" +
                "3. For each confirmed issue: a concrete fix in Java/Kotlin source terms plus a one-line hint of the smali change.\n" +
                "If the class is obfuscated, first say in one line what it probably does. If it has no security relevance, say so in one line and stop.\n" +
                "Answer in plain English with short headings and bullets. Keep identifiers in English. Start directly with the content: no greeting, no intro sentence, no closing remarks.\n\nCode:\n" + raw.take(60_000)
            runOnUiThread { runAiText("Security review (AI)", prompt, ct) }
        }.start()
    }

    /**
     * "Harden with AI" (Vulnerability Hunter remediation, 0.29.0): finds the top scanner hit in the
     * open class (or the one the user jumped here from) and asks for a defensive-only patch via
     * VulnHunter.buildHardenPrompt, then runs it through the exact same verbatim-match + diff dialog
     * + Apply + Council review pipeline as every other AI edit (runSuggestWithPrompt). No exploit code
     * is ever requested of the model; see VulnHunter.kt's prompt rules.
     */
    private fun fixVulnWithAi() {
        if (currentClassIndex !in classDefs.indices || !currentEditable || currentRaw.isBlank()) {
            Toast.makeText(this, "Open an editable class first", Toast.LENGTH_LONG).show()
            return
        }
        val key = aiKey()
        if (key.isNullOrEmpty()) {
            Toast.makeText(this, "Add your API key first", Toast.LENGTH_SHORT).show()
            showSettings()
            return
        }
        val ct = classDefs[currentClassIndex].type
        val idx = currentClassIndex
        val raw = currentRaw
        val pkg = packageNameOrNull() ?: ""
        val jf = jumpFinding?.takeIf { it.clsIndex == idx }
        Thread {
            val hits = try { SecurityScanner.scanSmali(ct, idx, raw, pkg).filter { it.severity.rank <= 3 }.sortedBy { it.severity.rank } } catch (_: Throwable) { emptyList() }
            val f = jf ?: hits.firstOrNull()
            runOnUiThread {
                if (f == null) {
                    Toast.makeText(this, "No scanner finding in this class - use Suggest with your own goal", Toast.LENGTH_LONG).show()
                } else if (currentClassIndex != idx || currentRaw != raw) {
                    Toast.makeText(this, "The class changed meanwhile - try again", Toast.LENGTH_LONG).show()
                } else {
                    val prompt = VulnHunter.buildHardenPrompt(f.title, f.severity.label, f.cwe, f.detail, f.recommendation, raw)
                    runSuggestWithPrompt(key, prompt)
                }
            }
        }.start()
    }

    /** Asks the AI to judge the top untriaged CRITICAL/HIGH/MEDIUM code findings of the current view (true / false positive). */
    private fun triageWithAi(limit: Int = 10) {
        if (triageRunning) { triageCancel = true; return }
        val key = aiNeedKey() ?: run { if (smartRunning) smartFinish(); return }
        val cands = secFindings.filter { secIsVisible(it) && it.clsIndex >= 0 && it.verdict.isEmpty() && it.severity.rank <= 2 }.take(limit)
        if (cands.isEmpty()) {
            if (smartRunning) { smartFinish(); return }
            Toast.makeText(this, "No untriaged code findings (CRITICAL/HIGH/MEDIUM) in this view. Run Deep scan first or change the filter.", Toast.LENGTH_LONG).show()
            return
        }
        triageRunning = true
        triageCancel = false
        secTriageBtn.text = "Stop triage"
        val defs = classDefs
        Thread {
            var done = 0
            var failure = ""
            var councilUsed = 0       // 0.29.0: the council re-checks at most 5 TRUE_POSITIVE findings per run (2 extra AI calls each)
            var councilOff = false
            try {
                for (f in cands) {
                    if (triageCancel) break
                    val def = defs.getOrNull(f.clsIndex) ?: continue
                    val text = try { agentIndexedText(def) } catch (_: Throwable) { continue }   // 0.102.0: the text the scan produced f.at from (decoded strings included)
                    var ex = SecurityScanner.excerpt(text, f.at, 3500)
                    // 0.82.0: a taint flow is judged from the SINK method only; show the AI where the untrusted value is read and the path
                    if (f.sourceMethod.isNotEmpty()) {
                        try {
                            val srcType = f.sourceMethod.substringBefore("->")
                            val srcDef = if (srcType == def.type) def else defs.firstOrNull { it.type == srcType }
                            val srcText = when {
                                srcDef == null -> ""
                                srcDef === def -> text
                                else -> { val sf = smaliFile("smali", srcDef.type); if (sf.exists()) sf.readText() else disassemble(srcDef) }
                            }
                            val srcCode = SecurityScanner.methodExcerpt(srcText, f.sourceMethod, 1800)
                            if (srcCode.isNotEmpty() || f.dataPath.isNotEmpty())
                                ex += "\n\nData path (source -> sink): " + f.dataPath.ifEmpty { "(see above)" } +
                                    (if (srcCode.isNotEmpty()) "\n\nCode of the method where the untrusted value is first held (" + f.sourceMethod.substringAfter("->") + "):\n" + srcCode else "")
                        } catch (_: Throwable) { }
                    }
                    traceFinding(f)
                    val prompt = "You are a senior Android application-security engineer triaging a static-analysis (SAST) finding. The code is smali from an app the user owns or is allowed to analyze.\n" +
                        "Finding: ${f.title} [${f.severity.label}] ${f.cwe}\nWhy flagged: ${f.detail.take(if (f.sourceMethod.isNotEmpty()) 900 else 400)}\nClass: ${f.location}\n\n" +
                        reachText(f) + "\n\n" + "Code (the enclosing method):\n$ex\n\n" +
                        "Decide whether this is a real, exploitable weakness. Consider: is the data attacker-controlled, is this library/boilerplate code, is the dangerous call actually used, are there mitigations in the code shown.\n" +
                        "Use TRUE_POSITIVE only if (a) the weakness is intrinsic (for example a hostname verifier that always returns true, a hardcoded key, cleartext traffic) or (b) the dangerous input demonstrably comes from an attacker-controlled source shown in the code or in the call chain. If the dangerous value is only a method parameter and you cannot show where it comes from, answer NEEDS_REVIEW. The confidence number must reflect what you could verify from the code shown (do not go above 70 when you could not see the source of the input).\n" +
                        "Return JSON only, no prose, no markdown fences: {\"verdict\":\"TRUE_POSITIVE|FALSE_POSITIVE|NEEDS_REVIEW\",\"confidence\":0,\"reason\":\"\",\"fix\":\"\"}\n" +
                        "Write reason and fix in plain English (one or two short sentences each); keep identifiers in English. When unsure use NEEDS_REVIEW instead of guessing."
                    val n = done + 1
                    val ans = aiCall(key, prompt, true) { st -> runOnUiThread { if (triageRunning) prog("AI triage $n/${cands.size}: $st") } }
                    val a = ans.indexOf('{')
                    val b = ans.lastIndexOf('}')
                    if (a >= 0 && b > a) {
                        try {
                            val o = JSONObject(ans.substring(a, b + 1))
                            val v = o.optString("verdict").uppercase()
                            f.verdict = when { v.contains("FALSE") -> "FP"; v.contains("TRUE") -> "TP"; else -> "REVIEW" }
                            f.verdictNote = o.optString("reason").trim() +
                                (if (o.optString("fix").isNotBlank()) "\nFix: " + o.optString("fix").trim() else "") +
                                "\n(confidence ${o.optInt("confidence", -1)}%)"
                            // 0.51.0: the AI verdict flips between runs (InsecureBankv2): a lone "false positive" must not bury a finding
                            // that an exact rule matched or that an exported component can reach
                            if (f.verdict == "FP") {
                                try { traceFinding(f) } catch (_: Throwable) { }
                                FindingPolish.guardFalsePositive(f)
                            }
                        } catch (_: Throwable) { f.verdict = "REVIEW"; f.verdictNote = "(the AI answer was not valid JSON)" }
                    } else {
                        f.verdict = "REVIEW"; f.verdictNote = "(the AI answer had no JSON)"
                    }
                    if (f.verdict == "TP" && !councilOff && councilUsed < 5 && !triageCancel && Council.enabled(prefs())) {
                        councilUsed++
                        val analyst = aiModelUsed
                        val cr = try {
                            Council.checkFinding(prefs(), f.title, f.cwe, f.detail, f.location, reachText(f), ex, f.verdictNote, analyst) { st ->
                                runOnUiThread { if (triageRunning) prog("Council $councilUsed/5: $st") }
                            }
                        } catch (_: Throwable) { null }
                        if (cr == null) {
                            councilOff = true        // no second model / quota gone: do not waste more calls this run
                        } else if (cr.verdict == "CONFIRM") {
                            f.verdictNote = f.verdictNote.trim() + "\n⚖️ Council confirmed: " + cr.summary
                        } else {
                            f.verdict = "REVIEW"
                            f.verdictNote = f.verdictNote.trim() + "\n⚖️ Council disagreed (downgraded to REVIEW): " + cr.summary
                        }
                    }
                    done++
                    runOnUiThread { if (inSecurity) { secFindings = secSorted(secFindings); showSecurityList() } }
                }
            } catch (t: Throwable) {
                failure = t.message ?: t.javaClass.simpleName
            }
            runOnUiThread {
                triageRunning = false
                triageCancel = false
                secTriageBtn.text = "AI triage"
                val cb = triageDoneCb
                triageDoneCb = null
                if (!smartRunning || failure.isNotEmpty()) {
                    Toast.makeText(this, "AI triage: $done checked" + (if (failure.isNotEmpty()) " - stopped: " + failure.take(120) else ""), Toast.LENGTH_LONG).show()
                }
                if (inSecurity) { secFindings = secSorted(secFindings); showSecurityList() }
                cb?.invoke()
            }
        }.start()
    }

    // ---------- 0.22.0: Smart scan, Top-5 summary, Explain exploit ----------

    // ---------- 0.23.0: path tracing (entry point -> vulnerable method) ----------

    /** type ("Lpkg/Cls;") of every exported component class present in the dex -> label. Built once per APK. */
    private fun entryTypeMap(): Map<String, String> {
        entryMap?.let { return it }
        val comps = SecurityScanner.exportedComponents(manifestFull, packageNameOrNull() ?: "")
        val types = HashSet<String>()
        for (d in classDefs) types.add(d.type)
        val out = HashMap<String, String>()
        for ((full, label) in comps) {
            val t = "L" + full.replace('.', '/') + ";"
            if (t in types) {
                out[t] = label
            } else {
                // renamed package / relative names: fall back to the simple class name
                val simple = full.substringAfterLast('.')
                val hit = types.firstOrNull { it.endsWith("/$simple;") }
                if (hit != null) out[hit] = label
            }
        }
        entryMap = out
        return out
    }

    /**
     * 0.69.1: exported components of the app that are protected by a SIGNATURE-level permission (class types, only those that exist in the
     * app). They stay entries of the call graph but are not attacker seeds, see CallGraph.setGuardedComponents. Any failure = no guard known
     * (nothing is downgraded), never an exception into the scan.
     */
    private fun guardedEntryTypes(): Collection<String> = try {
        val mc = ManifestContext(manifestFull)
        val pg = PermissionGuard(mc, PermissionGuard.systemResolver(this))
        val known = entryTypeMap().keys
        mc.exportedComponents.map { mc.smaliTypeOf(it) }
            .filter { it.isNotEmpty() && it in known && pg.guardFor(it) == PermissionGuard.Guard.SIGNATURE }
    } catch (_: Throwable) {
        emptyList()
    }

    /** 0.50.0: custom intent-filter actions of the component a class belongs to (an inner class counts for its outer class). */
    private fun actionsOfClass(ci: Int): List<String> {
        val t = classDefs.getOrNull(ci)?.type ?: return emptyList()
        val map = actionMap ?: SecurityScanner.componentActions(manifestFull, packageNameOrNull() ?: "").also { actionMap = it }
        map[t]?.let { return it }
        val outer = t.substringBefore('$').let { if (it.endsWith(";")) it else "$it;" }
        return map[outer] ?: emptyList()
    }

    private fun entryOfClass(ci: Int): String? {
        val t = classDefs.getOrNull(ci)?.type ?: return null
        val map = entryTypeMap()
        map[t]?.let { return it }
        val outer = t.substringBefore('$').let { if (it.endsWith(";")) it else "$it;" }
        return map[outer]
    }

    private fun smaliTextOf(def: ClassDef): String {
        val ef = smaliFile("smali", def.type)
        return if (ef.exists()) ef.readText() else disassemble(def)
    }

    private fun hopLabel(h: SecurityScanner.Hop): String {
        val def = classDefs.getOrNull(h.clsIndex) ?: return "?"
        val cname = def.type.removePrefix("L").removeSuffix(";").replace('/', '.')
        val text = try { smaliTextOf(def) } catch (_: Throwable) { return cname }
        for (line in text.lineSequence()) {
            val t = line.trim()
            if (t.startsWith(".method ")) {
                val sig = t.substringAfterLast(' ')
                if ((def.type + "->" + sig).hashCode() == h.methodHash) return cname + "." + sig.substringBefore('(') + "()"
            }
        }
        return cname
    }

    /** Fills f.reach / f.chain from the call graph. Blocking: call from a background thread. */
    private fun traceFinding(f: SecurityScanner.Finding) {
        if (f.clsIndex < 0 || f.reach.isNotEmpty()) return
        val idx = callIdx ?: return
        try {
            val def = classDefs.getOrNull(f.clsIndex) ?: return
            val key = SecurityScanner.methodKeyAt(def.type, agentIndexedText(def), f.at) ?: return
            val tr = SecurityScanner.trace(idx, key, f.clsIndex, { ci -> entryOfClass(ci) }, typeOf = { ci -> classDefs.getOrNull(ci)?.type }, actionsOf = { ci -> actionsOfClass(ci) })
            if (tr.entry != null) {
                f.reach = "YES"
                f.chain = "Entry: " + tr.entry + "\nPath: " + tr.hops.joinToString(" -> ") { hopLabel(it) }
            } else {
                // 0.50.2: the exact method-level path failed (fragments, lambdas, interface dispatch, Kotlin lowering): try the class level
                // 0.51.2: only caller-driven rules; "approximately reachable" says nothing about deserialization / PBKDF2 / crypto findings
                val ap = if (f.ruleId !in FindingPolish.REACH_RULES) SecurityScanner.Trace(emptyList(), null, true) else SecurityScanner.traceApprox(idx, key, f.clsIndex, { ci -> entryOfClass(ci) }, typeOf = { ci -> classDefs.getOrNull(ci)?.type }, actionsOf = { ci -> actionsOfClass(ci) })
                if (ap.entry != null) {
                    f.reach = "YES~"
                    f.chain = "Entry: " + ap.entry + "\nApproximate path (class level): " + ap.hops.joinToString(" -> ") { hopLabel(it) }
                } else {
                    f.reach = "NO"
                    f.chain = ""
                }
            }
        } catch (_: Throwable) { }
    }

    private fun reachText(f: SecurityScanner.Finding): String = when (f.reach) {
        "YES" -> "Static call graph: reachable from an exported component.\n" + f.chain
        "YES~" -> "Static call graph: APPROXIMATE path. No exact method-by-method path was found, but classes on the way call each other (class-level links skip fragments, lambdas and interface calls), so an exported component probably reaches this code. Not proven: check the path by hand.\n" + f.chain
        "NO" -> "Static call graph: no path from any exported component to this method was found within 6 calls (explicit launches and custom-action implicit Intents are followed; calls through interfaces, reflection or lambdas can be missed, so it may still be reachable; it may also be internal-only code)."
        else -> "Static call graph: not available."
    }

    /** One progress line for the whole Smart scan: "Smart scan [2/3 code] ...". */
    private fun prog(msg: String) {
        pathView.text = if (smartRunning) "Smart scan [$smartStep] $msg" else msg
    }

    /** Manifest scan -> deep scan of all classes -> AI triage of the top findings -> Top-5 summary. */
    private fun smartScan() {
        if (smartRunning) { smartCancelAll(); return }
        if (manifestFull.isBlank() && entries.isEmpty()) {
            Toast.makeText(this, "Pick an APK first", Toast.LENGTH_SHORT).show()
            return
        }
        if (indexing) {
            Toast.makeText(this, "Still reading the classes - try again in a moment", Toast.LENGTH_SHORT).show()
            return
        }
        if (secScanning || triageRunning) {
            Toast.makeText(this, "Another scan is still running", Toast.LENGTH_SHORT).show()
            return
        }
        val hasKey = !aiKey().isNullOrEmpty()
        smartRunning = true
        smartStopped = false
        secSmartBtn.text = "Stop smart scan"
        secMinRank = 3
        secOnly = -1
        secShowLibs = false
        smartStep = "1/3 manifest"
        runManifestScan()
        smartStep = "2/3 code"
        scanDoneCb = {
            if (smartStopped) {
                smartFinish()
            } else if (!hasKey) {
                Toast.makeText(this, "No API key: AI triage skipped (add it in AI settings to get confirmed findings)", Toast.LENGTH_LONG).show()
                smartFinish()
            } else {
                smartStep = "3/3 AI triage"
                triageDoneCb = { smartFinish() }
                triageWithAi(15)
            }
        }
        runDeepScan()
    }

    private fun smartCancelAll() {
        smartStopped = true
        secScanCancel = true
        triageCancel = true
    }

    private fun smartFinish() {
        val stopped = smartStopped
        smartRunning = false
        smartStopped = false
        smartStep = ""
        scanDoneCb = null
        triageDoneCb = null
        secSmartBtn.text = "Smart scan"
        if (!inSecurity) {
            Toast.makeText(this, "Smart scan finished - open the Security tab", Toast.LENGTH_LONG).show()
            return
        }
        if (stopped) showSecurityList() else showSummary()
    }

    /** Top 5 AI-confirmed (TP) findings of the app's own code, one line each; everything else is behind "Show all". */
    private fun showSummary() {
        secSummary = true
        val tpAll = secFindings.filter { it.verdict == "TP" && it.clsIndex >= 0 && it.scope != SecurityScanner.Scope.LIB }
            .sortedWith(compareBy<SecurityScanner.Finding>({ it.severity.rank }, { when (it.reach) { "YES" -> 0; "YES~" -> 1; else -> 2 } }, { scopeRank(it.scope) }, { -it.count }))
        val code = secFindings.filter { it.clsIndex >= 0 && it.scope != SecurityScanner.Scope.LIB }
        val review = code.count { it.verdict == "REVIEW" }
        val fp = code.count { it.verdict == "FP" }
        val untriaged = code.count { it.verdict.isEmpty() && it.severity.rank <= 2 }
        val manifestHigh = secFindings.count { it.clsIndex < 0 && it.severity.rank <= 1 }
        val out = ArrayList<Row>()
        if (tpAll.isEmpty()) {
            out.add(Row("No AI-confirmed vulnerabilities yet" +
                (if (secFindings.none { it.clsIndex >= 0 }) "\n   (code not scanned yet - tap Smart scan)" else
                    if (untriaged > 0) "\n   $untriaged result(s) not yet AI-triaged - tap AI triage" else "")))
        }
        for (f in tpAll.take(5)) {
            val i = secFindings.indexOf(f)
            val why = f.verdictNote.lineSequence().firstOrNull()?.trim().orEmpty().take(140)
            val n = if (f.count > 1) " (x${f.count})" else ""
            val sc = if (f.scope == SecurityScanner.Scope.OTHER) "" else "  [" + f.scope.tag + "]"
            val reachLine = when (f.reach) {
                "YES" -> "\n   ↳ " + f.chain.lineSequence().firstOrNull().orEmpty().removePrefix("Entry: ").take(100)
                "YES~" -> "\n   ↳ (approximate path) " + f.chain.lineSequence().firstOrNull().orEmpty().removePrefix("Entry: ").take(90)
                "NO" -> "\n   ↳ no path from exported components found"
                else -> ""
            }
            out.add(Row("[${f.severity.label}] ${f.title}$n\n   ${f.location}$sc" + (if (why.isNotEmpty()) "\n   $why" else "") + reachLine, file = "top:$i"))
        }
        out.add(Row("Show all results (${secFindings.size}) ▸", file = "top:all"))
        rows = out
        listTitle = "Top ${minOf(5, tpAll.size)} of ${tpAll.size} confirmed (TP) | review: $review | dismissed (FP): $fp" +
            (if (untriaged > 0) " | not triaged: $untriaged" else "") +
            (if (manifestHigh > 0) " | manifest HIGH+: $manifestHigh" else "")
        pathView.text = listTitle
        list.adapter = Ui.RowAdapter(this, out.map { it.label })
    }

    /** Detail of one finding with the AI verdict and the educational "Explain exploit" action. */
    private fun showFindingDialog(idx: Int) {
        val f = secFindings.getOrNull(idx) ?: return
        val pad = (16 * resources.displayMetrics.density).toInt()
        val body = "**[${f.severity.label}] ${f.title}** ${f.cwe}\n${f.location}\n\n" +
            (if (f.verdictNote.isNotBlank()) f.verdictNote.trim() + "\n\n" else f.detail + "\n\n") +
            (if (f.reach.isNotEmpty()) reachText(f) + "\n\n" else "") +
            "Recommendation: ${f.recommendation}" +
            (try { ReportBuilder.dialogExtra(f) } catch (_: Throwable) { "" })
        val tv = TextView(this).apply {
            text = renderMarkdown(body)
            textSize = 14f
            setPadding(pad, pad, pad, pad)
            setTextIsSelectable(true)
        }
        AlertDialog.Builder(this)
            .setTitle("Finding")
            .setView(ScrollView(this).apply { addView(tv) })
            .setPositiveButton("Explain exploit") { _, _ -> explainExploit(f) }
            .setNeutralButton("Open code") { _, _ -> openFinding(idx) }
            .setNegativeButton("Close", null)
            .show()
    }

    /** Educational 4-part explanation (idea / impact / safe check on your own app / fix). No attack code or tools. */
    private fun explainExploit(f: SecurityScanner.Finding) {
        if (aiKey().isNullOrEmpty()) { aiNeedKey(); return }
        val pkg = packageNameOrNull() ?: ""
        val def = classDefs.getOrNull(f.clsIndex)
        Thread {
            traceFinding(f)
            val code = try {
                if (def != null) {
                    SecurityScanner.excerpt(agentIndexedText(def), f.at, 3500)
                } else manifestFull.take(6000)
            } catch (_: Throwable) { "" }
            val prompt = "You are a mobile application security instructor writing a DEFENSIVE, educational explanation for the developer of an Android app that they own (package: $pkg). " +
                "The goal is to let them understand the weakness, confirm it on their own test device, and fix it.\n" +
                "Finding: ${f.title} [${f.severity.label}] ${f.cwe}\nWhy flagged: ${f.detail.take(400)}\n" +
                (if (f.verdictNote.isNotBlank()) "Triage note: ${f.verdictNote.take(500)}\n" else "") +
                "Location: ${f.location}\n${reachText(f)}\n\nCode / manifest excerpt:\n$code\n\n" +
                "If the excerpt shows this is a false positive or not reachable, say so in the first line and stop.\n" +
                "Otherwise write exactly these 4 sections, with these headings:\n" +
                "1) Concept: how another app, a crafted link/intent, a file or a network position could reach the weakness. When a call chain is given above, use it as the path from the entry point to the weakness (mention the entry component and the hops); otherwise name the entry point if the excerpt shows it, or say what you could not see.\n" +
                "2) Impact: what is lost (data, login bypass, code execution...), in plain words.\n" +
                "3) Verify on your app: one to three SAFE steps to confirm it on the developer's own test device, ideally ONE adb command or one observation (for example starting an exported component with `adb shell am start -n $pkg/<Activity>`, reading logcat, or checking a file's permissions). " +
                "Observation only: no payloads, no exploit code, no attack tools, nothing aimed at other people's apps or data. If a simple command cannot confirm it, name the code-review step that does.\n" +
                "4) Fix: the smallest change, in Java/Kotlin terms, with a short snippet if useful.\n" +
                "Keep it short (about 15 lines). Plain English throughout, identifiers and commands in English. Start directly with the content: no greeting, no intro, no closing remarks."
            runOnUiThread { runAiText("Explain exploit", prompt, f.title + " @ " + f.location) }
        }.start()
    }

    private fun runDeepScan() {
        if (secScanning) { secScanCancel = true; return }
        if (manifestFull.isBlank() && entries.isEmpty()) {
            Toast.makeText(this, "Pick an APK first", Toast.LENGTH_SHORT).show()
            return
        }
        if (classDefs.isEmpty()) {
            if (indexing) {
                // 0.36.0: the background index is still reading the classes; continue automatically when it is ready
                deepAfterIndex = true
                secScanBtn.text = "Indexing classes..."
                prog("Indexing classes...")
                return
            }
            indexing = true
            secScanBtn.text = "Indexing classes..."
            prog("Indexing classes...")
            Thread {
                try {
                    buildIndex()
                    runOnUiThread { deepAfterIndex = false; indexing = false; secScanBtn.text = "Deep scan (code)"; if (inSecurity && !(smartRunning && smartStopped)) runDeepScan() else if (smartRunning) smartFinish() }
                } catch (t: Throwable) {
                    runOnUiThread { indexing = false; secScanBtn.text = "Deep scan (code)"; if (smartRunning) smartFinish(); pathView.text = "Error: ${t.javaClass.simpleName}: ${t.message}" }
                }
            }.start()
            return
        }
        val defs = classDefs
        val appPkg = codePackageOf(defs)
        SecurityScanner.tlsInstalled.clear()   // 0.85.0
        SecurityScanner.secretFieldsUsed.clear()   // 0.86.1
        SecurityScanner.clearKeyTracking()   // 0.94.0
        scanDetail = ""; scanDetailOpen = false   // 0.101.0
        PostureScanner.clear()   // 0.91.0
        if (!SecretFormats.loaded()) try {   // 0.89.0: vendor token formats (assets/secret_formats.json)
            SecretFormats.load(assets.open("secret_formats.json").use { it.readBytes() }.toString(Charsets.UTF_8))
        } catch (_: Throwable) { RuleRegistry.noteError("secret-formats") }
        secScanning = true
        secScanCancel = false
        secScanBtn.text = "Stop scan"
        prog("Scanning code ... 0 / ${defs.size}")
        Thread {
            // 0.37.6: the classes are shared between up to 3 worker threads (was 1): same results, roughly 2-3x faster on phones with 4+ cores.
            // Each worker keeps its own findings and call edges (merged at the end, no locks in the hot loop).
            val done = java.util.concurrent.atomic.AtomicInteger(0)
            val errorCount = java.util.concurrent.atomic.AtomicInteger(0)
            val foundCount = java.util.concurrent.atomic.AtomicInteger(0)
            val nextIdx = java.util.concurrent.atomic.AtomicInteger(0)
            val workers = (Runtime.getRuntime().availableProcessors() - 1).coerceIn(1, 3)
            val parts = Array(workers) { ArrayList<SecurityScanner.Finding>() }
            val partEdges = Array(workers) { SecurityScanner.CallIndex() }
            val xlinker = TaintLinker(appPkg)   // 0.49.0: cross-class taint summaries (stage A in the workers, stage B after join)
            val threads = ArrayList<Thread>()
            for (w in 0 until workers) {
                val th = Thread {
                    try {
                        while (true) {
                            if (secScanCancel) break
                            val i = nextIdx.getAndIncrement()
                            if (i >= defs.size) break
                            val def = defs[i]
                            val text = try {
                                agentIndexedText(def)      // 0.36.0: edited smali, else the cached text index, else disassemble (and cache)
                            } catch (_: Throwable) { errorCount.incrementAndGet(); "" }
                            if (text.isNotEmpty()) {
                                try {
                                    val fs = SecurityScanner.scanSmali(def.type, i, text, appPkg)
                                    try { PostureScanner.observe(def.type, text, appPkg) } catch (_: Throwable) { }   // 0.91.0: only the full scan feeds the posture table (not a single-class review)
                                    parts[w].addAll(fs)
                                    foundCount.addAndGet(fs.size)
                                    if (SecurityScanner.scopeOf(def.type, appPkg) != SecurityScanner.Scope.LIB) {
                                        try { SecurityScanner.collectEdges(def.type, i, text, partEdges[w]) } catch (_: Throwable) { }
                                        try { TaintEngine.summarize(def.type, i, text, appPkg, xlinker) } catch (_: Throwable) { RuleRegistry.noteError("taint-xclass") }
                                    }
                                } catch (_: Throwable) { errorCount.incrementAndGet() }
                            }
                            val n = done.incrementAndGet()
                            if (n % 150 == 0) {
                                val h = foundCount.get()
                                runOnUiThread { if (secScanning) prog("Scanning code ... $n / ${defs.size}  ($h finding(s))") }
                            }
                        }
                    } catch (_: Throwable) { errorCount.incrementAndGet() }
                }
                th.priority = Thread.NORM_PRIORITY - 1
                threads.add(th)
                th.start()
            }
            for (th in threads) { try { th.join() } catch (_: InterruptedException) { } }
            val found = ArrayList<SecurityScanner.Finding>()
            for (part in parts) found.addAll(part)
            if (!secScanCancel) {
                try { found.addAll(xlinker.link()) } catch (_: Throwable) { RuleRegistry.noteError("taint-xclass") }
            }
            // 0.56.0 (P1 step 2): the SSA taint engine adds the flows the in-class engine did not report (additive, nothing is removed)
            var ssaNote = ""
            if (!secScanCancel) {
                runOnUiThread { if (secScanning) prog("Data-flow analysis (SSA) ...") }
                try {
                    val extra = ssaFindings(defs, appPkg, found) { msg -> runOnUiThread { if (secScanning) prog(msg) } }
                    found.addAll(extra)
                    // 0.75.2: per-class dedupe ran before the SSA flows existed; run it again so an SSA flow absorbs the text rule of the same class
                    try {
                        val merged = SecurityScanner.dedupe(found.toList())
                        if (merged.size != found.size) { found.clear(); found.addAll(merged) }
                    } catch (_: Throwable) { RuleRegistry.noteError("dedupe-ssa") }
                    // 0.65.0: when groups were capped the answer is only about the part that was analysed: say so instead of a bare "no extra flow"
                    val incomplete = if (ssaIncomplete.isNotEmpty()) " - INCOMPLETE: $ssaIncomplete" else ""
                    ssaNote = (if (extra.isEmpty()) (if (ssaIncomplete.isNotEmpty()) "SSA taint: no extra flow in the analysed scope" else "SSA taint: no extra flow")
                               else "SSA taint: +${extra.size} flow(s)") + incomplete +
                        (if (ssaScopeNote.isNotEmpty()) " ($ssaScopeNote)" else "")
                } catch (t: Throwable) {
                    if (t is IllegalStateException) {
                        ssaNote = "SSA taint ${t.message}"
                    } else {
                        RuleRegistry.noteError("taint-ssa")
                        ssaNote = "SSA taint failed: ${t.javaClass.simpleName}"
                    }
                }
            }
            found.sortBy { it.clsIndex }                      // same order as the old single-thread scan (stable sort)
            // 0.46.0: merge repeats (same rule+class, and INFO across classes into one xN card) before they hit the list
            val aggregated = try { SecurityScanner.aggregate(found) } catch (_: Throwable) { found }
            val edges = SecurityScanner.CallIndex()
            for (pe in partEdges) edges.addAll(pe)
            val scanned = done.get()
            val errors = errorCount.get()
            val stopped = secScanCancel
            runOnUiThread {
                secScanning = false
                secScanCancel = false
                secScanBtn.text = "Deep scan (code)"
                val cb = scanDoneCb
                scanDoneCb = null
                if (classDefs !== defs) { if (smartRunning) smartFinish(); return@runOnUiThread }   // a different APK was loaded meanwhile
                secFindings = secSorted(secFindings.filter { it.clsIndex < 0 } + aggregated)
                callIdx = edges
                lastScanNote = (if (stopped) "stopped at $scanned / ${defs.size}" else "finished, $scanned / ${defs.size} classes") +
                    (if (errors > 0) "; $errors classes failed" else "") +
                    (if (ssaNote.isNotEmpty()) "; $ssaNote" else "")
                if (inSecurity) {
                    showSecurityList()
                    scanDetail = listOfNotNull(if (stopped) "stopped at $scanned / ${defs.size}" else null, if (errors > 0) "$errors classes failed" else null, ssaNote.ifEmpty { null }).joinToString("; ")
                    scanDetailOpen = false
                    pathView.text = listTitle + scanTail()
                }
                cb?.invoke()
            }
        }.start()
    }

    /**
     * 0.56.0 (P1 step 2). Runs the SSA taint over every non-library class and returns, as `taint-flow` findings, the flows whose class has
     * NO finding with the same title yet. Why class + title: scanSmali merges same-title findings of one class into one card kept at the
     * first method, so that is the finest question the old findings can answer. Additive: nothing the in-class engine reported is changed or
     * removed. Called from the deep-scan worker thread. Apps with more than 6000 non-library classes are analysed group by group (0.59.0, ScopePlanner.groups; 0.57.0 used one capped selection, 0.56.0 skipped them because the IR keeps every parsed class in memory).
     */
    /** 0.57.0: set by [ssaFindings] when it analysed only part of a big app (empty = whole app); read by the deep-scan worker for the path bar. */
    private var ssaScopeNote = ""
    @Volatile private var ssaTimeUp = false   // 0.66.2: the SSA time limit was reached
    /** 0.66.2: SSA time limit in minutes for the group loop of big apps; 0 = no limit. Default 10. */
    private fun ssaBudgetMin(): Int = prefs().getInt("ssa_budget_min", 10)
    private fun devToolsEnabled() = prefs().getBoolean("dev_tools", false)
    private var ssaPlanLine = ""   // 0.66.1: plan summary shown in the SSA progress line
    private var ssaIncomplete = ""   // 0.65.0: non-empty when some SSA groups were capped (the result covers only the analysed part)
    /** 0.61.0: the path-bar status of the last Deep scan (stopped / failed classes / SSA taint result), written into the report so a report says whether the SSA step ran. */
    private var lastScanNote = ""

    private fun ssaFindings(defs: List<ClassDef>, appPkg: String, known: List<SecurityScanner.Finding>, progress: (String) -> Unit = {}): List<SecurityScanner.Finding> {
        val appIdx = ArrayList<Int>()
        for ((i, d) in defs.withIndex()) {
            if (SecurityScanner.scopeOf(d.type, appPkg) != SecurityScanner.Scope.LIB) appIdx.add(i)
        }
        val maxClasses = 6000      // up to this size the whole app is one run (as before)
        val groupSize = 3000       // 0.59.0: above it the app is analysed group by group, each group fits in memory
        var groupIdx: List<List<Int>> = listOf(appIdx)
        ssaScopeNote = ""
        ssaIncomplete = ""
        ssaPlanLine = ""
        val entries = entryTypeMap().keys
        var planMs = 0L
        if (appIdx.size > maxClasses) {
            // 0.59.0 (P1 step 4, part 2): no total cap any more. ScopePlanner.groups reads every class text once (keeps only int arrays),
            // then covers EVERY class with a source or a sink in some group, best classes first; each group is parsed, analysed and freed
            val tPlan = System.currentTimeMillis()
            val gr = dev.apkrelab.ir.ScopePlanner.groups(object : dev.apkrelab.ir.ScopePlanner.Source {
                override fun count(): Int = appIdx.size
                override fun type(i: Int): String = defs[appIdx[i]].type
                override fun text(i: Int): String = try { agentIndexedText(defs[appIdx[i]]) } catch (_: Throwable) { "" }
                override fun cancelled(): Boolean = secScanCancel
            }, entries, groupSize, false, false, false)   // 0.59.3: nothing is left out, accuracy before time
            planMs = System.currentTimeMillis() - tPlan
            if (secScanCancel || gr.cancelled) return emptyList()
            groupIdx = gr.groups.map { g -> g.map { appIdx[it] } }
            ssaScopeNote = "${gr.groups.size} groups of up to $groupSize classes, ${gr.marked} classes with a source or sink of ${appIdx.size}" +
                (if (gr.cappedGroups > 0) ", ${gr.cappedGroups} group(s) capped, ${gr.droppedClasses} class(es) cut, biggest closure ${gr.maxClosure} (${gr.maxClosureTiers})" else "") +
                (if (gr.hubs > 0) ", ${gr.hubs} hub class(es) not expanded" else "") +
                (if (gr.markedHubs > 0) ", ${gr.markedHubs} marked hub(s): callers not expanded, one entry path kept" else "")
            ssaPlanLine = "${gr.groups.size} groups, ${gr.cappedGroups} capped" + (if (gr.cappedGroups > 0) ", biggest closure ${gr.maxClosure} (${gr.maxClosureTiers})" else "")
            progress("Data-flow plan ready: $ssaPlanLine")   // visible while the first group runs
            if (gr.cappedGroups > 0) {
                val pct = gr.cappedGroups * 100 / maxOf(1, gr.groups.size)
                ssaIncomplete = "${gr.cappedGroups} of ${gr.groups.size} groups capped ($pct%), flows outside the cut scope are not checked"
            }
        }
        val old = ArrayList<dev.apkrelab.ir.TaintIr.Old>()
        for (f in known) {
            if (f.clsIndex < 0 || !f.ruleId.startsWith("taint")) continue
            val d = defs.getOrNull(f.clsIndex) ?: continue
            old.add(dev.apkrelab.ir.TaintIr.Old(d.type + "->", f.title))
        }
        val tStart = System.currentTimeMillis()
        // 0.60.0: same groups, same engine, same merge as 0.59.3 - only faster (SsaGroups): a class is read and parsed once for all the groups that
        // contain it, the SSA form of a method is built once, and independent groups run on several threads (results merged in group order,
        // so the output is identical). A group that runs out of memory is run again alone, never dropped.
        val rt = Runtime.getRuntime()
        val heapMb = (rt.maxMemory() / (1024L * 1024L)).toInt()
        // 0.101.0: one group needs about a gigabyte to run without the garbage collector taking half of the time (measured on a 18k-class app: at a 1 GB heap two threads spent 59 s
        // of 117 s in GC against 23 s of 78 s for one thread, and the phone's own report said "2 group(s) re-run for memory"); 256 MB per thread was far too little. The result
        // does not depend on the thread count.
        val ssaThreads = if (groupIdx.size < 2) 1 else maxOf(1, minOf(rt.availableProcessors() - 1, heapMb / 1000))
        val report = progress
        val budgetMs = ssaBudgetMin() * 60_000L
        ssaTimeUp = false
        val guardedTypes = guardedEntryTypes()      // 0.69.1: computed once, the groups may run on several threads
        val host = object : dev.apkrelab.ir.SsaGroups.Host {
            override fun guardedEntries(): Collection<String> = guardedTypes
            override fun text(index: Int): String = agentIndexedText(defs[index])
            override fun type(index: Int): String = defs[index].type
            override fun cancelled(): Boolean {
                // 0.66.2: optional time limit for the group loop (Settings). Flows found so far are kept, the status says INCOMPLETE with the coverage.
                if (budgetMs > 0 && !ssaTimeUp && System.currentTimeMillis() - tStart > budgetMs) ssaTimeUp = true
                return secScanCancel || ssaTimeUp
            }
            override fun progress(done: Int, total: Int) {
                if (total <= 1) return
                // 0.66.1: elapsed time + a rough ETA (average per finished group) + the plan summary, so a slow app is visible as such
                val el = (System.currentTimeMillis() - tStart) / 1000
                val eta = if (done > 0) el * (total - done) / done else 0L
                fun fmt(sec: Long) = if (sec >= 3600) "${sec / 3600}h ${(sec % 3600) / 60}m" else if (sec >= 60) "${sec / 60}m ${sec % 60}s" else "${sec}s"
                report("Data-flow analysis (SSA) group $done/$total - ${fmt(el)} elapsed, about ${fmt(eta)} left" + (if (ssaPlanLine.isNotEmpty()) "\n$ssaPlanLine" else ""))
            }
            override fun groupFailed() { RuleRegistry.noteError("taint-ssa") }      // one bad group must not lose the others
        }
        val gres = dev.apkrelab.ir.SsaGroups.run(groupIdx, entries, old, host, 200, ssaThreads)
        if (gres.stopped) {
            if (ssaTimeUp && !secScanCancel) {
                val cov = gres.groupsDone * 100 / maxOf(1, groupIdx.size)
                ssaScopeNote += ", stopped at the ${ssaBudgetMin()} min time limit after ${gres.groupsDone} of ${groupIdx.size} groups ($cov%)"
                ssaIncomplete = (if (ssaIncomplete.isNotEmpty()) "$ssaIncomplete; " else "") + "time limit: only $cov% of the groups were analysed (best classes first)"
            } else {
                ssaScopeNote += ", stopped by you after ${gres.groupsDone} of ${groupIdx.size} groups"      // Stop scan keeps the flows found so far
                val cov = gres.groupsDone * 100 / maxOf(1, groupIdx.size)
                ssaIncomplete = (if (ssaIncomplete.isNotEmpty()) "$ssaIncomplete; " else "") + "stopped: only $cov% of the groups were analysed"
            }
        }
        if (groupIdx.size > 1) ssaScopeNote += ", time: plan ${planMs / 1000}s + groups ${(System.currentTimeMillis() - tStart) / 1000}s on ${gres.threads} thread(s) (heap $heapMb MB, ${rt.availableProcessors()} cores)" +
            ", cpu: parse ${gres.parseMs / 1000}s + analysis ${gres.analyseMs / 1000}s (summed over threads)" +
            (if (gres.groupsRetried > 0) ", ${gres.groupsRetried} group(s) re-run for memory" else "")
        // 0.66.5: where taint is lost, which caps were hit, which methods are slowest (measurement only, no result changes)
        if (gres.stats.analyses > 0) ssaScopeNote += (if (ssaScopeNote.isEmpty()) "" else ", ") + gres.stats.line()
        val out = ArrayList<SecurityScanner.Finding>()
        for (pk in gres.picked) {
            val item = pk.item
            val ci = pk.classIndex
            val text = try { agentIndexedText(defs[ci]) } catch (_: Throwable) { "" }
            val line = if (text.isEmpty()) 0 else SecurityScanner.lineNo(text, item.at)
            val sev = SecurityScanner.Severity.values().firstOrNull { it.label == item.sev } ?: SecurityScanner.Severity.HIGH
            // 0.66.9: the note only when the call graph really was partial (big app analysed group by group, or groups capped / stopped); ssaScopeNote is never empty any more (it holds the stats line)
            val reducedNote = if (!item.reachable && (groupIdx.size > 1 || ssaIncomplete.isNotEmpty())) "  Note: this app was analysed group by group (hub classes are not expanded, one entry path is kept per marked class), so a missing path from an exported component can be an artefact of that." else ""
            val f = SecurityScanner.Finding(sev, item.title, item.detail + reducedNote + (if (line > 0) "  (around line $line)" else ""), item.fix, item.classType, ci, item.at, item.cwe)
            f.ruleId = TaintFlowRule.id
            f.confidence = item.confidence
            f.sourceMethod = item.sourceMethod      // 0.82.0: what the AI triage is shown besides the sink method
            f.dataPath = item.dataPath
            f.scope = SecurityScanner.scopeOfText(item.classType, appPkg, text)      // 0.83.0
            if (item.reachable) { f.reach = "YES"; f.chain = "Entry: " + item.entry + "\nPath: " + item.path } else { f.reach = "NO"; f.chain = "" }
            out.addAll(FindingPolish.apply(listOf(f), item.classType,
                f.scope == SecurityScanner.Scope.OBF && text.isNotEmpty() && SecurityScanner.isAppBoundObf(text, appPkg)))   // 0.82.0
        }
        return out
    }

    // ---------- viewer helpers: highlighting, methods jump, AI prompt ----------

    private fun present(text: String) {
        currentRaw = text
        showContent(if (text.startsWith(".class") && text.length <= 150_000) highlightSmali(text) else text)
    }

    private fun highlightSmali(src: String): CharSequence {
        val sb = SpannableStringBuilder(src)
        fun paint(re: Regex, color: Int, group: Int = 0) {
            for (m in re.findAll(src)) {
                val r = if (group == 0) m.range else (m.groups[group]?.range ?: continue)
                sb.setSpan(ForegroundColorSpan(color), r.first, r.last + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
        }
        val ml = RegexOption.MULTILINE
        paint(rx("\\bL[\\w/$]+;"), Ui.hl(0xFF2E7D32.toInt()))                       // types
        paint(rx("\\b[vp]\\d+\\b"), Ui.hl(0xFF6A1B9A.toInt()))                       // registers
        paint(rx("^\\s*([a-z][a-z0-9-]*(?:/[a-z0-9/]+)?)(?=\\s|$)", ml), Ui.hl(0xFF1565C0.toInt()), 1) // opcodes
        paint(rx("^\\s*(\\.[\\w-]+)", ml), Ui.hl(0xFFEF6C00.toInt()), 1)             // directives
        paint(rx("^\\s*:\\w+", ml), Ui.hl(0xFFC62828.toInt()))                       // labels
        paint(rx("\"(?:[^\"\\\\]|\\\\.)*\""), Ui.hl(0xFFAD1457.toInt()))            // strings
        paint(rx("#.*$", ml), Ui.hl(0xFF757575.toInt()))                             // comments
        return sb
    }

    private fun showMethods() {
        if (javaMode) leaveJava()
        val items = ArrayList<Pair<String, Int>>()
        var pos = 0
        for (line in currentRaw.split("\n")) {
            val t = line.trim()
            if (t.startsWith(".method ")) items.add(t.removePrefix(".method ") to pos)
            pos += line.length + 1
        }
        if (items.isEmpty()) {
            Toast.makeText(this, "No methods in this file", Toast.LENGTH_SHORT).show()
            return
        }
        AlertDialog.Builder(this)
            .setTitle("Methods (${items.size})")
            .setItems(items.map { it.first }.toTypedArray()) { _, i -> scrollToOffset(items[i].second) }
            .show()
    }

    private fun scrollToOffset(offset: Int) {
        val layout = contentText.layout ?: return
        val line = layout.getLineForOffset(minOf(offset, contentText.text.length))
        contentScroll.scrollTo(0, layout.getLineTop(line))
    }

    private fun copyPrompt() {
        val prompt = "You are a reverse-engineering tutor for educational static analysis.\n" +
            "Explain this smali code step by step: purpose, inputs/outputs, control flow, " +
            "and calls to other methods.\n" +
            "Answer in plain English as a numbered flow, then a 2-line summary.\n\n" +
            "Code:\n" + currentRaw.take(30_000)
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("prompt", prompt))
        Toast.makeText(this, "Prompt copied - paste it into any AI", Toast.LENGTH_SHORT).show()
    }

    // ---------- light markdown rendering for AI answers ----------

    private fun renderMarkdown(src: String): CharSequence {
        val sb = SpannableStringBuilder()
        val inline = rx("\\*\\*(.+?)\\*\\*|`([^`]+)`")
        val headingRe = rx("^\\s*#{1,6}\\s*(.*)$")
        val bulletRe = rx("^(\\s*)[*-]\\s+")
        var inCode = false
        val hrRe = rx("^\\s*(-{3,}|\\*{3,}|_{3,})\\s*$")
        for (raw in src.split("\n")) {
            if (raw.trim().startsWith("```")) { inCode = !inCode; continue }
            if (!inCode && hrRe.matches(raw)) {
                val hs = sb.length
                sb.append("────────────────").append('\n')
                sb.setSpan(ForegroundColorSpan(Ui.shade(0x55)), hs, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                continue
            }
            if (inCode) {
                val cs = sb.length
                sb.append(raw).append('\n')
                sb.setSpan(TypefaceSpan("monospace"), cs, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                sb.setSpan(BackgroundColorSpan(Ui.shade(0x14)), cs, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                continue
            }
            var line = raw
            var heading = false
            val h = headingRe.find(line)
            if (h != null) {
                line = h.groupValues[1]
                heading = true
            } else {
                line = line.replace(bulletRe, "$1• ")
            }
            val lineStart = sb.length
            var last = 0
            for (m in inline.findAll(line)) {
                sb.append(line, last, m.range.first)
                val start = sb.length
                if (m.groups[1] != null) {
                    sb.append(m.groupValues[1])
                    sb.setSpan(StyleSpan(Typeface.BOLD), start, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                } else {
                    sb.append(m.groupValues[2])
                    sb.setSpan(TypefaceSpan("monospace"), start, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                }
                last = m.range.last + 1
            }
            sb.append(line, last, line.length)
            if (heading && sb.length > lineStart) {
                sb.setSpan(StyleSpan(Typeface.BOLD), lineStart, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                sb.setSpan(RelativeSizeSpan(1.2f), lineStart, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            sb.append('\n')
        }
        return sb
    }

    // ---------- load last APK ----------

    private fun applyResult(r: Result) {
        reportItems.clear()
        entries = r.entries
        apkModule = r.module
        currentPath = ""
        manifestFull = r.manifest
        codeSearchCancel = true
        listTitle = ""
        apkGen++
        indexing = false
        deepAfterIndex = false
        infoBase = r.info
        classDefs = emptyList()
        classDex.clear()
        modified.clear()
        inClasses = false
        inSecurity = false
        secFindings = emptyList()
        scanResourcesAsync()
        callIdx = null
        entryMap = null
        actionMap = null
        currentFinding = null
        jumpFinding = null
        currentClassIndex = -1
        info.text = r.info
        setHeroCompact(true)
        showTree()
        showList()
        startBackgroundIndex()
    }

    private fun openLast() {
        if (!apkFile.exists()) {
            Toast.makeText(this, "No saved APK yet - pick one first", Toast.LENGTH_SHORT).show()
            return
        }
        apkGen++
        info.text = "Analyzing..."
        Thread {
            try {
                val r = analyzeFile(apkFile)
                runOnUiThread { applyResult(r) }
            } catch (t: Throwable) {
                runOnUiThread { info.text = "Error: ${t.javaClass.simpleName}: ${t.message}" }
            }
        }.start()
    }

    // ---------- smali editing (0.7.0) ----------

    /** root = "smali" (edited) or "smali_orig" (backup of the original). One folder per dex, e.g. smali/classes2/... */
    private fun smaliFile(root: String, type: String): File {
        val dex = (classDex[type] ?: "classes.dex").removeSuffix(".dex")
        return File(filesDir, "workspaces/p1/$root/$dex/${type.removePrefix("L").removeSuffix(";")}.smali")
    }

    private fun loadModified() {
        modified.clear()
        val root = File(filesDir, "workspaces/p1/smali")
        if (!root.exists()) return
        for (f in root.walkTopDown()) {
            if (!f.isFile || !f.name.endsWith(".smali")) continue
            val rel = f.relativeTo(root).path
            val slash = rel.indexOf('/')
            if (slash > 0) modified.add("L" + rel.substring(slash + 1).removeSuffix(".smali") + ";")
        }
    }

    private fun hideEditUi() {
        editing = false
        editScroll.visibility = View.GONE
        editActions.visibility = View.GONE
        buildActions.visibility = View.GONE
        buildActions2.visibility = View.GONE
        buildStatus.visibility = View.GONE
        buildScroll.visibility = View.GONE
        if (::manifestActions.isInitialized) manifestActions.visibility = View.GONE
    }

    private fun hideKeyboard() {
        val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
        imm.hideSoftInputFromWindow(editor.windowToken, 0)
    }

    private fun showClassTitle() {
        if (currentClassIndex !in classDefs.indices) return
        val t = classDefs[currentClassIndex].type
        pathView.text = t + if (t in modified) "   ✏ edited" else ""
    }

    private fun guardEdit(then: () -> Unit) {
        if (editing && editor.text.toString() != currentRaw) {
            AlertDialog.Builder(this)
                .setTitle("Unsaved changes")
                .setMessage("Discard your edits?")
                .setPositiveButton("Discard") { _, _ -> then() }
                .setNegativeButton("Keep editing", null)
                .show()
        } else {
            then()
        }
    }

    private fun startEdit() {
        if (javaMode) leaveJava()
        if (currentClassIndex !in classDefs.indices || !currentEditable) {
            Toast.makeText(this, "Read-only: open a class from the Classes tab (very large classes are view-only)", Toast.LENGTH_LONG).show()
            return
        }
        editing = true
        editor.setText(currentRaw)
        editor.setSelection(0)
        actions.visibility = View.GONE
        contentScroll.visibility = View.GONE
        editActions.visibility = View.VISIBLE
        editScroll.visibility = View.VISIBLE
        editScroll.scrollTo(0, 0)
        pathView.text = "✏ editing " + classDefs[currentClassIndex].type
    }

    private fun saveEdit(): Boolean {
        if (currentClassIndex !in classDefs.indices) return false
        val def = classDefs[currentClassIndex]
        val text = editor.text.toString()
        val head = text.lineSequence().firstOrNull { it.trimStart().startsWith(".class") }
        if (head == null || !head.trimEnd().endsWith(" " + def.type)) {
            Toast.makeText(this, "Keep the .class line unchanged (class must stay ${def.type})", Toast.LENGTH_LONG).show()
            return false
        }
        return try {
            val ef = smaliFile("smali", def.type)
            val of = smaliFile("smali_orig", def.type)
            if (text == currentOrig) {
                ef.delete()
                of.delete()
                modified.remove(def.type)
                Toast.makeText(this, "Same as original - edit removed", Toast.LENGTH_SHORT).show()
            } else {
                if (!of.exists()) {
                    of.parentFile?.mkdirs()
                    of.writeText(currentOrig)
                }
                ef.parentFile?.mkdirs()
                ef.writeText(text)
                modified.add(def.type)
                Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
            }
            currentRaw = text
            true
        } catch (t: Throwable) {
            Toast.makeText(this, "Save failed: ${t.javaClass.simpleName}: ${t.message}", Toast.LENGTH_LONG).show()
            false
        }
    }

    private fun closeEditor() {
        hideKeyboard()
        hideEditUi()
        viewingFile = true
        present(currentRaw)
        showClassTitle()
    }

    private fun finishEdit() {
        if (editor.text.toString() == currentRaw) {
            closeEditor()
            return
        }
        AlertDialog.Builder(this)
            .setTitle("Unsaved changes")
            .setPositiveButton("Save") { _, _ -> if (saveEdit()) closeEditor() }
            .setNegativeButton("Discard") { _, _ -> closeEditor() }
            .setNeutralButton("Cancel", null)
            .show()
    }

    private fun revertEdit() {
        if (currentClassIndex !in classDefs.indices) return
        val def = classDefs[currentClassIndex]
        AlertDialog.Builder(this)
            .setTitle("Revert to original?")
            .setMessage("Your edits of this class (saved and unsaved) will be deleted.")
            .setPositiveButton("Revert") { _, _ ->
                smaliFile("smali", def.type).delete()
                smaliFile("smali_orig", def.type).delete()
                modified.remove(def.type)
                hideKeyboard()
                hideEditUi()
                openClass(currentClassIndex)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showDiff() {
        if (currentClassIndex !in classDefs.indices) return
        val pad = (12 * resources.displayMetrics.density).toInt()
        val tv = TextView(this).apply {
            text = simpleDiff(currentOrig, editor.text.toString())
            textSize = 11f
            typeface = Typeface.MONOSPACE
            setPadding(pad, pad, pad, pad)
            setTextIsSelectable(true)
        }
        AlertDialog.Builder(this)
            .setTitle("Changes vs original")
            .setView(ScrollView(this).apply { addView(tv) })
            .setPositiveButton("Close", null)
            .show()
    }

    /** Line diff: trims common head/tail, then LCS on the middle (falls back to a plain block if it is huge). */
    private fun simpleDiff(a: String, b: String): CharSequence {
        if (a == b) return "No changes"
        val x = a.split("\n")
        val y = b.split("\n")
        var s = 0
        while (s < x.size && s < y.size && x[s] == y[s]) s++
        var ex = x.size
        var ey = y.size
        while (ex > s && ey > s && x[ex - 1] == y[ey - 1]) { ex--; ey-- }
        val n = ex - s
        val m = ey - s
        val sb = SpannableStringBuilder()
        var shown = 0
        val red = 0xFFC62828.toInt()
        val green = 0xFF2E7D32.toInt()
        fun line(prefix: String, no: Int, text: String, color: Int) {
            if (shown++ >= 400) return
            val st = sb.length
            sb.append(prefix).append(no.toString()).append(": ").append(text).append('\n')
            sb.setSpan(ForegroundColorSpan(color), st, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        if (n.toLong() * m <= 4_000_000L) {
            val dp = Array(n + 1) { IntArray(m + 1) }
            for (i in n - 1 downTo 0) {
                for (j in m - 1 downTo 0) {
                    dp[i][j] = if (x[s + i] == y[s + j]) dp[i + 1][j + 1] + 1 else maxOf(dp[i + 1][j], dp[i][j + 1])
                }
            }
            var i = 0
            var j = 0
            while (i < n || j < m) {
                when {
                    i < n && j < m && x[s + i] == y[s + j] -> { i++; j++ }
                    j >= m || (i < n && dp[i + 1][j] >= dp[i][j + 1]) -> { line("-", s + i + 1, x[s + i], red); i++ }
                    else -> { line("+", s + j + 1, y[s + j], green); j++ }
                }
            }
        } else {
            for (i in 0 until n) line("-", s + i + 1, x[s + i], red)
            for (j in 0 until m) line("+", s + j + 1, y[s + j], green)
        }
        if (shown > 400) sb.append("... (${shown - 400} more changed lines not shown)\n")
        return sb
    }

    // ---------- AI (providers: see AiHub.kt) ----------

    private fun prefs() = getSharedPreferences("apkrelab_prefs", MODE_PRIVATE)

    private fun showSettings() {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val p = prefs()
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
        }
        var primary = AiHub.primaryId(p)
        val primaryBtn = Button(this)
        fun refreshPrimary() {
            val lbl = AiHub.specs.firstOrNull { it.id == primary }?.label ?: primary
            primaryBtn.text = "Primary: $lbl  (tap to change)"
        }
        refreshPrimary()
        primaryBtn.setOnClickListener {
            val i = AiHub.specs.indexOfFirst { it.id == primary }
            primary = AiHub.specs[(i + 1) % AiHub.specs.size].id
            refreshPrimary()
        }
        box.addView(primaryBtn)
        box.addView(TextView(this).apply {
            text = "The primary provider (Gemini by default) leads, workers and council use its models first; if a model is busy or out of quota the next one answers, then the other providers that have a key. Leave a key empty to skip that provider."
            textSize = 12f
        })
        val keyEdits = ArrayList<EditText>()
        val modelEdits = ArrayList<EditText>()
        val orEdit = EditText(this).apply {
            setText(AiHub.orList(p).joinToString("\n"))
            hint = "tap Refresh to fill the list"
            textSize = 12f
            minLines = 3
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        }
        for (s in AiHub.specs) {
            val saved = p.getString(s.keyPref, null) != null
            box.addView(TextView(this).apply { text = "\n" + s.label; textSize = 15f })
            val ke = EditText(this).apply {
                hint = if (saved) "Key saved (leave empty to keep it)" else s.keyHint
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                setSingleLine()
            }
            val me = EditText(this).apply {
                setText(AiHub.model(p, s))
                hint = "model name (change it if you get a 404)"
                setSingleLine()
            }
            keyEdits.add(ke)
            modelEdits.add(me)
            box.addView(ke)
            box.addView(me)
            if (s.id == "openrouter") {
                box.addView(TextView(this).apply {
                    text = "Free models, strongest first (one id per line). When one is busy or out of quota the next one is used; the model above is the last resort."
                    textSize = 12f
                })
                box.addView(orEdit)
                box.addView(Button(this).apply {
                    text = "Refresh free models list"
                    setOnClickListener {
                        text = "Loading..."
                        Thread {
                            val r: List<String>? = try { AiHub.fetchFreeModels() } catch (_: Throwable) { null }
                            this@MainActivity.runOnUiThread {
                                if (r == null || r.isEmpty()) {
                                    text = "Refresh failed - tap to retry"
                                } else {
                                    orEdit.setText(r.joinToString("\n"))
                                    text = "Refresh free models list (" + r.size + " found)"
                                }
                            }
                        }.start()
                    }
                })
            }
        }
        box.addView(TextView(this).apply {
            text = "\nSelected code is sent to the AI providers you enable (free tiers may use it for training). Use it only on apps you own or are allowed to analyze."
            textSize = 12f
        })
        box.addView(Button(this).apply {
            text = "Clear AI cache (${AiCache.count()} saved answers)"
            setOnClickListener {
                val n = AiCache.clear()
                text = "Clear AI cache (0 saved answers)"
                Toast.makeText(this@MainActivity, "Cache cleared ($n)", Toast.LENGTH_SHORT).show()
            }
        })
        box.addView(Button(this).apply {
            fun lbl() = if (bgIndexEnabled()) "Background indexing: ON  (tap to turn off)" else "Background indexing: OFF  (tap to turn on)"
            text = lbl()
            setOnClickListener {
                prefs().edit().putBoolean("bg_index", !bgIndexEnabled()).apply()
                if (!bgIndexEnabled()) bgIndexCancel = true
                text = lbl()
            }
        })
        box.addView(TextView(this).apply {
            text = "After an APK is loaded the app reads all classes in the background (low priority) so search and scans start fast. Uses up to ~400 MB of cache; turning it off stops it at once."
            textSize = 12f
        })
        box.addView(Button(this).apply {
            fun lbl(): String { val m = ssaBudgetMin(); return "SSA time limit: " + (if (m == 0) "none" else "$m min") + "  (tap to change)" }
            text = lbl()
            setOnClickListener {
                val opts = listOf(5, 10, 20, 0)
                val i = opts.indexOf(ssaBudgetMin())
                prefs().edit().putInt("ssa_budget_min", opts[(i + 1) % opts.size]).apply()
                text = lbl()
            }
        })
        box.addView(TextView(this).apply {
            text = "Big apps only (more than 6000 classes): the data-flow step stops after this time and keeps the flows found so far. The report then says INCOMPLETE with the share of groups analysed (best classes first). \"none\" = run to the end."
            textSize = 12f
        })
        box.addView(Button(this).apply {
            fun lbl() = if (devToolsEnabled()) "Developer exports: ON  (tap to turn off)" else "Developer exports: OFF  (tap to turn on)"
            text = lbl()
            setOnClickListener {
                prefs().edit().putBoolean("dev_tools", !devToolsEnabled()).apply()
                text = lbl()
            }
        })
        box.addView(TextView(this).apply {
            text = "Adds the engine test exports (IR stress test, call graph compare, taint on SSA) to the Export report list. They are for debugging the scanner, not for reading findings."
            textSize = 12f
        })
        box.addView(Button(this).apply {
            fun lbl() = if (Council.enabled(prefs())) "Council: ON  (tap to turn off)" else "Council: OFF  (tap to turn on)"
            text = lbl()
            setOnClickListener {
                prefs().edit().putBoolean("council", !Council.enabled(prefs())).apply()
                text = lbl()
            }
        })
        box.addView(TextView(this).apply {
            text = "Council = for hard tasks only (agent edits, confirmed security findings) a second and third model review the answer before you see it. Costs 2 extra AI calls per review."
            textSize = 12f
        })
        box.addView(Button(this).apply {
            fun lbl(): String {
                val v = Team.leadPref(prefs())
                return "Lead model: " + (if (v.isEmpty()) "Auto (strongest: " + (Team.lead(prefs())?.label ?: "none") + ")" else v) + "  (tap to change)"
            }
            text = lbl()
            setOnClickListener {
                val opts = listOf("") + Team.roster(prefs()).map { it.label }
                val i = opts.indexOf(Team.leadPref(prefs()))
                prefs().edit().putString("lead", opts[(i + 1) % opts.size]).apply()
                text = lbl()
            }
        })
        box.addView(Button(this).apply {
            fun lbl() = if (Team.delegationEnabled(prefs())) "Delegation to worker models: ON  (tap to turn off)" else "Delegation to worker models: OFF  (tap to turn on)"
            text = lbl()
            setOnClickListener {
                prefs().edit().putBoolean("delegate", !Team.delegationEnabled(prefs())).apply()
                text = lbl()
            }
        })
        box.addView(TextView(this).apply {
            text = "AI Hub team: the LEAD (the strongest model you have a key for, or the one you pick) plans and answers; the other models are WORKERS that get focused sub-tasks (read a class, review the manifest, find vulnerabilities) in parallel. Models are ranked by my own estimate, not a benchmark: pick the lead yourself if you disagree. Keys are saved with the Save button; the list of models updates after you save."
            textSize = 12f
        })
        box.addView(Button(this).apply {
            text = "Theme: " + Ui.p.key.replaceFirstChar { it.uppercase() } + "  (tap to change)"
            setOnClickListener {
                val order = listOf("cobra", "midnight", "ocean", "night")
                val next = order[(order.indexOf(Ui.p.key) + 1) % order.size]
                prefs().edit().putString("theme", next).apply()
                text = "Theme: " + next.replaceFirstChar { it.uppercase() } + " - applies on next app start"
            }
        })
        Ui.skin(box)
        AlertDialog.Builder(this)
            .setTitle("AI settings")
            .setView(ScrollView(this).apply { addView(box) })
            .setPositiveButton("Save") { _, _ ->
                val e = prefs().edit()
                for ((i, s) in AiHub.specs.withIndex()) {
                    val k = keyEdits[i].text.toString().filter { !it.isWhitespace() }
                    if (k.isNotEmpty()) e.putString(s.keyPref, SecureStore.encrypt(k))
                    e.putString(s.modelPref, modelEdits[i].text.toString().trim().ifEmpty { s.defaultModel })
                }
                e.putString("primary", primary)
                e.putString("or_free_list", orEdit.text.toString().lines().map { it.trim() }.filter { it.isNotEmpty() }.joinToString("\n"))
                e.apply()
                Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
            }
            .setNeutralButton("Delete keys") { _, _ ->
                val e = prefs().edit()
                for (s in AiHub.specs) e.remove(s.keyPref)
                e.apply()
                Toast.makeText(this, "All keys deleted", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun aiNeedKey(): String? {
        val key = aiKey()
        if (key.isNullOrEmpty()) {
            Toast.makeText(this, "Add your API key first", Toast.LENGTH_SHORT).show()
            showSettings()
            return null
        }
        return key
    }

    private fun showAiDialog(title: String): TextView {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val tv = TextView(this).apply {
            text = "Thinking..."
            textSize = 14f
            setPadding(pad, pad, pad, pad)
            setTextIsSelectable(true)
        }
        AlertDialog.Builder(this)
            .setTitle(title)
            .setView(ScrollView(this).apply { addView(tv) })
            .setPositiveButton("Copy") { _, _ ->
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("ai", tv.text))
            }
            .setNegativeButton("Close", null)
            .show()
        return tv
    }

    /** Runs a free-text prompt (answer cached) and shows it with light markdown rendering. */
    private fun runAiText(title: String, prompt: String, subject: String = "") {
        val key = aiNeedKey() ?: return
        val tv = showAiDialog(title)
        Thread {
            val result: CharSequence = try {
                var lastUi = 0L
                val ans = aiCall(key, prompt, true, { partial ->
                    // 0.16.0: live text while streaming (throttled ~4 updates/s, markdown re-rendered)
                    val now = System.currentTimeMillis()
                    if (now - lastUi > 250) { lastUi = now; runOnUiThread { tv.text = renderMarkdown(partial) } }
                }) { st -> runOnUiThread { tv.text = st } }
                runOnUiThread { addReportItem(title, subject, ans.trim()) }
                renderMarkdown((if (aiFromCache) "⚡ (from cache - no API usage)\n\n" else "") + ans.trim() + aiFooter())
            } catch (t: Throwable) {
                "Error: ${t.message ?: t.javaClass.simpleName}"
            }
            runOnUiThread { tv.text = result }
        }.start()
    }

    private fun explainWithAi() {
        if (currentRaw.isBlank()) return
        val prompt = "You are a reverse-engineering tutor for educational static analysis.\n" +
            "Explain the following smali code step by step: the purpose, inputs/outputs, " +
            "control flow (branches/loops), and calls to other methods. If it is obfuscated, " +
            "suggest meaningful names. Answer in plain English as a numbered flow, " +
            "then a 2-line summary. Keep code identifiers in English. Start directly with the content: no greeting, no intro sentence, no closing remarks.\n\nCode:\n" + currentRaw.take(80_000)
        runAiText("AI explanation", prompt, currentClassName())
    }

    // ---------- Markdown report export (0.15.0) ----------

    private fun currentClassName(): String =
        if (currentClassIndex in classDefs.indices) classDefs[currentClassIndex].type else ""

    /** Keeps the latest answer per (title, subject) for the report. */
    private fun addReportItem(title: String, subject: String, text: String) {
        if (text.isBlank()) return
        reportItems.removeAll { it.title == title && it.subject == subject }
        reportItems.add(ReportItem(title, subject, text))
    }

    /** Plain unified-style diff: common head/tail trimmed, the middle shown as - / + lines (capped). */
    private fun plainDiff(a: String, b: String): String {
        if (a == b) return "(no changes)"
        val x = a.split("\n")
        val y = b.split("\n")
        var s = 0
        while (s < x.size && s < y.size && x[s] == y[s]) s++
        var ex = x.size
        var ey = y.size
        while (ex > s && ey > s && x[ex - 1] == y[ey - 1]) { ex--; ey-- }
        val sb = StringBuilder()
        sb.append("@@ line ${s + 1} @@\n")
        for (i in s until minOf(ex, s + 80)) sb.append("- ").append(x[i]).append('\n')
        if (ex - s > 80) sb.append("... (${ex - s - 80} more removed lines)\n")
        for (i in s until minOf(ey, s + 80)) sb.append("+ ").append(y[i]).append('\n')
        if (ey - s > 80) sb.append("... (${ey - s - 80} more added lines)\n")
        return sb.toString()
    }

    /**
     * 0.49.1 / 0.49.5: runs on the report's background thread. Traces the findings whose risk depends on a caller reaching them
     * (FindingPolish.wantsReach: HIGH taint flows plus MEDIUM+ APP findings of the caller-driven rules, max 150) so the report knows
     * whether an exported component can reach them, then lets FindingPolish add the "not reached" note (severity is never lowered).
     * A class that is itself an exported component (or an inner class of one) is YES at once, with no path to walk.
     */
    private fun reachPass() {
        try {
            var n = 0
            for (f in secFindings) {
                if (n >= 150) break
                if (f.reach.isNotEmpty() || !FindingPolish.wantsReach(f)) continue
                traceFinding(f); n++
            }
            FindingPolish.applyReach(secFindings)
            // 0.77.0: unreached HIGH taint findings in helper classes / signature-guarded components drop one level
            try {
                val mc = ManifestContext(manifestFull)
                FindingPolish.lowerUnreachedHelpers(secFindings, mc.components.map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.toSet(),
                    guardedEntryTypes().toSet())
                FindingPolish.lowerNonExportedReceivers(secFindings, FindingPolish.nonExportedReceiversAndServices(mc))   // 0.80.0
                FindingPolish.lowerSeparateProcessDialogs(secFindings, FindingPolish.separateProcessActivities(mc))       // 0.81.0
                FindingPolish.applyProviderCodeChecks(secFindings)                                                      // 0.81.0
                FindingPolish.applyNetworkEvidence(secFindings)                                                         // 0.81.0
                FindingPolish.restoreInstalledTls(secFindings)                                                          // 0.85.0
                FindingPolish.raiseUsedSecretFields(secFindings)                                                        // 0.86.1
                FindingPolish.lowerCallerVerified(secFindings)                                                          // 0.94.0
                if (secFindings.none { it.ruleId == "posture-summary" }) secFindings = secFindings + FindingPolish.resolvePendingKeys().filter { k -> secFindings.none { it.classType == k.classType && it.title == k.title } }   // 0.94.0
                if (secFindings.none { it.ruleId == "posture-summary" }) secFindings = secFindings + PostureScanner.findings()   // 0.91.0: summary (INFO) and the retired SafetyNet API (LOW)
                FindingPolish.lowerNonExportedProviders(secFindings, FindingPolish.nonExportedProviders(mc) { t ->
                    classDefs.firstOrNull { it.type == t }?.superclass?.takeIf { sc -> classDefs.any { it.type == sc } }                     // app classes only
                })              // 0.84.0
            } catch (_: Throwable) { }
        } catch (_: Throwable) { }
    }

    private fun buildReport(): String {
        reachPass()
        val sb = StringBuilder()
        val pkg = packageNameOrNull() ?: "unknown"
        sb.append("# APK ReLab report: ").append(pkg).append("\n\n")
        sb.append("> Educational static analysis. Use only on apps you own or are allowed to analyze.\n\n")
        sb.append("## App info\n\n```\n").append(info.text.toString().replace(rx("\\n(⏳|✅|⚠) Index[^\\n]*"), "").trim()).append("\n```\n\n")
        if (manifestFull.isNotBlank()) {
            val xi = manifestFull.indexOf("<?xml")
            val mx = if (xi > 0) manifestFull.substring(xi) else manifestFull
            sb.append("## AndroidManifest.xml\n\n```xml\n").append(mx.take(40_000))
            if (mx.length > 40_000) sb.append("\n... (truncated)")
            sb.append("\n```\n\n")
        }
        if (manifestFull.isNotBlank()) {
            val xi2 = manifestFull.indexOf("<?xml")
            sb.append(try { ReportBuilder.attackSurface(if (xi2 > 0) manifestFull.substring(xi2) else manifestFull, pkg) } catch (_: Throwable) { "" })
        }
        sb.append("## Security scan\n\n")
        if (secFindings.isEmpty()) {
            sb.append("Not run yet. Open the Security tab (manifest checks run automatically) and tap 'Deep scan (code)' for code-level checks.\n\n")
        } else {
            if (lastScanNote.isNotEmpty()) sb.append("Deep scan status: ").append(lastScanNote).append("\n\n")
            sb.append(ReportBuilder.securitySection(secFindings, 400))
            sb.append(try { ReportBuilder.scaSection(LibraryScanner.inventory) } catch (_: Throwable) { LibraryScanner.sbomMarkdown() })
            try { sb.append(PostureScanner.section()) } catch (_: Throwable) { RuleRegistry.noteError("posture") }   // 0.91.0
            try { sb.append(AttackScenarios.section(secFindings, ManifestContext(manifestFull), packageNameOrNull() ?: "")) } catch (_: Throwable) { RuleRegistry.noteError("scenarios") }   // 0.93.0
            try { sb.append(Masvs.section(secFindings)) } catch (_: Throwable) { RuleRegistry.noteError("masvs") }   // 0.92.0: which MASVS v2 controls were assessed   // 0.47.0: Third-Party Libraries & SCA
        }
        val edited = modified.toList().sorted()
        sb.append("## Edited classes (").append(edited.size).append(")\n\n")
        if (edited.isEmpty()) sb.append("None.\n\n")
        for (t in edited) {
            sb.append("### ").append(t).append("\n\n")
            try {
                val o = smaliFile("smali_orig", t)
                val e = smaliFile("smali", t)
                val orig = if (o.exists()) o.readText() else ""
                val now = if (e.exists()) e.readText() else ""
                sb.append("```diff\n").append(plainDiff(orig, now).trimEnd()).append("\n```\n\n")
            } catch (th: Throwable) {
                sb.append("(could not read: ").append(th.message).append(")\n\n")
            }
        }
        sb.append("## AI notes (this session)\n\n")
        if (reportItems.isEmpty()) sb.append("None. Use Explain / Patterns / Review manifest first and they will be included.\n")
        for (ri in reportItems) {
            sb.append("### ").append(ri.title)
            if (ri.subject.isNotEmpty()) sb.append(" - ").append(ri.subject)
            sb.append("\n\n").append(ri.text).append("\n\n")
        }
        return sb.toString()
    }

    /** 0.40.0: the same report as a single HTML page (security findings with the educational cards, AI notes). */
    private fun buildReportHtml(): String {
        reachPass()
        val pkg = packageNameOrNull() ?: "unknown"
        val infoText = info.text.toString().replace(rx("\\n(⏳|✅|⚠) Index[^\\n]*"), "").trim()
        val notes = reportItems.map { (if (it.subject.isNotEmpty()) it.title + " - " + it.subject else it.title) to it.text }
        return ReportBuilder.html(pkg, infoText, secFindings, notes, manifestXml = manifestFull,
            scaLibs = LibraryScanner.inventory)   // 0.47.0: SCA table in the HTML report
    }

    /** 0.40.0: [format] "md" or "html"; empty = ask the user (the Report chip). The AI Hub tool passes "md". */
    private fun exportReport(format: String = "") {
        if (apkModule == null) {
            Toast.makeText(this, "Pick an APK first", Toast.LENGTH_SHORT).show()
            return
        }
        if (format.isEmpty()) {
            // 0.66.8: the three engine test exports are listed only when Settings > Developer exports is ON (they are not findings)
            val labels = ArrayList(listOf("Markdown (.md)", "HTML (.html, opens in any browser)", "SARIF (.sarif, for GitHub / VS Code / DefectDojo)"))
            if (devToolsEnabled()) labels.addAll(listOf("IR stress test (.txt, needs a Deep scan first)", "Call graph compare (.txt, needs a Deep scan first)", "Taint on SSA, experimental (.txt, needs a Deep scan first)"))
            AlertDialog.Builder(this)
                .setTitle("Export report")
                .setItems(labels.toTypedArray()) { _, which ->
                    exportReport(when (which) { 1 -> "html"; 2 -> "sarif"; 3 -> "irstress"; 4 -> "cgcompare"; 5 -> "taint"; else -> "md" })
                }
                .setNegativeButton("Cancel", null)
                .show()
            return
        }
        val asHtml = format == "html"
        val asSarif = format == "sarif"
        val asIr = format == "irstress"
        val asCg = format == "cgcompare"
        val asTaint = format == "taint"
        if ((asIr || asCg || asTaint) && classDefs.isEmpty()) {
            Toast.makeText(this, "Run a Deep scan first so the classes are indexed", Toast.LENGTH_LONG).show()
            return
        }
        Thread {
            try {
                val md = if (asCg) {
                    // 0.54.0: old Kotlin reach answers vs the new IR CallGraph, per finding (nothing in the scanner is changed)
                    reachPass()
                    val defs = classDefs
                    val appPkg = codePackageOf(defs)
                    val app = ArrayList<dev.apkrelab.ir.ClassIr>()
                    for (d in defs) {
                        if (SecurityScanner.scopeOf(d.type, appPkg) == SecurityScanner.Scope.LIB) continue
                        try { app.add(dev.apkrelab.ir.SmaliParser.parse(agentIndexedText(d))) } catch (_: Throwable) { }
                    }
                    val items = ArrayList<dev.apkrelab.ir.CgCompare.Item>()
                    for (f in secFindings) {
                        if (f.clsIndex < 0 || f.reach.isEmpty()) continue
                        val d = defs.getOrNull(f.clsIndex) ?: continue
                        val key = try { SecurityScanner.methodKeyAt(d.type, agentIndexedText(d), f.at) } catch (_: Throwable) { null } ?: continue
                        items.add(dev.apkrelab.ir.CgCompare.Item(key, f.reach, f.title, f.chain))
                    }
                    dev.apkrelab.ir.CgCompare.run(app, entryTypeMap().keys, items)
                } else if (asTaint) {
                    // 0.55.0 (P1): taint on SSA over the new CallGraph, a separate report, nothing in the scanner is changed
                    val defs = classDefs
                    val appPkg = codePackageOf(defs)
                    val app = ArrayList<dev.apkrelab.ir.ClassIr>()
                    for (d in defs) {
                        if (SecurityScanner.scopeOf(d.type, appPkg) == SecurityScanner.Scope.LIB) continue
                        try { app.add(dev.apkrelab.ir.SmaliParser.parse(agentIndexedText(d))) } catch (_: Throwable) { }
                    }
                    val old = ArrayList<dev.apkrelab.ir.TaintIr.Old>()
                    for (f in secFindings) {
                        if (f.clsIndex < 0 || !f.ruleId.startsWith("taint")) continue
                        val d = defs.getOrNull(f.clsIndex) ?: continue
                        val key = try { SecurityScanner.methodKeyAt(d.type, agentIndexedText(d), f.at) } catch (_: Throwable) { null } ?: continue
                        old.add(dev.apkrelab.ir.TaintIr.Old(key, f.title))
                    }
                    val g = dev.apkrelab.ir.CallGraph.build(app, entryTypeMap().keys, dev.apkrelab.ir.CallGraph.Mode.RTA, null)
                    dev.apkrelab.ir.TaintIr.analyze(g, false, old).format()   // 0.55.2: every app method, each flow is marked reachable or not
                } else if (asIr) {
                    // 0.53.1: parser + CFG + SSA over every indexed class, nothing else touched
                    val defs = classDefs
                    dev.apkrelab.ir.IrStress.run(defs.size, dev.apkrelab.ir.IrStress.TextSource { i -> agentIndexedText(defs[i]) }).format()
                } else if (asSarif) {
                    reachPass()
                    val ver = try { packageManager.getPackageInfo(packageName, 0).versionName ?: "" } catch (_: Throwable) { "" }
                    SarifExport.build(packageNameOrNull() ?: "unknown", ver, secFindings)
                } else if (asHtml) buildReportHtml() else buildReport()
                runOnUiThread {
                    pendingReport = md
                    val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = if (asIr || asCg || asTaint) "text/plain" else if (asSarif) "application/json" else if (asHtml) "text/html" else "text/markdown"
                        putExtra(Intent.EXTRA_TITLE, (packageNameOrNull() ?: "apk") + (if (asTaint) "-taint.txt" else if (asCg) "-cg-compare.txt" else if (asIr) "-ir-stress.txt" else if (asSarif) ".sarif" else if (asHtml) "-report.html" else "-report.md"))
                    }
                    @Suppress("DEPRECATION")
                    startActivityForResult(intent, reportRequest)
                }
            } catch (t: Throwable) {
                runOnUiThread { Toast.makeText(this, "Report failed: ${t.message}", Toast.LENGTH_LONG).show() }
            }
        }.start()
    }

    // ---------- Template E: manifest / permission review (0.12.0) ----------

    private fun reviewManifest() {
        if (manifestFull.isBlank()) {
            Toast.makeText(this, "Pick an APK first", Toast.LENGTH_SHORT).show()
            return
        }
        val prompt = "You are a reverse-engineering tutor for educational static analysis of apps the user owns or is allowed to analyze.\n" +
            "Review this AndroidManifest.xml:\n" +
            "1) Explain each permission in one plain line.\n" +
            "2) List the exported components (activities, services, receivers, providers), say whether each is protected by a permission, and what that implies.\n" +
            "3) Flag anything unusual for the app's apparent purpose and say why. Also mention debuggable, allowBackup and cleartext-traffic flags if present.\n" +
            "Answer in plain English with short headings and bullets. Keep identifiers in English. Start directly with the content: no greeting, no intro sentence, no closing remarks.\n\nManifest:\n" + manifestFull.take(60_000)
        runAiText("AI manifest review", prompt, "AndroidManifest.xml")
    }

    // ---------- Template B: design pattern detection (0.14.0) ----------

    private fun patternsWithAi() {
        if (currentClassIndex !in classDefs.indices || currentRaw.isBlank()) {
            Toast.makeText(this, "Open a class from the Classes tab first", Toast.LENGTH_LONG).show()
            return
        }
        val cls = classDefs[currentClassIndex].type
        // direct context: other classes in the same package (names only, capped) - helps spot Factory/Adapter/Observer partners
        val pkg = cls.substringBeforeLast('/', "")
        val siblings = ArrayList<String>()
        if (pkg.isNotEmpty()) {
            for (d in classDefs) {
                if (siblings.size >= 60) break
                if (d.type != cls && d.type.substringBeforeLast('/', "") == pkg) siblings.add(d.type)
            }
        }
        val prompt = "You are a reverse-engineering tutor for educational static analysis.\n" +
            "Analyze the following smali class and identify design patterns (Singleton, Observer, Factory, Builder, Adapter, " +
            "Strategy, Decorator, Proxy, MVVM, Repository, ...). For each pattern found give: the pattern name, " +
            "the evidence from the code (fields, methods, calls), a confidence level (low/medium/high), and the role of this class " +
            "(and of the related classes listed below, if relevant). If no clear pattern exists, say so honestly instead of guessing. " +
            "The class may be obfuscated: judge by structure and behavior, not by names. " +
            "Answer in plain English with short headings and bullets. Keep identifiers in English. " +
            "Start directly with the content: no greeting, no intro sentence, no closing remarks.\n\n" +
            "Class: $cls\n" +
            (if (siblings.isNotEmpty()) "Other classes in the same package (names only):\n" + siblings.joinToString("\n") + "\n\n" else "\n") +
            "Code:\n" + currentRaw.take(80_000)
        runAiText("AI design patterns", prompt, cls)
    }

    // ---------- Template D: rename suggestions for obfuscated code (0.12.0) ----------

    private fun renameWithAi() {
        if (currentClassIndex !in classDefs.indices || currentRaw.isBlank()) {
            Toast.makeText(this, "Open a class from the Classes tab first", Toast.LENGTH_LONG).show()
            return
        }
        val key = aiNeedKey() ?: return
        val cls = classDefs[currentClassIndex].type
        // explicit list of the names declared in this class, so the model does not skip them
        val declared = ArrayList<String>()
        declared.add("class: $cls")
        for (line in currentRaw.lineSequence()) {
            val t = line.trim()
            if (t.startsWith(".method ")) {
                val n = t.substringBefore('(').substringAfterLast(' ')
                if (n.isNotEmpty() && n != "<init>" && n != "<clinit>") declared.add("method: $n")
            } else if (t.startsWith(".field ")) {
                val n = t.substringBefore(':').substringAfterLast(' ')
                if (n.isNotEmpty()) declared.add("field: $n")
            }
            if (declared.size >= 60) break
        }
        val base = "You are a reverse-engineering tutor for educational static analysis of apps the user owns or is allowed to analyze.\n" +
            "Short names such as a, b, c or La/a; are obfuscated. Suggest a meaningful English name for each declared name below whose purpose you can infer from the code " +
            "(also infer from the callees and from what the class does as a whole). Skip framework/library methods. Maximum 25 items.\n" +
            "Return [] ONLY if every declared name is already meaningful. If you cannot infer a purpose, still give your best guess and say so in the reason.\n" +
            "Declared names:\n" + declared.joinToString("\n") + "\n" +
            "Return JSON only (no prose, no markdown fences): [{\"old\":\"\",\"new\":\"\",\"reason\":\"\"}]\n" +
            "\"old\" is exactly as written in the code (class descriptor, method name or field name); \"new\" is a readable English name; " +
            "\"reason\" is one short sentence in plain English. If nothing needs renaming return [].\n\nCode:\n" + currentRaw.take(60_000)
        val model = AiHub.cacheModel(prefs())
        val tv = showAiDialog("AI rename suggestions")
        Thread {
            var items: JSONArray? = null
            var err = ""
            var cached = false
            var footer = ""
            try {
                var prompt = base
                for (attempt in 1..2) {
                    val ans = aiCall(key, prompt, attempt == 1) { st -> runOnUiThread { tv.text = st } }
                    val wasCached = aiFromCache
                    val foot = aiFooter()
                    val parsed: JSONArray? = try {
                        val a = ans.indexOf('[')
                        val b = ans.lastIndexOf(']')
                        if (a < 0 || b <= a) null else JSONArray(ans.substring(a, b + 1))
                    } catch (_: Throwable) { null }
                    if (parsed == null) {
                        if (attempt == 1) AiCache.remove(AiCache.key(model, base))
                        err = "The answer was not valid JSON."
                        prompt = base + "\n\nYour previous answer was not valid JSON. Return a valid JSON array only."
                        continue
                    }
                    items = parsed
                    cached = wasCached
                    footer = foot
                    err = ""
                    break
                }
            } catch (t: Throwable) {
                err = t.message ?: t.javaClass.simpleName
            }
            val finalItems = items
            val result: CharSequence = if (finalItems == null) {
                "Error: $err"
            } else if (finalItems.length() == 0) {
                AiCache.remove(AiCache.key(model, base))
                "The AI says no names need changing in this class (this reply isn't cached, you can retry)." + footer
            } else {
                val sb = StringBuilder()
                if (cached) sb.append("⚡ (from cache - no API usage)\n\n")
                sb.append("Class: ").append(cls).append("\n\n")
                for (i in 0 until finalItems.length()) {
                    val o = finalItems.optJSONObject(i) ?: continue
                    sb.append("${i + 1}. ${o.optString("old")}  ->  ${o.optString("new")}\n")
                    sb.append("   ${o.optString("reason")}\n\n")
                }
                sb.append("Note: these are read-only suggestions (no automatic apply). Actually renaming must be done across every class that uses it.")
                sb.append(footer)
                sb.toString()
            }
            runOnUiThread { tv.text = result }
        }.start()
    }

    // ---------- build / sign / install (0.8.0) ----------

    private fun blog(msg: String) {
        if (building) BuildService.update(applicationContext, msg)
        runOnUiThread {
            buildText.append(msg).append('\n')
            buildLog.text = buildText.toString()
            setBuildStatus(msg)
            buildScroll.post { buildScroll.fullScroll(View.FOCUS_DOWN) }
        }
    }

    /** 0.37.15: coloured status pill above the build log (Ready / Building / Done / Failed). */
    private fun setBuildStatus(msg: String) {
        if (!::buildStatus.isInitialized) return
        val green = 0xFF2E9E5B.toInt()
        val red = 0xFFE53935.toInt()
        when {
            msg.startsWith("BUILD FAILED") -> { buildStatus.text = "✘ Build failed"; buildStatus.setTextColor(red); buildStatus.background = Ui.rr(Ui.alpha(red, 0x2E), 16) }
            msg.startsWith("DONE") -> { buildStatus.text = "✔ Build finished - tap Install"; buildStatus.setTextColor(green); buildStatus.background = Ui.rr(Ui.alpha(green, 0x2E), 16) }
            building -> { buildStatus.text = "Building..."; buildStatus.setTextColor(Ui.p.hi); buildStatus.background = Ui.rr(Ui.alpha(Ui.p.hi, 0x2E), 16) }
        }
    }

    /** 0.92.1: the app's code package, with the manifest components as evidence (white-label apps). */
    private fun codePackageOf(defs: List<com.android.tools.smali.dexlib2.iface.ClassDef>): String {
        val pkg = packageNameOrNull() ?: ""
        val comps = try { ManifestContext(manifestFull).componentTypes(pkg) } catch (_: Throwable) { emptyList() }
        return SecurityScanner.codePackage(defs.map { it.type }, pkg, comps)
    }

    private fun packageNameOrNull(): String? = try { apkModule?.androidManifest?.packageName } catch (_: Throwable) { null }

    private fun openBuildTab() {
        inClasses = false
        inSecurity = false
        viewingFile = false
        hideEditUi()
        list.visibility = View.GONE
        setSearchUi(View.GONE)
        secScanBtn.visibility = View.GONE
        secSmartBtn.visibility = View.GONE
        secBenchBtn.visibility = View.GONE
        actions.visibility = View.GONE
        secActions.visibility = View.GONE
        contentScroll.visibility = View.GONE
        buildActions.visibility = View.VISIBLE
        buildActions2.visibility = View.VISIBLE
        buildStatus.visibility = View.VISIBLE
        buildScroll.visibility = View.VISIBLE
        pathView.text = "Build / Sign / Install"
        if (buildText.isEmpty() && !building) {
            val edited = Rebuilder(wsDir) { }.editedFiles().values.sumOf { it.size }
            buildText.append("Package: ${packageNameOrNull() ?: "(open an APK first)"}\n")
            buildText.append("Edited classes: $edited\n")
            val mpend = ManifestEdits.load(wsDir).size
            if (mpend > 0) buildText.append("Manifest changes: $mpend pending\n")
            buildText.append("Signing key: " + (SigningKey.fingerprint()?.take(23)?.plus("...") ?: "(created on first build)") + "  [Export key = backup .p12]" + "\n\n")
            buildText.append("Build, then Install. Same package already installed with another signature? Tap Uninstall first (its data is deleted).\n")
            buildText.append("The build keeps running if you leave the app.\n")
            buildLog.text = buildText.toString()
        } else {
            buildLog.text = buildText.toString()
        }
    }

    private fun startBuild() {
        if (building) { Toast.makeText(this, "Build already running", Toast.LENGTH_SHORT).show(); return }
        if (!apkFile.exists()) { Toast.makeText(this, "Pick an APK first", Toast.LENGTH_SHORT).show(); return }
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 77)
        }
        buildText.setLength(0)
        buildLog.text = ""
        try {
            BuildService.start(applicationContext)
        } catch (t: Throwable) {
            BuildService.running = true   // build still runs, just without the foreground service
            blog("(foreground service not started: ${t.javaClass.simpleName})")
        }
        val appCtx = applicationContext
        val t0 = System.currentTimeMillis()
        val newPkg = renameTarget()
        if (newPkg != null) blog("Package rename is ON: -> $newPkg (the original app is NOT replaced; both can be installed)")
        Thread {
            var finalMsg = "Build finished"
            try {
                val rb = Rebuilder(wsDir) { blog(it) }
                val out = rb.build(newPkg)
                prepareSplits(rb, newPkg)
                if (newPkg != null) checkRenamed(out, newPkg)
                finalMsg = "Done in ${(System.currentTimeMillis() - t0) / 1000}s (${fmt(out.length())}). Tap Install."
                blog("DONE in ${(System.currentTimeMillis() - t0) / 1000}s (${fmt(out.length())}). Tap Install.")
            } catch (t: Throwable) {
                finalMsg = "Build failed: ${t.javaClass.simpleName}"
                blog("BUILD FAILED: ${t.javaClass.simpleName}: ${t.message}")
                if (t is OutOfMemoryError) blog("Out of memory: close other apps, or edit classes in a smaller dex.")
            } finally {
                BuildService.finish(appCtx, finalMsg)
            }
        }.start()
    }

    // ---------- package rename (0.17.0) ----------

    private val pkgRegex = rx("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

    /** New package chosen by the user (null = rename off, or equal to the original / to this app). */
    private fun renameTarget(): String? {
        val v = prefs().getString("newpkg", "")?.trim().orEmpty()
        if (v.isEmpty() || !pkgRegex.matches(v)) return null
        if (v == packageNameOrNull() || v == packageName) return null
        return v
    }

    private fun renameDialog() {
        val old = packageNameOrNull()
        if (old == null) { Toast.makeText(this, "Pick an APK first", Toast.LENGTH_SHORT).show(); return }
        val pad = (16 * resources.displayMetrics.density).toInt()
        val et = EditText(this).apply {
            hint = "$old.relab"
            setText(prefs().getString("newpkg", "").orEmpty())
            setSingleLine()
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
            addView(et)
        }
        AlertDialog.Builder(this)
            .setTitle("Package rename")
            .setMessage("Original: $old\n\nWith a new package the modified app installs NEXT TO the original (no uninstall needed). " +
                "Meant for testing apps you own. The manifest (and the split APKs) are patched; code and resources are not, " +
                "so an app that hard-codes its own package name in code or resources may misbehave.")
            .setView(box)
            .setPositiveButton("Save") { _, _ ->
                val v = et.text.toString().trim()
                when {
                    v.isEmpty() -> { prefs().edit().remove("newpkg").apply(); blog("Package rename: OFF") }
                    !pkgRegex.matches(v) -> Toast.makeText(this, "Invalid package name", Toast.LENGTH_LONG).show()
                    v == old || v == packageName -> Toast.makeText(this, "Must differ from the original and from APK ReLab", Toast.LENGTH_LONG).show()
                    else -> { prefs().edit().putString("newpkg", v).apply(); blog("Package rename: ON -> $v (applies to the next Build)") }
                }
            }
            .setNeutralButton("Turn off") { _, _ -> prefs().edit().remove("newpkg").apply(); blog("Package rename: OFF") }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /** Asks Android itself to parse the rebuilt base APK: confirms the patched manifest is valid. */
    private fun checkRenamed(apk: File, expected: String) {
        try {
            @Suppress("DEPRECATION")
            val pi = packageManager.getPackageArchiveInfo(apk.absolutePath, 0)
            when {
                pi == null -> blog("Check: Android could NOT parse the new manifest (install will probably fail)")
                pi.packageName == expected -> blog("Check: Android parsed the APK, package = ${pi.packageName}  OK")
                else -> blog("Check: Android reports package ${pi.packageName}, expected $expected")
            }
        } catch (t: Throwable) {
            blog("Check skipped: ${t.javaClass.simpleName}: ${t.message}")
        }
    }

    /** Split apps: copy the installed app's split APKs and sign them with the same key (must be done BEFORE uninstalling the original). */
    private fun prepareSplits(rb: Rebuilder, newPkg: String? = null) {
        val pkg = packageNameOrNull() ?: return
        val marker = File(splitsDir, ".prepared")
        val tag = pkg + "|" + (newPkg ?: "") + "|" + (SigningKey.fingerprint() ?: "")
        val splits = try { packageManager.getApplicationInfo(pkg, 0).splitSourceDirs } catch (_: Throwable) { null }
        if (splits.isNullOrEmpty()) {
            val sameTag = try { marker.exists() && marker.readText() == tag } catch (_: Throwable) { false }
            val haveApks = splitsDir.listFiles().orEmpty().any { it.name.endsWith(".apk") }
            val reuse = sameTag && haveApks
            if (reuse) {
                blog("Splits: original not installed - reusing the splits prepared earlier (same app, same key)")
            } else {
                splitsDir.deleteRecursively()
                blog("Splits: none found (original not installed, or not a split app)")
            }
            return
        }
        splitsDir.deleteRecursively()
        splitsDir.mkdirs()
        blog("Splits: signing ${splits.size} split APK(s) from the installed app")
        for (p in splits) {
            val src = File(p)
            if (newPkg != null) {
                val tmpSplit = File(splitsDir, src.name + ".unsigned")
                try {
                    rb.renameApk(src, tmpSplit, newPkg)
                    rb.sign(tmpSplit, File(splitsDir, src.name), 26)
                } finally {
                    tmpSplit.delete()
                }
            } else {
                rb.sign(src, File(splitsDir, src.name), 26)
            }
        }
        try { marker.writeText(tag) } catch (_: Throwable) { }
    }

    private fun installApk() {
        if (building) return
        if (!signedFile.exists()) { Toast.makeText(this, "Build first", Toast.LENGTH_SHORT).show(); return }
        if (!packageManager.canRequestPackageInstalls()) {
            blog("Allow 'Install unknown apps' for APK ReLab in the settings screen that just opened, come back and tap Install again.")
            startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:$packageName")))
            return
        }
        blog("Installing...")
        val f = signedFile
        Thread {
            var sid = -1
            try {
                val pi = packageManager.packageInstaller
                val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL)
                val id = pi.createSession(params)
                sid = id
                pi.openSession(id).use { session ->
                    f.inputStream().use { input ->
                        session.openWrite("base.apk", 0, f.length()).use { o ->
                            input.copyTo(o)
                            session.fsync(o)
                        }
                    }
                    for ((i, sp) in splitsDir.listFiles().orEmpty().filter { it.name.endsWith(".apk") }.sortedBy { it.name }.withIndex()) {
                        sp.inputStream().use { input ->
                            session.openWrite("split_$i.apk", 0, sp.length()).use { o ->
                                input.copyTo(o)
                                session.fsync(o)
                            }
                        }
                    }
                    val intent = Intent(installAction).setPackage(packageName)
                    val pending = PendingIntent.getBroadcast(
                        this, id, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                    )
                    session.commit(pending.intentSender)
                }
            } catch (t: Throwable) {
                if (sid >= 0) try { packageManager.packageInstaller.abandonSession(sid) } catch (_: Throwable) { }
                blog("Install error: ${t.javaClass.simpleName}: ${t.message}")
            }
        }.start()
    }

    private fun uninstallOriginal() {
        val pkg = packageNameOrNull()
        if (pkg == null) { Toast.makeText(this, "Open an APK first", Toast.LENGTH_SHORT).show(); return }
        if (pkg == packageName) { Toast.makeText(this, "That is APK ReLab itself", Toast.LENGTH_LONG).show(); return }
        AlertDialog.Builder(this)
            .setTitle("Uninstall $pkg?")
            .setMessage("Needed because your signature differs from the original. The app's data will be deleted.")
            .setPositiveButton("Uninstall") { _, _ ->
                startActivity(Intent(Intent.ACTION_DELETE, Uri.parse("package:$pkg")))
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun askPassword(title: String, msg: String, onOk: (CharArray) -> Unit) {
        val pad = (16 * resources.displayMetrics.density).toInt()
        val et = EditText(this).apply {
            hint = "Password (min 4 characters)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine()
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
            addView(et)
        }
        AlertDialog.Builder(this)
            .setTitle(title)
            .setMessage(msg)
            .setView(box)
            .setPositiveButton("OK") { _, _ ->
                val t = et.text.toString()
                if (t.length < 4) Toast.makeText(this, "Password too short", Toast.LENGTH_SHORT).show()
                else onOk(t.toCharArray())
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun exportKey() {
        if (!SigningKey.exists()) { blog("No key yet - run a Build once (it creates the key), then export."); return }
        askPassword("Export signing key", "Choose a password for the .p12 file. Anyone with the file and password can sign apps as you - keep it private.") { pw ->
            pendingKeyPwd = pw
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/x-pkcs12"
                putExtra(Intent.EXTRA_TITLE, "relab-signing-key.p12")
            }
            @Suppress("DEPRECATION")
            startActivityForResult(intent, exportKeyRequest)
        }
    }

    private fun importKeyPick() {
        AlertDialog.Builder(this)
            .setTitle("Import signing key")
            .setMessage("This replaces the current key. APKs signed with the current key can then no longer be updated in place (export it first if you need it).")
            .setPositiveButton("Choose .p12") { _, _ ->
                val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "*/*"
                }
                @Suppress("DEPRECATION")
                startActivityForResult(intent, importKeyRequest)
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun newKey() {
        AlertDialog.Builder(this)
            .setTitle("Create a new signing key?")
            .setMessage("The current key will be deleted (export it first if you want to keep it). Apps installed with the old key must be uninstalled before installing new builds.")
            .setPositiveButton("Create") { _, _ ->
                Thread {
                    try {
                        SigningKey.createNew()
                        blog("New key created. SHA-256: " + (SigningKey.fingerprint()?.take(23) ?: "?") + "...")
                    } catch (t: Throwable) {
                        blog("Key creation failed: ${t.javaClass.simpleName}: ${t.message}")
                    }
                }.start()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun exportApk() {
        if (!signedFile.exists()) { Toast.makeText(this, "Build first", Toast.LENGTH_SHORT).show(); return }
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/vnd.android.package-archive"
            putExtra(Intent.EXTRA_TITLE, "modified-signed.apk")
        }
        @Suppress("DEPRECATION")
        startActivityForResult(intent, exportRequest)
    }

    // ---------- AI modification suggestion (Template C, 0.9.0) ----------

    private class Suggestion(val original: String, val modified: String, val explanation: String, val risk: String)
    private class Loc(val start: Int, val end: Int, val origUsed: String, val repl: String)

    private fun aiKey(): String? = AiHub.anyKey(prefs())

    /** Blocking Gemini call with the same retry/fallback policy as Explain. Throws RuntimeException(message). */
    @Volatile private var aiFromCache = false

    private fun aiCall(key: String, prompt: String, cache: Boolean = false, onPartial: ((String) -> Unit)? = null, status: (String) -> Unit): String {
        // 0.27.0: provider chain (primary, then the other providers with a key) lives in AiHub.kt; "key" is kept only for the old call sites.
        val r = Team.call(prefs(), prompt, cache, onPartial, status)   // 0.31.0: same team order as the agent (primary provider first, default Gemini)
        aiFromCache = r.fromCache
        aiModelUsed = r.label
        aiNote = r.notes
        return r.text
    }

    @Volatile private var aiModelUsed = ""
    @Volatile private var aiNote = ""

    /** Footer shown under AI answers: which model answered, and why a fallback happened (if it did). */
    private fun aiFooter(): String {
        val who = if (aiModelUsed.isEmpty()) "unknown model" else aiModelUsed
        val src = if (aiFromCache) " (cached)" else ""
        return "\n\nanswered by: " + who + src + (if (aiNote.isNotEmpty()) "\nfailed attempts before:\n" + aiNote else "")
    }

    private fun parseSuggestion(raw: String): Suggestion {
        val t = raw.trim()
        val a = t.indexOf('{')
        val b = t.lastIndexOf('}')
        if (a < 0 || b <= a) throw RuntimeException("no JSON object in the answer")
        val o = JSONObject(t.substring(a, b + 1))
        return Suggestion(o.optString("original"), o.optString("modified"), o.optString("explanation"), o.optString("risk"))
    }

    private class SL(val lineStart: Int, val start: Int, val end: Int, val text: String)

    private fun countOcc(src: String, o: String): Int {
        var n = 0
        var i = src.indexOf(o)
        while (i >= 0) { n++; i = src.indexOf(o, i + o.length) }
        return n
    }

    /**
     * The 'original' snippet must match exactly one place in the class.
     * Tries exact text, then newline-trimmed, then fully trimmed, then a line-by-line match that ignores indentation/blank lines.
     * Returns (location or null, number of matches seen: 0 = not found, >=2 = ambiguous).
     */
    private fun locate(src: String, s: Suggestion): Pair<Loc?, Int> {
        var seen = 0
        val cands = listOf(
            s.original to s.modified,
            s.original.trim('\n', '\r') to s.modified.trim('\n', '\r'),
            s.original.trim() to s.modified.trim()
        )
        for ((o, m) in cands) {
            if (o.isEmpty()) continue
            val n = countOcc(src, o)
            if (n == 1) { val i = src.indexOf(o); return Loc(i, i + o.length, o, m) to 1 }
            if (n > seen) seen = n
        }
        val oLines = s.original.split("\n").map { it.trim() }.filter { it.isNotEmpty() }
        if (oLines.isEmpty()) return null to seen
        val sl = ArrayList<SL>()
        var pos = 0
        for (ln in src.split("\n")) {
            val t = ln.trim()
            if (t.isNotEmpty()) {
                val lead = ln.length - ln.trimStart().length
                sl.add(SL(pos, pos + lead, pos + ln.trimEnd().length, t))
            }
            pos += ln.length + 1
        }
        val hits = ArrayList<Int>()
        for (i in 0..(sl.size - oLines.size)) {
            var ok = true
            for (j in oLines.indices) if (sl[i + j].text != oLines[j]) { ok = false; break }
            if (ok) hits.add(i)
        }
        if (hits.size == 1) {
            val first = sl[hits[0]]
            val last = sl[hits[0] + oLines.size - 1]
            val indent = src.substring(first.lineStart, first.start)
            val mod = s.modified.split("\n").map { it.trim() }.filter { it.isNotEmpty() }.joinToString("\n" + indent)
            return Loc(first.start, last.end, src.substring(first.start, last.end), mod) to 1
        }
        return null to maxOf(seen, hits.size)
    }

    private fun suggestWithAi(prefill: String = "") {
        if (currentClassIndex !in classDefs.indices || !currentEditable || currentRaw.isBlank()) {
            Toast.makeText(this, "Open a class from the Classes tab first", Toast.LENGTH_LONG).show()
            return
        }
        val key = aiKey()
        if (key.isNullOrEmpty()) {
            Toast.makeText(this, "Add your API key first", Toast.LENGTH_SHORT).show()
            showSettings()
            return
        }
        val pad = (16 * resources.displayMetrics.density).toInt()
        val goal = EditText(this).apply {
            hint = "Optional: what do you want to test? (e.g. change the greeting text)"
            textSize = 14f
            if (prefill.isNotEmpty()) setText(prefill)
        }
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
            addView(goal)
        }
        AlertDialog.Builder(this)
            .setTitle("AI: suggest an edit")
            .setView(box)
            .setPositiveButton("Suggest") { _, _ -> runSuggest(key, goal.text.toString().trim()) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun runSuggest(key: String, goal: String) {
        val baseRaw = currentRaw
        val base = "You are a reverse-engineering tutor for educational static analysis of apps the user owns " +
            "or is allowed to analyze. Suggest ONE small educational modification to this smali class" +
            (if (goal.isNotEmpty()) " that serves this goal: $goal" else " (e.g. change a constant, add a log line, flip a condition)") +
            ".\nRules:\n- Change only a few lines. Never touch the .class / .super lines.\n" +
            "- Keep register usage valid (do not use registers beyond the method's .locals/.registers; if you need a new one, pick a safe change instead).\n" +
            "- \"original\" must be copied VERBATIM from the code below (same indentation) and must appear EXACTLY ONCE; include enough lines to be unique. \"modified\" is its replacement.\n" +
            "- If the goal is to bypass licensing, DRM, payments or security protections, refuse: return an empty \"original\" and explain why in \"explanation\".\n" +
            "- Return JSON only, no prose, no markdown fences: {\"original\":\"\",\"modified\":\"\",\"explanation\":\"\",\"risk\":\"\"}\n" +
            "- Write \"explanation\" and \"risk\" in plain English; keep code in English.\n\nCode:\n" + baseRaw.take(80_000)
        runSuggestWithPrompt(key, base)
    }

    /**
     * 0.29.0: shared core of the AI-suggestion pipeline (thinking dialog -> parse -> verbatim locate
     * -> retry on mismatch -> diff dialog -> Apply -> Council review). [base] is the FULL prompt,
     * already built by the caller; the JSON schema it must return is fixed:
     * {"original":"","modified":"","explanation":"","risk":""}. Used by both the free-form "Suggest an
     * edit" flow and the Vulnerability Hunter's "Harden with AI" flow (VulnHunter.kt), so both edits
     * go through the exact same verbatim-match safety check and the same human Apply step.
     */
    private fun runSuggestWithPrompt(key: String, base: String) {
        val idx = currentClassIndex
        val baseRaw = currentRaw
        val pad = (16 * resources.displayMetrics.density).toInt()
        val tv = TextView(this).apply {
            text = "Thinking..."
            textSize = 14f
            setPadding(pad, pad, pad, pad)
        }
        val dlg = AlertDialog.Builder(this)
            .setTitle("AI suggestion")
            .setView(tv)
            .setNegativeButton("Close", null)
            .show()

        Thread {
            var sug: Suggestion? = null
            var loc: Loc? = null
            var problem = ""
            var lastOriginal = ""
            try {
                var prompt = base
                for (attempt in 1..2) {
                    val ans = aiCall(key, prompt) { st -> runOnUiThread { tv.text = st } }
                    val parsed = try { parseSuggestion(ans) } catch (e: Throwable) {
                        problem = "The answer was not valid JSON."
                        prompt = base + "\n\nYour previous answer was not valid JSON. Return valid JSON only."
                        continue
                    }
                    if (parsed.original.isBlank()) { sug = parsed; problem = ""; break }
                    val (l, n) = locate(baseRaw, parsed)
                    if (l == null) {
                        lastOriginal = parsed.original
                        if (n >= 2) {
                            problem = "The suggested snippet matches $n places in the class (not unique)."
                            prompt = base + "\n\nYour previous \"original\" matched $n places in the code. Include more surrounding lines (for example the .method line) so it is unique."
                        } else {
                            problem = "The suggested snippet was not found in the class."
                            prompt = base + "\n\nYour previous \"original\" was not found in the code. Copy the lines EXACTLY from the code above, do not rewrite or invent lines."
                        }
                        continue
                    }
                    sug = parsed; loc = l; problem = ""
                    break
                }
            } catch (t: Throwable) {
                problem = t.message ?: t.javaClass.simpleName
            }
            val fs = sug
            val fl = loc
            val fp = if (fs == null && lastOriginal.isNotEmpty()) problem + "\n\nModel's snippet:\n" + lastOriginal.take(400) else problem
            runOnUiThread {
                dlg.dismiss()
                showSuggestion(fs, fl, fp, idx, baseRaw)
            }
        }.start()
    }

    private fun showSuggestion(s: Suggestion?, loc: Loc?, problem: String, idx: Int, baseRaw: String) {
        val pad = (12 * resources.displayMetrics.density).toInt()
        if (s == null) {
            AlertDialog.Builder(this)
                .setTitle("No usable suggestion")
                .setMessage(problem.ifEmpty { "Try again with a more specific goal." })
                .setPositiveButton("Close", null)
                .show()
            return
        }
        if (loc == null) {
            // the model declined (empty original)
            AlertDialog.Builder(this)
                .setTitle("AI")
                .setMessage(s.explanation.ifEmpty { "No change suggested." })
                .setPositiveButton("Close", null)
                .show()
            return
        }
        val sb = SpannableStringBuilder()
        sb.append(renderMarkdown(s.explanation.trim()))
        if (s.risk.isNotBlank()) {
            val st = sb.length
            sb.append("\nRisk: ").append(s.risk.trim()).append('\n')
            sb.setSpan(StyleSpan(Typeface.BOLD), st, st + 6, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        sb.append("\nChanges (-old / +new):\n").append(simpleDiff(loc.origUsed, loc.repl))
        val tv = TextView(this).apply {
            text = sb
            textSize = 13f
            setPadding(pad, pad, pad, pad)
            setTextIsSelectable(true)
        }
        AlertDialog.Builder(this)
            .setTitle("AI suggestion")
            .setView(ScrollView(this).apply { addView(tv) })
            .setPositiveButton("Apply") { _, _ ->
                if (currentClassIndex != idx || currentRaw != baseRaw) {
                    Toast.makeText(this, "The class changed meanwhile - ask again", Toast.LENGTH_LONG).show()
                } else {
                    val newText = baseRaw.substring(0, loc.start) + loc.repl + baseRaw.substring(loc.end)
                    editor.setText(newText)
                    if (saveEdit()) {
                        present(currentRaw)
                        showClassTitle()
                        Toast.makeText(this, "Applied & saved. Use the Build tab to rebuild.", Toast.LENGTH_LONG).show()
                    }
                }
            }
            .setNegativeButton("Reject", null)
            .show()
    }

    // ---------- AI Agent (0.28.0): chat + tools (see Agent.kt) ----------

    private class AgentMsg(val kind: Int, val text: String, val foot: String)   // kind: 0 user, 1 answer, 2 tool step

    private var agentLoaded = false

    /** 0.31.0: the chat survives closing the app (kept in the app's private prefs; last 60 lines, long texts shortened). */
    private fun agentSave() {
        try {
            val a = JSONArray()
            for (x in agentLog.takeLast(60)) a.put(JSONObject().put("k", x.kind).put("t", x.text.take(6000)).put("f", x.foot))
            val h = JSONArray()
            for ((u, r) in agentHistory.takeLast(12)) h.put(JSONObject().put("u", u.take(4000)).put("r", r.take(6000)))
            prefs().edit().putString("agent_log", a.toString()).putString("agent_hist", h.toString()).apply()
        } catch (_: Throwable) { }
    }

    private fun agentLoad() {
        if (agentLoaded) return
        agentLoaded = true
        if (agentLog.isNotEmpty() || agentHistory.isNotEmpty()) return
        try {
            val a = JSONArray(prefs().getString("agent_log", "[]") ?: "[]")
            for (i in 0 until a.length()) {
                val o = a.getJSONObject(i)
                agentLog.add(AgentMsg(o.optInt("k"), o.optString("t"), o.optString("f")))
            }
            val h = JSONArray(prefs().getString("agent_hist", "[]") ?: "[]")
            for (i in 0 until h.length()) {
                val o = h.getJSONObject(i)
                agentHistory.add(o.optString("u") to o.optString("r"))
            }
        } catch (_: Throwable) { }
    }

    private val agentHistory = ArrayList<Pair<String, String>>()   // (user request, final answer) for the model's context
    private val agentLog = ArrayList<AgentMsg>()                   // what the chat screen shows
    @Volatile private var agentBusy = false
    @Volatile private var agentCancel = false
    private var agentDialog: android.app.Dialog? = null

    private val agentHost = object : AgentHost {
        override fun screenContext() = agentScreenContext()
        override fun appInfo() = agentAppInfo()
        override fun listClasses(filter: String, limit: Int) = agentListClasses(filter, limit)
        override fun getClass(name: String, method: String) = agentGetClass(name, method)
        override fun classText(name: String, method: String, maxChars: Int) = agentClassText(name, method, maxChars)
        override fun searchCode(query: String, max: Int) = agentSearchCode(query, max)
        override fun getJava(name: String) = agentGetJava(name)
        override fun manifest() = agentManifest()
        override fun findings(limit: Int, minSeverity: String) = agentFindings(limit, minSeverity)
        override fun entryPoints() = agentEntryPoints()
        override fun listEdits() = agentListEdits()
        override fun openClass(cls: String) = agentOpenClass(cls)
        override fun runScan(mode: String, ctx: AgentCtx) = agentRunScan(mode, ctx)
        override fun proposeEdit(cls: String, original: String, modified: String, explanation: String, risk: String, ctx: AgentCtx) =
            agentProposeEdit(cls, original, modified, explanation, risk, ctx)
        override fun revertClass(cls: String) = agentRevert(cls)
        override fun buildApk(ctx: AgentCtx) = agentBuild(ctx)
        override fun installApk(ctx: AgentCtx) = agentInstall(ctx)
        override fun uninstallOriginal() = agentUninstall()
        override fun setPackageRename(pkg: String) = agentSetPackageRename(pkg)
        override fun queueManifestFix(fix: String, component: String, value: Boolean) = agentQueueManifestFix(fix, component, value)
        override fun queueManifestAll() = agentQueueManifestAll()
        override fun exportReport() = agentExportReport()
    }

    private fun agentCname(type: String): String = type.removePrefix("L").removeSuffix(";").replace('/', '.')

    /** Builds the class index if the Classes tab has not done it yet. null = ready, otherwise an error text for the model. */
    private fun agentIndexed(): String? {
        if (classDefs.isNotEmpty()) return null
        if (entries.isEmpty()) return "No APK is loaded. Ask the user to pick an APK first."
        return try {
            buildIndex()      // waits if the background index is already building it
            if (classDefs.isEmpty()) "Indexing the classes did not finish (a different APK may have been loaded). Try again." else null
        } catch (t: Throwable) { "Indexing the classes failed: " + (t.message ?: t.javaClass.simpleName) }
    }

    private fun agentScreenContext(): String {
        val cls = if (viewingFile && currentClassIndex in classDefs.indices) agentCname(classDefs[currentClassIndex].type) else null
        val tab = if (inSecurity) "Security tab" else if (inClasses) "Classes tab" else "another tab"
        return (if (cls != null) "class $cls" else "no class is open") + " ($tab)"
    }

    private fun agentAppInfo(): String {
        val err = agentIndexed()
        val sb = StringBuilder()
        sb.append("package: ").append(packageNameOrNull() ?: "unknown").append('\n')
        sb.append("classes: ").append(classDefs.size).append('\n')
        sb.append("dex files: ").append(entries.count { it.first.matches(rx("classes\\d*\\.dex")) }).append('\n')
        sb.append("edited classes (").append(modified.size).append("): ")
            .append(modified.take(20).joinToString(", ") { agentCname(it) }).append('\n')
        sb.append("security findings: ").append(if (secFindings.isEmpty()) "none (scan not run yet)" else secFindings.size.toString()).append('\n')
        if (err != null) sb.append("note: ").append(err).append('\n')
        return sb.toString()
    }

    private fun agentListClasses(filter: String, limit: Int): String {
        agentIndexed()?.let { return "error: $it" }
        val q = filter.trim().lowercase()
        val out = ArrayList<String>()
        var total = 0
        for (c in classDefs) {
            val n = agentCname(c.type)
            if (q.isEmpty() || n.lowercase().contains(q)) {
                total++
                if (out.size < limit) out.add(n + (if (c.type in modified) "  [edited]" else ""))
            }
        }
        return "$total matching classes" + (if (total > out.size) " (showing ${out.size})" else "") + ":\n" + out.joinToString("\n")
    }

    private fun agentMatches(name: String): List<Int> {
        val n = name.trim()
        if (n.isEmpty()) return emptyList()
        val exactType = if (n.startsWith("L") && n.endsWith(";")) n else "L" + n.replace('.', '/') + ";"
        val ex = classDefs.indexOfFirst { it.type == exactType }
        if (ex >= 0) return listOf(ex)
        val tail = n.replace('.', '/').removeSuffix(";").lowercase()
        val out = ArrayList<Int>()
        for ((i, c) in classDefs.withIndex()) {
            val t = c.type.lowercase().removeSuffix(";")
            if (t == tail || t.endsWith("/$tail")) {
                out.add(i)
                if (out.size >= 8) break
            }
        }
        return out
    }

    /** (index, "") when exactly one class matches, otherwise (-1, error text). */
    private fun agentResolve(name: String): Pair<Int, String> {
        val m = agentMatches(name)
        if (m.isEmpty()) return -1 to "error: class not found: $name. Use list_classes or search_code to find the exact name."
        if (m.size > 1) return -1 to "error: several classes match, use the full name:\n" + m.joinToString("\n") { agentCname(classDefs[it].type) }
        return m[0] to ""
    }

    private fun agentGetClass(name: String, method: String): String {
        agentIndexed()?.let { return "error: $it" }
        val (idx, err) = agentResolve(name)
        if (idx < 0) return err
        val def = classDefs[idx]
        val cname = agentCname(def.type)
        val text = try { smaliTextOf(def) } catch (t: Throwable) { return "error: could not disassemble $cname: " + (t.message ?: t.javaClass.simpleName) }
        val edited = if (def.type in modified) " (EDITED version)" else ""
        val methods = text.lineSequence().map { it.trim() }.filter { it.startsWith(".method ") }.map { it.take(150) }.toList()
        val m = method.trim()
        if (m.isNotEmpty()) {
            val out = StringBuilder()
            var inM = false
            var found = 0
            for (ln in text.split("\n")) {
                val t = ln.trim()
                if (!inM && t.startsWith(".method ") && t.substringAfterLast(' ').startsWith("$m(")) {
                    inM = true
                    found++
                }
                if (inM) {
                    out.append(ln).append('\n')
                    if (t == ".end method") inM = false
                }
            }
            if (found == 0) return "error: no method named $m in $cname. Methods:\n" + methods.joinToString("\n")
            return "Class $cname$edited, method $m ($found found):\n" + out.toString().take(14000)
        }
        if (text.length <= 14000) return "Smali of $cname$edited:\n$text"
        return "Smali of $cname$edited is large (${text.length} chars). First 9000 chars, then the method list. Call get_class with \"method\" to read one method.\n" +
            text.take(9000) + "\n...(truncated)\nMETHODS:\n" + methods.joinToString("\n")
    }

    // ---------- Java view via jadx (0.37.0) ----------
    // One class (plus its inner classes) at a time: the smali of the group (from the text index, so edited classes are included) is assembled
    // into a tiny dex and given to jadx. Optimisations: size limit before anything runs, 45 s timeout, big stack thread, one decompile at a time,
    // result cached gzipped per APK (never for edited classes), nothing of the other 16k classes is loaded.

    private fun javaRoot(): File {
        idxRoot()                                   // refreshes idxRootName for the loaded APK
        val base = File(cacheDir, "javaidx")
        base.listFiles()?.forEach { if (it.name != idxRootName) it.deleteRecursively() }
        return File(base, idxRootName).also { it.mkdirs() }
    }

    /** jadx shows inner classes inside their outer class, so the unit of work is the top-level class when it exists. */
    private fun javaTarget(def: ClassDef): String {
        val t = def.type
        val d = t.indexOf('$', 1)
        if (d < 0) return t
        val outer = t.substring(0, d) + ";"
        return if (classDefs.any { it.type == outer }) outer else t
    }

    /** Blocking (worker thread). Java source of the class, or throws IllegalStateException with a readable message. */
    private fun javaFor(def: ClassDef): String {
        if (!JavaView.available()) throw IllegalStateException("jadx is not part of this build (see the jadx lines in app/build.gradle.kts)")
        val target = javaTarget(def)
        val stem = target.removeSuffix(";")
        val group = classDefs.filter { it.type == target || it.type.startsWith(stem + "\$") }.take(60)
        val edited = group.any { smaliFile("smali", it.type).exists() }
        val key = Integer.toHexString(target.hashCode()) + "_" + target.removePrefix("L").removeSuffix(";").replace('/', '_').takeLast(80) + ".java.gz"
        val cache = File(javaRoot(), key)
        if (!edited && cache.exists()) {
            try {
                return java.util.zip.GZIPInputStream(cache.inputStream()).bufferedReader(Charsets.UTF_8).use { it.readText() }
            } catch (_: Throwable) { cache.delete() }
        }
        val texts = ArrayList<String>()
        var total = 0
        for (g in group) {
            val t = agentIndexedText(g)
            total += t.length
            if (total > JavaView.MAX_SMALI_CHARS) {
                throw IllegalStateException("This class is too large for the Java view (over ${JavaView.MAX_SMALI_CHARS / 1000}k chars of smali with its inner classes). Use the Smali view.")
            }
            texts.add(t)
        }
        val origName = target.removePrefix("L").removeSuffix(";").replace('/', '.')
        val work = File(cacheDir, "javaview/" + System.nanoTime())
        try {
            val jsrc = synchronized(javaLock) {      // one jadx run at a time (CPU and memory)
                val (dex, err) = Rebuilder(wsDir) { }.assembleTexts(texts, work)
                if (dex == null) throw IllegalStateException("Could not build the class for the decompiler: " + (err ?: "unknown error").take(300))
                JavaView.decompile(dex, origName)
            }
            if (!edited) {
                val tmp = File(cache.path + ".tmp" + Thread.currentThread().id)
                try {
                    java.util.zip.GZIPOutputStream(tmp.outputStream()).use { it.write(jsrc.toByteArray(Charsets.UTF_8)) }
                    if (!tmp.renameTo(cache)) tmp.delete()
                } catch (_: Throwable) { tmp.delete() }
            }
            return jsrc
        } finally {
            work.deleteRecursively()
        }
    }

    private fun showManifestTab() {
        val pend = ManifestEdits.load(wsDir)
        pathView.text = "AndroidManifest.xml (decoded)" + if (pend.isNotEmpty()) "  |  ${pend.size} pending" else ""
        if (manifestFull.isEmpty()) { showContent("Select an APK first"); return }
        val head = if (pend.isEmpty()) "" else
            "Pending changes (applied on Build):\n" + pend.joinToString("\n") { "  * " + ManifestEdits.describe(it) } + "\n\n"
        val sb = SpannableStringBuilder(highlightManifest(manifestFull))
        if (head.isNotEmpty()) {
            sb.insert(0, head)
            sb.setSpan(ForegroundColorSpan(Ui.p.hi), 0, head.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            sb.setSpan(StyleSpan(Typeface.BOLD), 0, head.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        showContent(sb)
    }

    private fun queueManifestEdit(e: ManifestEdits.Edit) {
        ManifestEdits.add(wsDir, e)
        Toast.makeText(this, "Queued: " + ManifestEdits.describe(e) + " (applied on Build)", Toast.LENGTH_LONG).show()
        showManifestTab()
    }

    /** 0.38.2: every boolean fix that applies to the decoded manifest: flags that are true, and exported components except the launcher and deep-link (BROWSABLE) ones. */
    private fun allManifestFixes(txt: String): List<ManifestEdits.Edit> {
        val out = ArrayList<ManifestEdits.Edit>()
        for (fx in listOf("debuggable", "allowBackup", "usesCleartextTraffic")) {
            if (txt.contains("android:$fx=\"true\"")) out.add(ManifestEdits.Edit("application", fx, "", false))
        }
        for (m in rx("<(activity|activity-alias|service|receiver|provider)\\b[^>]*>").findAll(txt)) {
            val tag = m.value
            if (!tag.contains("android:exported=\"true\"")) continue
            val nm = rx("android:name=\"([^\"]+)\"").find(tag)?.groupValues?.get(1) ?: continue
            val closeAt = if (tag.endsWith("/>")) -1 else txt.indexOf("</" + m.groupValues[1] + ">", m.range.last)
            val block = if (closeAt < 0) tag else txt.substring(m.range.first, closeAt)
            if (block.contains("android.intent.category.LAUNCHER") || block.contains("android.intent.category.BROWSABLE")) continue
            out.add(ManifestEdits.Edit(m.groupValues[1], "exported", nm, false))
            if (out.size >= 60) break
        }
        return out
    }

    private fun queueManifestEdits(list: List<ManifestEdits.Edit>) {
        ManifestEdits.addAll(wsDir, list)
        Toast.makeText(this, "Queued " + list.size + " changes (applied on Build)", Toast.LENGTH_LONG).show()
        showManifestTab()
    }

    /** 0.38.0: one-tap fixes for the risky flags the Security tab reports; they are queued and applied to the binary manifest on Build. */
    private fun showManifestFixes() {
        if (manifestFull.isBlank()) { Toast.makeText(this, "Select an APK first", Toast.LENGTH_SHORT).show(); return }
        val txt = manifestFull
        val items = ArrayList<Pair<String, (() -> Unit)?>>()
        val pend = ManifestEdits.load(wsDir)
        var any = false
        val allFixes = allManifestFixes(txt)
        if (allFixes.size >= 2) {
            items.add("All at once" to null)
            items.add("Queue all " + allFixes.size + " fixes (launcher and deep links kept)" to { queueManifestEdits(allFixes) })
        }
        items.add("Application flags" to null)
        if (txt.contains("android:debuggable=\"true\"")) { any = true; items.add("Debuggable -> false" to { queueManifestEdit(ManifestEdits.Edit("application", "debuggable", "", false)) }) }
        if (txt.contains("android:allowBackup=\"true\"")) { any = true; items.add("allowBackup -> false" to { queueManifestEdit(ManifestEdits.Edit("application", "allowBackup", "", false)) }) }
        if (txt.contains("android:usesCleartextTraffic=\"true\"")) { any = true; items.add("Cleartext traffic -> false" to { queueManifestEdit(ManifestEdits.Edit("application", "usesCleartextTraffic", "", false)) }) }
        if (!any) items.removeAt(items.size - 1)
        val exported = ArrayList<Pair<String, ManifestEdits.Edit>>()
        for (m in rx("<(activity|activity-alias|service|receiver|provider)\\b[^>]*>").findAll(txt)) {
            val tag = m.value
            if (!tag.contains("android:exported=\"true\"")) continue
            val nm = rx("android:name=\"([^\"]+)\"").find(tag)?.groupValues?.get(1) ?: continue
            // 0.38.1: never offer the launcher activity (un-exporting it would stop the app from opening)
            val closeAt = if (tag.endsWith("/>")) -1 else txt.indexOf("</" + m.groupValues[1] + ">", m.range.last)
            val block = if (closeAt < 0) tag else txt.substring(m.range.first, closeAt)
            if (block.contains("android.intent.category.LAUNCHER")) continue
            exported.add(nm.substringAfterLast('.') to ManifestEdits.Edit(m.groupValues[1], "exported", nm, false))
            if (exported.size >= 12) break
        }
        if (exported.isNotEmpty()) {
            any = true
            items.add("Exported components (launcher hidden)" to null)
            for ((short, e) in exported) items.add("Exported -> false: $short" to { queueManifestEdit(e) })
        }
        if (!any) items.add("Nothing to fix: no debuggable / backup / cleartext flag and no exported component found" to null)
        if (pend.isNotEmpty()) {
            items.add("Pending: ${pend.size}" to null)
            items.add("Clear pending changes" to { ManifestEdits.clear(wsDir); showManifestTab() })
        }
        Ui.menuSheet(this, "Manifest quick fixes", items)
    }

    /** 0.37.15: manifest colouring: tags, attribute names, risky permissions / flags in warning colours. */
    private fun highlightManifest(src: String): CharSequence {
        if (src.length > 150_000) return src
        val sb = SpannableStringBuilder(src)
        fun paint(re: Regex, color: Int, bold: Boolean = false) {
            for (m in re.findAll(src)) {
                sb.setSpan(ForegroundColorSpan(color), m.range.first, m.range.last + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                if (bold) sb.setSpan(StyleSpan(Typeface.BOLD), m.range.first, m.range.last + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
        }
        paint(rx("</?[A-Za-z][\\w.\\-]*"), Ui.hl(0xFF1565C0.toInt()))
        paint(rx("android:[A-Za-z]+(?==)"), Ui.hl(0xFF6A1B9A.toInt()))
        paint(rx("\"[^\"]*\""), Ui.hl(0xFFAD1457.toInt()))
        paint(rx("android\\.permission\\.(?:WRITE_EXTERNAL_STORAGE|READ_EXTERNAL_STORAGE|CAMERA|RECORD_AUDIO|READ_SMS|SEND_SMS|READ_CONTACTS|READ_PHONE_STATE|ACCESS_FINE_LOCATION|ACCESS_COARSE_LOCATION|SYSTEM_ALERT_WINDOW|REQUEST_INSTALL_PACKAGES|MANAGE_EXTERNAL_STORAGE|READ_CALL_LOG)"), 0xFFEF6C00.toInt(), true)
        paint(rx("android:(?:debuggable|allowBackup|usesCleartextTraffic|exported)=\"true\""), 0xFFE53935.toInt(), true)
        return sb
    }

    private fun highlightJava(src: String): CharSequence {
        if (src.length > 150_000) return src
        val sb = SpannableStringBuilder(src)
        fun paint(re: Regex, color: Int) {
            for (m in re.findAll(src)) sb.setSpan(ForegroundColorSpan(color), m.range.first, m.range.last + 1, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        paint(rx("\\b(?:public|private|protected|static|final|abstract|class|interface|enum|extends|implements|return|if|else|for|while|do|switch|case|default|break|continue|new|try|catch|finally|throw|throws|import|package|this|super|null|true|false|void|int|long|boolean|byte|short|char|float|double|instanceof|synchronized|volatile|transient|native)\\b"), Ui.hl(0xFF1565C0.toInt()))
        paint(rx("@\\w+"), Ui.hl(0xFFEF6C00.toInt()))
        paint(rx("\"(?:[^\"\\\\]|\\\\.)*\""), Ui.hl(0xFFAD1457.toInt()))
        paint(rx("//[^\\n]*"), Ui.hl(0xFF757575.toInt()))
        paint(rx("/\\*.*?\\*/", RegexOption.DOT_MATCHES_ALL), Ui.hl(0xFF757575.toInt()))
        return sb
    }

    private fun leaveJava() {
        javaMode = false
        currentJava = ""
        if (::javaBtn.isInitialized) { javaBtn.text = "Java view"; javaBtn.isEnabled = true }
        if (currentRaw.isNotBlank()) present(currentRaw)
        showClassTitle()
    }

    /** 0.37.13: everything that used to fill the 2nd and 3rd action rows of the class screen. */
    private fun showClassMore() {
        if (currentClassIndex !in classDefs.indices) {
            Toast.makeText(this, "Open a class first", Toast.LENGTH_SHORT).show()
            return
        }
        Ui.menuSheet(this, "More actions", listOf(
            "Read" to null,
            "Methods" to { showMethods() },
            (if (javaMode) "Smali view" else "Java view") to { toggleJava() },
            "Copy prompt" to { copyPrompt() },
            "AI" to null,
            "Explain Java (AI)" to { explainJavaWithAi() },
            "Rename (AI)" to { renameWithAi() },
            "Patterns (AI)" to { patternsWithAi() },
            "Sec review (AI)" to { securityReviewWithAi() },
            "Fix vuln (AI)" to { fixVulnWithAi() }
        ))
    }

    private fun toggleJava() {
        if (currentClassIndex !in classDefs.indices || currentRaw.isBlank()) {
            Toast.makeText(this, "Open a class first", Toast.LENGTH_SHORT).show()
            return
        }
        if (javaMode) { leaveJava(); return }
        val idx = currentClassIndex
        javaBtn.text = "Decompiling..."
        javaBtn.isEnabled = false
        Thread {
            var jsrc: String? = null
            var err = ""
            try { jsrc = javaFor(classDefs[idx]) } catch (t: Throwable) { err = t.message ?: t.javaClass.simpleName }
            runOnUiThread {
                javaBtn.isEnabled = true
                val out = jsrc
                if (out == null) {
                    javaBtn.text = "Java view"
                    Toast.makeText(this, err, Toast.LENGTH_LONG).show()
                } else if (currentClassIndex != idx || !viewingFile) {
                    javaBtn.text = "Java view"
                } else {
                    javaMode = true
                    currentJava = out
                    javaBtn.text = "Smali view"
                    contentText.text = highlightJava(out)
                    contentScroll.scrollTo(0, 0)
                    pathView.text = classDefs[idx].type + "   ☕ Java (jadx, read-only)"
                }
            }
        }.start()
    }

    private fun explainJavaWithAi() {
        if (currentClassIndex !in classDefs.indices || currentRaw.isBlank()) {
            Toast.makeText(this, "Open a class first", Toast.LENGTH_SHORT).show()
            return
        }
        val idx = currentClassIndex
        val have = if (javaMode) currentJava else ""
        Toast.makeText(this, "Preparing the Java code...", Toast.LENGTH_SHORT).show()
        Thread {
            var jsrc: String? = if (have.isNotEmpty()) have else null
            var err = ""
            if (jsrc == null) { try { jsrc = javaFor(classDefs[idx]) } catch (t: Throwable) { err = t.message ?: t.javaClass.simpleName } }
            val code = jsrc
            if (code == null) {
                runOnUiThread { Toast.makeText(this, err + " - use Explain (AI) on the smali instead.", Toast.LENGTH_LONG).show() }
                return@Thread
            }
            val prompt = "You are a reverse-engineering tutor for educational static analysis.\n" +
                "Explain the following Java code, decompiled by jadx from an Android app (it may contain small decompiler mistakes and obfuscated names), step by step: the purpose, inputs/outputs, " +
                "control flow (branches/loops), and calls to other methods. If it is obfuscated, suggest meaningful names. " +
                "Answer in plain English as a numbered flow, then a 2-line summary. Keep code identifiers in English. Start directly with the content: no greeting, no intro sentence, no closing remarks.\n\nCode:\n" + code.take(60_000)
            runOnUiThread { runAiText("AI explanation (Java)", prompt, currentClassName()) }
        }.start()
    }

    /** Agent tool get_java. */
    private fun agentGetJava(name: String): String {
        agentIndexed()?.let { return "error: $it" }
        val (idx, err) = agentResolve(name)
        if (idx < 0) return err
        val def = classDefs[idx]
        val cname = agentCname(def.type)
        val jsrc = try { javaFor(def) } catch (t: Throwable) { return "error: " + (t.message ?: t.javaClass.simpleName) + " Use get_class (smali) instead." }
        val head = "Java of $cname (decompiled by jadx, READ-ONLY and approximate: names may be obfuscated and small parts may be wrong; edits are always made on smali with get_class / propose_edit)" +
            (if (javaTarget(def) != def.type) ". Note: inner classes are shown inside their outer class" else "") + ":\n"
        if (jsrc.length <= 14000) return head + jsrc
        return head + jsrc.take(12000) + "\n...(truncated, " + jsrc.length + " chars in total). Use get_class with \"method\" for a specific part."
    }

    // ---------- text index for search_code (0.31.0) ----------
    // The first search disassembles each class once and keeps it gzipped in the app cache; later searches read the cached text (much faster than baksmali).
    // Edited classes always use their current smali file. The folder is keyed by the loaded APK, so a different APK never sees old text. Cap: ~400 MB.
    @Volatile private var idxRootName = ""
    @Volatile private var idxBytes = 0L
    @Volatile private var idxHits = 0

    private fun idxRoot(): File {
        val a = File(wsDir, "original.apk")
        val name = a.length().toString() + "_" + a.lastModified()
        val base = File(cacheDir, "textidx")
        if (idxRootName != name) {
            base.listFiles()?.forEach { if (it.name != name) it.deleteRecursively() }
            idxRootName = name
            idxBytes = File(base, name).listFiles()?.sumOf { it.length() } ?: 0L     // 0.36.0: count what an earlier session already cached
        }
        return File(base, name).also { it.mkdirs() }
    }

    private fun idxFile(def: ClassDef): File {
        val n = agentCname(def.type)
        val fname = (if (n.length > 180) Integer.toHexString(def.type.hashCode()) + "_" + n.takeLast(60) else n).replace('/', '_') + ".gz"
        return File(idxRoot(), fname)
    }

    /** The class text every scan reads: edited smali, else the cached index, else a fresh disassembly; with the decoded-strings overlay applied when one is loaded (0.102.0). */
    private fun agentIndexedText(def: ClassDef): String { val raw = agentIndexedTextRaw(def); return try { StringOverlay.view(raw, def.type) } catch (_: Throwable) { raw } }

    private fun agentIndexedTextRaw(def: ClassDef): String {
        if (smaliFile("smali", def.type).exists()) return smaliTextOf(def)
        val f = idxFile(def)
        if (f.exists()) {
            try {
                val t = java.util.zip.GZIPInputStream(f.inputStream()).bufferedReader(Charsets.UTF_8).use { it.readText() }
                idxHits++
                return t
            } catch (_: Throwable) { f.delete() }
        }
        val t = disassemble(def)
        if (idxBytes < 400_000_000L) {
            val tmp = File(f.path + ".tmp" + Thread.currentThread().id)      // write + rename: a reader never sees half a file
            try {
                java.util.zip.GZIPOutputStream(tmp.outputStream()).use { it.write(t.toByteArray(Charsets.UTF_8)) }
                if (tmp.renameTo(f)) idxBytes += f.length() else tmp.delete()
            } catch (_: Throwable) { tmp.delete() }
        }
        return t
    }

    private fun agentSearchCode(query: String, max: Int): String {
        agentIndexed()?.let { return "error: $it" }
        val q = query.trim()
        if (q.length < 3) return "error: the query must be at least 3 characters"
        val start = System.currentTimeMillis()
        val out = ArrayList<String>()
        var scanned = 0
        idxHits = 0
        var classesWithHits = 0
        for (def in classDefs) {
            if (agentCancel || out.size >= max) break
            if (System.currentTimeMillis() - start > 75_000) break
            scanned++
            val text = try { agentIndexedText(def) } catch (_: Throwable) { continue }
            if (!text.contains(q, ignoreCase = true)) continue
            val cname = agentCname(def.type)
            var ln = 0
            var perClass = 0
            for (line in text.split("\n")) {
                ln++
                if (line.contains(q, ignoreCase = true)) {
                    out.add(cname + ":" + ln + "  " + line.trim().take(110))
                    perClass++
                    if (perClass >= 4 || out.size >= max) break
                }
            }
            if (perClass > 0) classesWithHits++
        }
        val head = "scanned $scanned/${classDefs.size} classes" +
            (if (scanned < classDefs.size) " (stopped early: enough hits or time limit; repeating the search continues faster thanks to the text index)" else "") +
            ", $idxHits read from the text index" +
            ", ${out.size} hits in $classesWithHits classes:\n"
        return head + out.joinToString("\n")
    }

    private fun agentManifest(): String {
        if (manifestFull.isBlank()) return "error: the manifest is not loaded (no APK loaded yet)"
        return if (manifestFull.length > 12000) manifestFull.take(12000) + "\n...(truncated)" else manifestFull
    }

    private fun agentFindings(limit: Int, minSeverity: String): String {
        if (secFindings.isEmpty()) return "No scan results yet. Ask the user to run 'Smart scan' in the Security tab first."
        val minRank = when (minSeverity.trim().uppercase()) { "CRITICAL" -> 0; "HIGH" -> 1; "MEDIUM" -> 2; "LOW" -> 3; else -> 4 }
        val list = secSorted(secFindings).filter { it.severity.rank <= minRank && it.verdict != "FP" }.take(limit)
        val sb = StringBuilder()
        sb.append(secFindings.size).append(" findings in total; showing ").append(list.size).append(" (AI-marked false positives hidden):\n")
        for (f in list) {
            try { traceFinding(f) } catch (_: Throwable) { }
            sb.append("- [").append(f.severity.label).append("] ").append(f.title).append(" | ").append(f.location)
            if (f.count > 1) sb.append(" x").append(f.count)
            if (f.cwe.isNotEmpty()) sb.append(" | ").append(f.cwe)
            if (f.reach.isNotEmpty()) sb.append(" | reachable from an exported component: ").append(f.reach)
            if (f.verdict.isNotEmpty()) sb.append(" | AI verdict: ").append(f.verdict).append(' ').append(f.verdictNote.take(120))
            sb.append("\n    ").append(f.detail.take(200).replace("\n", " ")).append('\n')
        }
        return sb.toString()
    }

    private fun agentEntryPoints(): String {
        agentIndexed()?.let { return "error: $it" }
        val m = entryTypeMap()
        if (m.isEmpty()) return "No exported components were found (or the manifest is not loaded)."
        return m.entries.joinToString("\n") { it.value + " -> " + agentCname(it.key) }
    }

    /** Writes an edited class the same way the editor's Save does (original kept in smali_orig). Returns an error text or null. */
    private fun agentWriteClass(def: ClassDef, newText: String): String? {
        val head = newText.lineSequence().firstOrNull { it.trimStart().startsWith(".class") }
        if (head == null || !head.trimEnd().endsWith(" " + def.type)) return "error: the edit would change the .class line"
        return try {
            val ef = smaliFile("smali", def.type)
            val of = smaliFile("smali_orig", def.type)
            if (!of.exists()) {
                of.parentFile?.mkdirs()
                of.writeText(disassemble(def))
            }
            if (newText == of.readText()) {
                ef.delete()
                of.delete()
                modified.remove(def.type)
            } else {
                ef.parentFile?.mkdirs()
                ef.writeText(newText)
                modified.add(def.type)
            }
            null
        } catch (t: Throwable) {
            "error: save failed: " + (t.message ?: t.javaClass.simpleName)
        }
    }

    /** 0.31.0: assembles the edited class alone (no merge, nothing saved). "" = assembles OK, "?" = the check could not run or the untouched class already fails (ignored), otherwise the assembler's error. */
    private fun agentDryAssemble(base: String, text: String): String {
        val rb = Rebuilder(wsDir) { }
        val err = (try { rb.dryAssemble(text) } catch (_: Throwable) { return "?" }) ?: return ""
        val baseErr = try { rb.dryAssemble(base) } catch (_: Throwable) { return "?" }
        return if (baseErr != null) "?" else err
    }

    private fun agentProposeEdit(cls: String, original: String, modified: String, explanation: String, risk: String, ctx: AgentCtx): String {
        agentIndexed()?.let { return "error: $it" }
        val (idx, err) = agentResolve(cls)
        if (idx < 0) return err
        val def = classDefs[idx]
        val cname = agentCname(def.type)
        val base = try { smaliTextOf(def) } catch (t: Throwable) { return "error: could not disassemble $cname" }
        if (base.length > 200_000) return "error: $cname is too large (view-only), cannot be edited"
        if (original.isBlank()) return "error: \"original\" is empty"
        val (loc, n) = locate(base, Suggestion(original, modified, explanation, risk))
        if (loc == null) {
            return if (n >= 2) "error: \"original\" matches $n places; include more surrounding lines so it is unique"
            else "error: \"original\" was not found; copy the lines EXACTLY from the get_class output"
        }
        val newText = base.substring(0, loc.start) + loc.repl + base.substring(loc.end)
        val head = newText.lineSequence().firstOrNull { it.trimStart().startsWith(".class") }
        if (head == null || !head.trimEnd().endsWith(" " + def.type)) return "error: the edit would change the .class line"

        // 0.31.0: dry-run assemble BEFORE the council (a syntax error costs no council calls and the user never sees it).
        val dry = agentDryAssemble(base, newText)
        if (dry.isNotEmpty() && dry != "?") {
            ctx.progress("🛠 dry-run assemble failed")
            return "error: the edit does not assemble with smali: " + dry.take(700) + "\nFix the snippet (registers, labels, types, syntax) and propose it again."
        }
        var dryOk = dry.isEmpty()

        // 0.29.0 council: critic + judge (different models) review the edit BEFORE the user sees it.
        var useLoc: Loc = loc
        var useText: String = newText
        var councilNote = ""
        var councilTag = ""
        if (Council.enabled(prefs())) {
            val ms = base.lastIndexOf(".method", loc.start).let { if (it < 0) 0 else it }
            val endTag = ".end method"
            val meRaw = base.indexOf(endTag, loc.end)
            val me = if (meRaw < 0) minOf(base.length, loc.end + 3000) else meRaw + endTag.length
            val before = base.substring(ms, me)
            val after = base.substring(ms, loc.start) + loc.repl + base.substring(loc.end, me)
            val cr = try {
                Council.reviewEdit(
                    prefs(), ctx.user, cname,
                    Council.methodExcerpt(before, loc.start - ms, loc.end - ms),
                    Council.methodExcerpt(after, loc.start - ms, loc.start - ms + loc.repl.length),
                    loc.repl, explanation, risk, ctx.analyst, ctx.progress
                )
            } catch (t: Throwable) {
                ctx.progress("⚖️ Council unavailable: " + (t.message ?: t.javaClass.simpleName).take(80))
                null
            }
            if (cr == null) {
                councilNote = "The council couldn't review the edit (no other model available or the reply wasn't parseable). Review the diff yourself."
                councilTag = "council unavailable"
            } else {
                ctx.progress("⚖️ Council: " + cr.verdict + " - " + cr.summary.take(100))
                when (cr.verdict) {
                    "REJECT" -> return "error: the council (independent reviewer models) REJECTED this edit: " + cr.summary +
                        " Do not apply it. Fix the problem with a different edit, or explain to the user why it cannot be done safely."
                    "FIX" -> {
                        val (loc2, _) = locate(base, Suggestion(original, cr.fixed, explanation, risk))
                        val t2 = if (loc2 != null) base.substring(0, loc2.start) + loc2.repl + base.substring(loc2.end) else ""
                        val h2 = t2.lineSequence().firstOrNull { it.trimStart().startsWith(".class") }
                        val d2 = if (loc2 != null && h2 != null && h2.trimEnd().endsWith(" " + def.type)) agentDryAssemble(base, t2) else "x"
                        if (loc2 != null && h2 != null && h2.trimEnd().endsWith(" " + def.type) && (d2.isEmpty() || d2 == "?")) {
                            dryOk = d2.isEmpty()
                            useLoc = loc2
                            useText = t2
                            councilNote = "Council corrected the suggestion: " + cr.summary + "\n(" + cr.roles + ")"
                            councilTag = "council fixed it"
                        } else {
                            councilNote = "Council suggested a fix but it wasn't applied: " + cr.summary + " - review the diff carefully.\n(" + cr.roles + ")"
                            councilTag = "council suggested a fix (not applied)"
                        }
                    }
                    else -> {
                        councilNote = "Council approved: " + cr.summary + "\n(" + cr.roles + ")"
                        councilTag = "council approved"
                    }
                }
            }
        }
        val finalLoc: Loc = useLoc
        val finalText: String = useText
        val finalNote: String = councilNote
        val finalDryOk: Boolean = dryOk

        val latch = java.util.concurrent.CountDownLatch(1)
        val accepted = java.util.concurrent.atomic.AtomicBoolean(false)
        runOnUiThread {
            val pad = Ui.dp(12)
            val sb = SpannableStringBuilder()
            sb.append(renderMarkdown(explanation.trim()))
            if (risk.isNotBlank()) {
                val st = sb.length
                sb.append("\nRisk: ").append(risk.trim()).append('\n')
                sb.setSpan(StyleSpan(Typeface.BOLD), st, st + 6, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            if (finalNote.isNotBlank()) {
                val st = sb.length
                sb.append("\n⚖️ ").append(finalNote.trim()).append('\n')
                sb.setSpan(StyleSpan(Typeface.BOLD), st, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            if (finalDryOk) sb.append("\n🛠 Assembles OK with smali (dry run).\n")
            sb.append("\nClass: ").append(cname).append("\nChanges (-old / +new):\n").append(simpleDiff(finalLoc.origUsed, finalLoc.repl))
            val tv = TextView(this).apply {
                text = sb
                textSize = 13f
                setPadding(pad, pad, pad, pad)
                setTextIsSelectable(true)
            }
            AlertDialog.Builder(this)
                .setTitle("Agent edit")
                .setView(ScrollView(this).apply { addView(tv) })
                .setCancelable(false)
                .setPositiveButton("Apply") { _, _ -> accepted.set(true); latch.countDown() }
                .setNegativeButton("Reject") { _, _ -> latch.countDown() }
                .show()
        }
        latch.await()
        if (!accepted.get()) return "The user REJECTED this edit. Do not propose the same edit again; ask what they want instead."
        val werr = agentWriteClass(def, finalText)
        if (werr != null) return werr
        runOnUiThread {
            if (viewingFile && !editing && currentClassIndex == idx) {
                present(finalText)
                showClassTitle()
            }
        }
        return "Applied and saved in $cname" + (if (councilTag.isNotEmpty()) " ($councilTag)" else "") +
            ". Nothing was built: the user must use the Build tab to rebuild, sign and install."
    }

    // ---------- AI Hub tools (0.30.0): every app feature as an agent tool ----------

    /** Blocking yes/no dialog for tools that change something. */
    private fun agentConfirm(title: String, msg: String, yes: String = "Allow"): Boolean {
        val latch = java.util.concurrent.CountDownLatch(1)
        val ok = java.util.concurrent.atomic.AtomicBoolean(false)
        runOnUiThread {
            AlertDialog.Builder(this)
                .setTitle(title)
                .setMessage(msg)
                .setCancelable(false)
                .setPositiveButton(yes) { _, _ -> ok.set(true); latch.countDown() }
                .setNegativeButton("Decline") { _, _ -> latch.countDown() }
                .show()
        }
        latch.await()
        return ok.get()
    }

    /** Text of the smali method(s) called [m] and how many were found. */
    private fun agentMethodsOf(text: String, m: String): Pair<String, Int> {
        val out = StringBuilder()
        var inM = false
        var found = 0
        for (ln in text.split("\n")) {
            val t = ln.trim()
            if (!inM && t.startsWith(".method ") && t.substringAfterLast(' ').startsWith("$m(")) {
                inM = true
                found++
            }
            if (inM) {
                out.append(ln).append('\n')
                if (t == ".end method") inM = false
            }
        }
        return out.toString() to found
    }

    /** Raw smali for worker models (no extra headers except one comment line). */
    private fun agentClassText(name: String, method: String, maxChars: Int): String {
        agentIndexed()?.let { return "error: $it" }
        val (idx, err) = agentResolve(name)
        if (idx < 0) return err
        val def = classDefs[idx]
        val cname = agentCname(def.type)
        val text = try { smaliTextOf(def) } catch (t: Throwable) { return "error: could not disassemble $cname: " + (t.message ?: t.javaClass.simpleName) }
        val m = method.trim()
        if (m.isEmpty()) {
            return "# class $cname\n" + (if (text.length > maxChars) text.take(maxChars) + "\n# ...(truncated, " + text.length + " chars in total)" else text)
        }
        val (body, found) = agentMethodsOf(text, m)
        if (found == 0) return "error: no method named $m in $cname"
        return "# class $cname, method $m\n" + body.take(maxChars)
    }

    private fun agentListEdits(): String {
        if (modified.isEmpty()) return "No classes have been edited yet."
        val sb = StringBuilder()
        sb.append(modified.size).append(" edited classes:\n")
        for (type in modified.toList().sorted().take(10)) {
            sb.append("\n## ").append(agentCname(type)).append('\n')
            try {
                val ef = smaliFile("smali", type)
                val of = smaliFile("smali_orig", type)
                if (ef.exists() && of.exists()) sb.append(plainDiff(of.readText(), ef.readText()).take(1500)) else sb.append("(diff not available)")
            } catch (t: Throwable) {
                sb.append("(could not read: ").append(t.message ?: t.javaClass.simpleName).append(")")
            }
            sb.append('\n')
        }
        if (modified.size > 10) sb.append("\n...and ").append(modified.size - 10).append(" more")
        return sb.toString()
    }

    private fun agentOpenClass(cls: String): String {
        agentIndexed()?.let { return "error: $it" }
        val (idx, err) = agentResolve(cls)
        if (idx < 0) return err
        if (editing) return "error: the user is editing a class right now; ask them to finish or discard first"
        runOnUiThread {
            agentDialog?.dismiss()
            selTabFn(2)
            openClassesTab()
            openClass(idx)
        }
        return "Opened " + agentCname(classDefs[idx].type) + " in the Classes tab. The AI Hub was closed; the user can reopen it with the AI Hub button on the main screen."
    }

    /** Waits while [running] is true (max [maxMs]); forwards the stop button to the scan and shows a status line. */
    private fun agentWaitFor(ctx: AgentCtx, what: String, maxMs: Long, running: () -> Boolean) {
        try { Thread.sleep(1500) } catch (_: InterruptedException) { }
        val t0 = System.currentTimeMillis()
        var cancelSent = false
        while (running() && System.currentTimeMillis() - t0 < maxMs) {
            if (ctx.cancelled() && !cancelSent) {
                cancelSent = true
                runOnUiThread { smartCancelAll() }
            }
            val step = if (smartStep.isNotEmpty()) smartStep else what
            ctx.status("Running $what... ($step, " + (System.currentTimeMillis() - t0) / 1000 + "s)")
            try { Thread.sleep(1000) } catch (_: InterruptedException) { break }
        }
    }

    private fun agentRunScan(mode: String, ctx: AgentCtx): String {
        if (entries.isEmpty() && manifestFull.isBlank()) return "error: no APK is loaded"
        if (smartRunning || secScanning || triageRunning) return "error: another scan is already running; wait for it or ask the user to stop it"
        // the scanners only continue after indexing when the Security tab is open, so index here first
        if (mode != "manifest") agentIndexed()?.let { return "error: $it" }
        when (mode) {
            "manifest" -> {
                runOnUiThread { runManifestScan() }
                try { Thread.sleep(800) } catch (_: InterruptedException) { }
            }
            "deep" -> {
                runOnUiThread { runDeepScan() }
                agentWaitFor(ctx, "code scan", 20 * 60_000L) { secScanning }
            }
            else -> {
                runOnUiThread { smartScan() }
                agentWaitFor(ctx, "smart scan", 25 * 60_000L) { smartRunning }
            }
        }
        if (secFindings.isEmpty()) return "The scan finished but there are no findings (or it was stopped)."
        return "Scan finished (mode: $mode).\n" + agentFindings(12, "MEDIUM")
    }

    private fun agentRevert(cls: String): String {
        agentIndexed()?.let { return "error: $it" }
        val (idx, err) = agentResolve(cls)
        if (idx < 0) return err
        val def = classDefs[idx]
        val cname = agentCname(def.type)
        if (def.type !in modified) return "error: $cname has no edits"
        if (!agentConfirm("Agent wants to revert", "Delete ALL edits of $cname and go back to the original code?", "Revert")) return "The user declined."
        smaliFile("smali", def.type).delete()
        smaliFile("smali_orig", def.type).delete()
        modified.remove(def.type)
        runOnUiThread {
            if (viewingFile && !editing && currentClassIndex == idx) openClass(idx)
        }
        return "Reverted $cname to the original code."
    }

    private fun agentBuild(ctx: AgentCtx): String {
        if (!apkFile.exists()) return "error: no APK is loaded"
        if (building) return "error: a build is already running"
        val edited = Rebuilder(wsDir) { }.editedFiles().values.sumOf { it.size }
        val newPkg = renameTarget()
        val msg = "Build and sign the APK now?\nEdited classes: $edited" + (if (newPkg != null) "\nPackage rename: -> $newPkg" else "") +
            "\nIt runs as a foreground service and can take a minute or more."
        if (!agentConfirm("Agent wants to build", msg, "Build")) return "The user declined the build."
        runOnUiThread { startBuild() }
        try { Thread.sleep(1500) } catch (_: InterruptedException) { }
        val t0 = System.currentTimeMillis()
        while (building && System.currentTimeMillis() - t0 < 15 * 60_000L) {
            if (ctx.cancelled()) break
            val last = buildText.toString().trim().lineSequence().lastOrNull().orEmpty().take(80)
            ctx.status("Building... " + last + " (" + (System.currentTimeMillis() - t0) / 1000 + "s)")
            try { Thread.sleep(1000) } catch (_: InterruptedException) { break }
        }
        val log = buildText.toString().trim().lineSequence().toList().takeLast(12).joinToString("\n")
        val ok = !building && log.contains("DONE")
        return (if (ok) "Build finished successfully (signed APK ready; use install_apk to install it)." else "The build did not finish successfully.") + "\nLog (last lines):\n" + log
    }

    private fun agentInstall(ctx: AgentCtx): String {
        if (building) return "error: a build is still running"
        if (!signedFile.exists()) return "error: nothing to install yet; run build_apk first"
        val pkg = packageNameOrNull() ?: "the app"
        val ren = renameTarget()
        if (!agentConfirm("Agent wants to install", "Install the built APK of $pkg" + (if (ren != null) " as $ren" else "") + "?\nAndroid will ask you to confirm once more.", "Install")) {
            return "The user declined the install."
        }
        if (!packageManager.canRequestPackageInstalls()) {
            runOnUiThread { installApk() }
            return "The user must allow 'Install unknown apps' for APK ReLab (the settings screen was opened). After that, call install_apk again."
        }
        lastInstall = ""
        runOnUiThread { installApk() }
        val t0 = System.currentTimeMillis()
        while (lastInstall.isEmpty() && System.currentTimeMillis() - t0 < 150_000L) {
            if (ctx.cancelled()) break
            ctx.status("Waiting for the system installer (the user must confirm)...")
            try { Thread.sleep(1000) } catch (_: InterruptedException) { break }
        }
        val r = lastInstall
        if (r.isEmpty()) return "No install result yet: the user may still be confirming in the system installer. See the Build tab log."
        val conflict = r.contains("INCOMPATIBLE", true) || r.contains("signatures", true) || r.contains("CONFLICT", true)
        return "Install result: $r" + (if (conflict) "\nThe original app has a different signature: use uninstall_original (the user confirms), or set_package_rename and build again." else "")
    }

    private fun agentUninstall(): String {
        val pkg = packageNameOrNull() ?: return "error: no APK is loaded"
        if (pkg == packageName) return "error: that is APK ReLab itself"
        runOnUiThread { uninstallOriginal() }
        return "The uninstall confirmation for $pkg was shown to the user (its data is deleted if they accept)."
    }

    private fun agentSetPackageRename(pkg: String): String {
        val v = pkg.trim()
        if (v.isEmpty() || v.equals("off", ignoreCase = true)) {
            if (!agentConfirm("Agent: package rename", "Turn package rename OFF for the next build?")) return "The user declined."
            prefs().edit().remove("newpkg").apply()
            return "Package rename is OFF."
        }
        if (!pkgRegex.matches(v)) return "error: \"$v\" is not a valid package name (example: com.example.test)"
        if (v == packageNameOrNull() || v == packageName) return "error: choose a name that differs from the original app and from APK ReLab itself"
        if (!agentConfirm("Agent: package rename", "Use the package name $v for the next build, so the modified app installs next to the original?")) return "The user declined."
        prefs().edit().putString("newpkg", v).apply()
        return "Package rename set to $v. It applies to the next build_apk."
    }

    private fun agentQueueManifestFix(fix: String, component: String, value: Boolean): String {
        if (manifestFull.isBlank()) return "error: no APK is loaded"
        val txt = manifestFull
        val edit: ManifestEdits.Edit
        when (fix) {
            "debuggable", "allowBackup", "usesCleartextTraffic" -> {
                if (!txt.contains("android:$fix=")) return "error: android:$fix is not present in the manifest, so it cannot be changed (this tool only flips existing attributes)."
                edit = ManifestEdits.Edit("application", fix, "", value)
            }
            "exported" -> {
                if (component.isEmpty()) return "error: give the component class name in \"component\"."
                var found: ManifestEdits.Edit? = null
                var launcher = false
                for (m in rx("<(activity|activity-alias|service|receiver|provider)\\b[^>]*>").findAll(txt)) {
                    val tag = m.value
                    val nm = rx("android:name=\"([^\"]+)\"").find(tag)?.groupValues?.get(1) ?: continue
                    if (nm != component && !nm.endsWith("." + component.substringAfterLast('.'))) continue
                    if (!tag.contains("android:exported=")) return "error: $nm has no android:exported attribute, so it cannot be changed."
                    val closeAt = if (tag.endsWith("/>")) -1 else txt.indexOf("</" + m.groupValues[1] + ">", m.range.last)
                    val block = if (closeAt < 0) tag else txt.substring(m.range.first, closeAt)
                    if (block.contains("android.intent.category.LAUNCHER")) launcher = true
                    found = ManifestEdits.Edit(m.groupValues[1], "exported", nm, value)
                    break
                }
                if (launcher) return "error: $component is the launcher activity; un-exporting it would stop the app from opening. Refused. The launcher must stay exported; do not suggest moving its intent-filter, this tool cannot do that. Tell the user to leave it as is."
                edit = found ?: return "error: component $component was not found in the manifest."
            }
            else -> return "error: unknown fix \"$fix\". Use debuggable, allowBackup, usesCleartextTraffic or exported."
        }
        if (!agentConfirm("Agent: manifest fix", "Queue this manifest change for the next build?\n\n" + ManifestEdits.describe(edit))) return "The user declined."
        ManifestEdits.add(wsDir, edit)
        runOnUiThread { if (selectedManifestTab()) showManifestTab() }
        return "Queued: " + ManifestEdits.describe(edit) + ". It is applied to the manifest by the next build_apk (" + ManifestEdits.load(wsDir).size + " pending)."
    }

    private fun agentQueueManifestAll(): String {
        if (manifestFull.isBlank()) return "error: no APK is loaded"
        val list = allManifestFixes(manifestFull)
        if (list.isEmpty()) return "Nothing to fix: no debuggable / allowBackup / cleartext flag is true, and no exported component other than the launcher and deep-link activities was found."
        val msg = "Queue these " + list.size + " manifest changes for the next build?\n\n" + list.joinToString("\n") { ManifestEdits.describe(it) } +
            "\n\nThe launcher and deep-link (BROWSABLE) activities are left alone. A component that other apps are meant to call will stop working once it is not exported."
        if (!agentConfirm("Agent: manifest fixes", msg)) return "The user declined."
        ManifestEdits.addAll(wsDir, list)
        runOnUiThread { if (selectedManifestTab()) showManifestTab() }
        return "Queued " + list.size + " change(s): " + list.joinToString("; ") { ManifestEdits.describe(it) } + ". Applied by the next build_apk (" + ManifestEdits.load(wsDir).size + " pending)."
    }

    private fun selectedManifestTab(): Boolean = ::pathView.isInitialized && pathView.text.startsWith("AndroidManifest.xml")

    private fun agentExportReport(): String {
        if (apkModule == null) return "error: no APK is loaded"
        runOnUiThread { exportReport("md") }
        return "The save dialog for the Markdown report was opened for the user."
    }

    /** Palette of every tool (from Tools.kt). Tapping one calls [onPick]. */
    private fun showToolsPalette(onPick: (ToolSpec) -> Unit) {
        val pad = Ui.dp(12)
        val box = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, 0)
        }
        var dlg: AlertDialog? = null
        for (g in Tools.groups) {
            box.addView(TextView(this).apply {
                text = g
                textSize = 14f
                typeface = Typeface.DEFAULT_BOLD
                setPadding(0, Ui.dp(10), 0, Ui.dp(2))
            })
            for (t in Tools.all) {
                if (t.group != g) continue
                box.addView(Button(this).apply {
                    text = t.label + (if (t.asks) "  (asks you)" else "")
                    textSize = 13f
                    isAllCaps = false
                    setOnClickListener { dlg?.dismiss(); onPick(t) }
                })
                box.addView(TextView(this).apply {
                    text = t.desc.take(90)
                    textSize = 11f
                    setPadding(Ui.dp(4), 0, 0, Ui.dp(2))
                })
            }
        }
        Ui.skin(box)
        dlg = AlertDialog.Builder(this)
            .setTitle("All tools")
            .setView(ScrollView(this).apply { addView(box) })
            .setNegativeButton("Close", null)
            .show()
    }

    private fun showAgentChat() {
        if (aiKey().isNullOrEmpty()) { aiNeedKey(); return }
        agentDialog?.let { if (it.isShowing) return }
        val dlg = android.app.Dialog(this, if (Ui.p.dark) android.R.style.Theme_DeviceDefault_NoActionBar else android.R.style.Theme_DeviceDefault_Light_NoActionBar)
        agentDialog = dlg
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            background = Ui.AmbientDrawable()
        }

        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(Ui.dp(14), Ui.dp(8), Ui.dp(8), Ui.dp(4))
        }
        bar.addView(TextView(this).apply {
            text = "AI Hub"
            textSize = 20f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(Ui.p.ink)
        }, LinearLayout.LayoutParams(0, WRAP, 1f))
        val toolsBtn = Button(this).apply { text = "Tools"; textSize = 12f }
        val clearBtn = Button(this).apply { text = "Clear"; textSize = 12f }
        val closeBtn = Button(this).apply { text = "Close"; textSize = 12f }
        bar.addView(toolsBtn, LinearLayout.LayoutParams(WRAP, WRAP))
        bar.addView(clearBtn, LinearLayout.LayoutParams(WRAP, WRAP))
        bar.addView(closeBtn, LinearLayout.LayoutParams(WRAP, WRAP))
        root.addView(bar, LinearLayout.LayoutParams(MATCH, WRAP))

        // 0.30.0: who leads and who works (tap to open AI settings)
        val teamLine = TextView(this).apply {
            text = "🧠 " + Team.describe(prefs())
            textSize = 11f
            setTextColor(Ui.p.sub)
            setPadding(Ui.dp(16), 0, Ui.dp(12), Ui.dp(6))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
            setOnClickListener { showSettings() }
        }
        root.addView(teamLine, LinearLayout.LayoutParams(MATCH, WRAP))

        val chipRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(Ui.dp(8), 0, Ui.dp(8), Ui.dp(4))
        }

        // 0.37.2: two tabs (Chat | Map), a live status strip, and the map as a full-width page
        val tabRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            background = Ui.GlassDrawable(30, Ui.p.glassHi, true, false)
            setPadding(Ui.dp(3), Ui.dp(3), Ui.dp(3), Ui.dp(3))
        }
        val tabChat = TextView(this).apply { text = "Chat"; textSize = 14f; gravity = Gravity.CENTER; setPadding(0, Ui.dp(8), 0, Ui.dp(8)) }
        val tabMap = TextView(this).apply { text = "Map"; textSize = 14f; gravity = Gravity.CENTER; setPadding(0, Ui.dp(8), 0, Ui.dp(8)) }
        tabRow.addView(tabChat, LinearLayout.LayoutParams(0, WRAP, 1f))
        tabRow.addView(tabMap, LinearLayout.LayoutParams(0, WRAP, 1f))
        root.addView(tabRow, LinearLayout.LayoutParams(MATCH, WRAP).apply { setMargins(Ui.dp(12), Ui.dp(2), Ui.dp(12), Ui.dp(6)) })

        val liveStrip = TextView(this).apply {
            textSize = 13f
            setTextColor(Ui.p.onAccent)
            background = Ui.GlassDrawable(24, Ui.p.accent, true, false)
            setPadding(Ui.dp(14), Ui.dp(7), Ui.dp(14), Ui.dp(7))
            maxLines = 1
            ellipsize = android.text.TextUtils.TruncateAt.END
            visibility = View.GONE
        }
        root.addView(liveStrip, LinearLayout.LayoutParams(MATCH, WRAP).apply { setMargins(Ui.dp(12), 0, Ui.dp(12), Ui.dp(6)) })

        val agentMap = AgentMapView(this)
        val mapScroll = ScrollView(this).apply {
            isVerticalScrollBarEnabled = false
            addView(agentMap, FrameLayout.LayoutParams(MATCH, WRAP))
            visibility = View.GONE
        }
        agentMap.onFocus = { _, cy -> mapScroll.post { mapScroll.smoothScrollTo(0, maxOf(0, cy - mapScroll.height / 2)) } }
        root.addView(mapScroll, LinearLayout.LayoutParams(MATCH, 0, 1f))

        val msgBox = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(Ui.dp(10), Ui.dp(6), Ui.dp(10), Ui.dp(6))
        }
        val msgScroll = ScrollView(this).apply { addView(msgBox) }
        root.addView(msgScroll, LinearLayout.LayoutParams(MATCH, 0, 1f))

        val inputRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(Ui.dp(8), Ui.dp(4), Ui.dp(8), Ui.dp(8))
        }
        val input = EditText(this).apply {
            hint = "Type your request..."
            textSize = 15f
            maxLines = 4
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE
        }
        val sendBtn = Button(this).apply {
            text = if (agentBusy) "\u25A0" else "\u27A4"
            textSize = 18f
            tag = "primary"
        }
        inputRow.addView(input, LinearLayout.LayoutParams(0, WRAP, 1f))
        inputRow.addView(sendBtn, LinearLayout.LayoutParams(Ui.dp(48), Ui.dp(48)).apply { leftMargin = Ui.dp(8) })
        root.addView(inputRow, LinearLayout.LayoutParams(MATCH, WRAP))

        fun bubble(color: Int, stroke: Boolean): android.graphics.drawable.Drawable = Ui.GlassDrawable(18, color, stroke, false)

        // 0.37.5: attachments (images / PDF / text files) waiting to be sent with the next message
        val pendingAtt = ArrayList<Attach>()
        val attachBar = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val attachScroll = android.widget.HorizontalScrollView(this).apply {
            isHorizontalScrollBarEnabled = false
            visibility = View.GONE
            setPadding(Ui.dp(10), Ui.dp(2), Ui.dp(10), Ui.dp(2))
            addView(attachBar)
        }
        root.addView(attachScroll, root.indexOfChild(inputRow), LinearLayout.LayoutParams(MATCH, WRAP))
        val attachBtn = Button(this).apply {
            text = "\uD83D\uDCCE"
            textSize = 18f
            isAllCaps = false
        }
        inputRow.addView(attachBtn, 0, LinearLayout.LayoutParams(Ui.dp(44), Ui.dp(44)).apply { rightMargin = Ui.dp(6) })

        fun refreshAttach() {
            attachBar.removeAllViews()
            for (a in pendingAtt.toList()) {
                val chip = TextView(this)
                val icon = if (a.kind == "image") "\uD83D\uDDBC " else if (a.kind == "pdf") "\uD83D\uDCC4 " else "\uD83D\uDCDD "
                chip.text = (if (a.kept) "\u21BB " else "") + icon + (if (a.name.length > 22) a.name.take(20) + "\u2026" else a.name) + "  \u2715"
                chip.textSize = 12f
                chip.setTextColor(Ui.p.ink)
                chip.background = bubble(Ui.p.surface, true)
                chip.setPadding(Ui.dp(10), Ui.dp(6), Ui.dp(10), Ui.dp(6))
                chip.setOnClickListener {
                    pendingAtt.remove(a)
                    refreshAttach()
                }
                attachBar.addView(chip, LinearLayout.LayoutParams(WRAP, WRAP).apply { rightMargin = Ui.dp(6) })
            }
            attachScroll.visibility = if (pendingAtt.isEmpty()) View.GONE else View.VISIBLE
        }

        fun addAttachments(uris: List<Uri>) {
            if (uris.isEmpty()) return
            val room = Attachments.MAX_FILES - pendingAtt.size
            if (room <= 0) {
                Toast.makeText(this, "Max " + Attachments.MAX_FILES + " files per message", Toast.LENGTH_SHORT).show()
                return
            }
            val cr = contentResolver
            Thread {
                val errors = ArrayList<String>()
                val loaded = ArrayList<Attach>()
                for (u in uris) {
                    if (loaded.size >= room) { errors.add("Max " + Attachments.MAX_FILES + " files per message"); break }
                    val (a, err) = Attachments.load(cr, u)
                    if (a != null) loaded.add(a) else errors.add(err)
                }
                runOnUiThread {
                    for (a in loaded) {
                        val have = Attachments.mediaList(pendingAtt).sumOf { it.b64.length }
                        val add = a.media?.b64?.length ?: 0
                        if (have + add > Attachments.MAX_MEDIA_TOTAL) {
                            errors.add(a.name + ": too much image / PDF data in one message")
                            continue
                        }
                        pendingAtt.add(a)
                    }
                    refreshAttach()
                    if (errors.isNotEmpty()) Toast.makeText(this, errors.joinToString("\n").take(300), Toast.LENGTH_LONG).show()
                }
            }.start()
        }
        attachCallback = { uris -> addAttachments(uris) }
        dlg.setOnDismissListener { attachCallback = null }
        attachBtn.setOnClickListener {
            if (agentBusy) return@setOnClickListener
            launchAttachPicker()
        }

        // 0.37.3: tool steps are cards (label in the group colour + short args) instead of raw "tool {json}" lines
        var lastStepTv: TextView? = null
        var liveDetail = ""
        var welcomeView: View? = null
        var welcomeBuilder: (() -> Unit)? = null

        fun renderStep(tv: TextView, info: StepInfo, done: Boolean) {
            val sb = SpannableStringBuilder()
            val a = sb.length
            sb.append(if (done) "\u2713  " else "\u25CF  ")
            sb.setSpan(ForegroundColorSpan(info.color), a, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            val b = sb.length
            sb.append(info.label)
            sb.setSpan(ForegroundColorSpan(info.color), b, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            sb.setSpan(StyleSpan(Typeface.BOLD), b, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            if (info.args.isNotEmpty()) {
                val c = sb.length
                sb.append("   ").append(info.args)
                sb.setSpan(ForegroundColorSpan(Ui.p.sub), c, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                sb.setSpan(RelativeSizeSpan(0.85f), c, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            tv.text = sb
        }

        fun stepInfo(line: String): StepInfo? {
            val t = line.trim()
            val first = t.substringBefore(' ').substringBefore('{')
            val label = AgentMapView.labelFor(first) ?: return null
            val raw = t.removePrefix(first).trim()
            val args = if (raw == "{}" || raw.isEmpty()) "" else raw.replace(rx("[{}\"]"), "").take(70)
            return StepInfo(label, args, AgentMapView.colorForTool(first))
        }

        // kind: 0 user, 1 answer, 2 tool step, 3 status/hint
        fun addMsg(kind: Int, text: String, foot: String = ""): TextView {
            val tv = TextView(this)
            val lp = LinearLayout.LayoutParams(WRAP, WRAP)
            lp.setMargins(0, Ui.dp(4), 0, Ui.dp(4))
            tv.maxWidth = (resources.displayMetrics.widthPixels * 0.92f).toInt()
            when (kind) {
                0 -> {
                    tv.text = text
                    tv.textSize = 15f
                    tv.setTextColor(Color.WHITE)
                    tv.background = bubble(Ui.p.primary, false)
                    tv.setPadding(Ui.dp(12), Ui.dp(8), Ui.dp(12), Ui.dp(8))
                    lp.gravity = Gravity.END
                }
                1 -> {
                    val sb = SpannableStringBuilder(renderMarkdown(text.trim()))
                    if (foot.isNotEmpty()) {
                        val st = sb.length
                        sb.append('\n').append(foot)
                        sb.setSpan(RelativeSizeSpan(0.75f), st, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                        sb.setSpan(ForegroundColorSpan(Ui.p.sub), st, sb.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                    }
                    tv.text = sb
                    tv.textSize = 15f
                    tv.setTextColor(Ui.p.ink)
                    tv.background = bubble(Ui.p.surface, true)
                    tv.setPadding(Ui.dp(12), Ui.dp(8), Ui.dp(12), Ui.dp(8))
                    tv.setTextIsSelectable(true)
                    lp.gravity = Gravity.START
                }
                else -> {
                    val info = if (kind == 2) stepInfo(text) else null
                    if (info != null) {
                        lastStepTv?.let { prev -> (prev.tag as? StepInfo)?.let { renderStep(prev, it, true) } }
                        tv.tag = info
                        renderStep(tv, info, false)
                        tv.textSize = 13f
                        tv.setTextColor(Ui.p.ink)
                        tv.background = Ui.GlassDrawable(16, Ui.p.surface, true, false)
                        tv.setPadding(Ui.dp(12), Ui.dp(7), Ui.dp(12), Ui.dp(7))
                        lastStepTv = tv
                    } else {
                        tv.text = if (kind == 2) text else text
                        tv.textSize = 12f
                        tv.setTextColor(Ui.p.sub)
                        tv.setPadding(Ui.dp(6), 0, Ui.dp(6), 0)
                    }
                    lp.gravity = Gravity.START
                }
            }
            msgBox.addView(tv, lp)
            msgScroll.post { msgScroll.fullScroll(View.FOCUS_DOWN) }
            return tv
        }

        fun finishSteps() {
            lastStepTv?.let { prev -> (prev.tag as? StepInfo)?.let { renderStep(prev, it, true) } }
            lastStepTv = null
        }

        agentLoad()
        if (agentLog.isNotEmpty()) {
            for (m in agentLog) addMsg(m.kind, m.text, m.foot)
            finishSteps()
        }

        fun send(text: String) {
            val typed = text.trim()
            val atts = ArrayList(pendingAtt)
            val t = if (typed.isEmpty() && atts.any { !it.kept }) "Look at the attached file(s): what do they show, and what matters in them for the analysis of the open APK?" else typed
            if (t.isEmpty() || agentBusy) return
            agentBusy = true
            agentCancel = false
            input.setText("")
            hideKeyboard()
            val shown = if (atts.isEmpty()) t else t + "\n\uD83D\uDCCE " + atts.joinToString(", ") { it.name + (if (it.kept) " \u21BB" else "") }
            // 0.37.8: the files stay attached (chips with a refresh mark) so follow-up questions still see them; tap a chip to drop one
            val newImgs = atts.filter { it.thumb != null && !it.kept }      // thumbnails only for files that were not already shown
            pendingAtt.clear()
            for (a in atts) { a.kept = true; pendingAtt.add(a) }
            refreshAttach()
            if (newImgs.isNotEmpty()) {
                val row = LinearLayout(this)
                row.orientation = LinearLayout.HORIZONTAL
                row.gravity = Gravity.END
                for (a in newImgs) {
                    val iv = android.widget.ImageView(this)
                    iv.setImageBitmap(a.thumb)
                    iv.scaleType = android.widget.ImageView.ScaleType.CENTER_CROP
                    iv.background = bubble(Ui.p.surface, true)
                    iv.clipToOutline = true
                    row.addView(iv, LinearLayout.LayoutParams(Ui.dp(72), Ui.dp(72)).apply { leftMargin = Ui.dp(6) })
                }
                msgBox.addView(row, LinearLayout.LayoutParams(MATCH, WRAP).apply { setMargins(0, Ui.dp(4), 0, 0) })
            }
            agentLog.add(AgentMsg(0, shown, ""))
            agentSave()
            addMsg(0, shown)
            sendBtn.text = "\u25A0"
            welcomeView?.let { msgBox.removeView(it) }
            welcomeView = null
            liveDetail = ""
            agentMap.reset()
            agentMap.setRunning(true)
            val st = addMsg(3, "Thinking...")
            val hist = ArrayList(agentHistory)
            Thread {
                val res = try {
                    Agent.run(agentHost, prefs(), hist, t,
                        { s -> runOnUiThread { st.text = s; liveDetail = if (s.startsWith("Thinking")) "" else s.take(48); agentMap.setLead(s.removePrefix("Thinking... ")) } },
                        { s -> runOnUiThread { agentLog.add(AgentMsg(2, s, "")); addMsg(2, s); agentMap.onStep(s) } },
                        { agentCancel },
                        attachText = Attachments.textBlock(atts), media = Attachments.mediaList(atts))
                } catch (e: Throwable) {
                    AgentResult("Error: " + (e.message ?: e.javaClass.simpleName), "", "")
                }
                runOnUiThread {
                    msgBox.removeView(st)
                    val foot = if (res.label.isEmpty()) "" else "answered by: " + res.label + (if (res.notes.isNotEmpty()) "\nfailed attempts before:\n" + res.notes else "")
                    agentLog.add(AgentMsg(1, res.text, foot))
                    agentHistory.add(shown to res.text)
                    agentSave()
                    addMsg(1, res.text, foot)
                    agentBusy = false
                    finishSteps()
                    agentMap.setRunning(false)
                    sendBtn.text = "\u27A4"
                    teamLine.text = "🧠 " + Team.describe(prefs())
                }
            }.start()
        }

        sendBtn.setOnClickListener {
            if (agentBusy) {
                agentCancel = true
                sendBtn.text = "\u2026"
            } else {
                send(input.text.toString())
            }
        }
        clearBtn.setOnClickListener {
            if (agentBusy) return@setOnClickListener
            agentLog.clear()
            agentHistory.clear()
            agentSave()
            pendingAtt.clear()
            refreshAttach()
            msgBox.removeAllViews()
            lastStepTv = null
            welcomeView = null
            welcomeBuilder?.invoke()
        }
        closeBtn.setOnClickListener { dlg.dismiss() }

        fun chipBtn(label: String, action: () -> Unit) {
            val b = Button(this).apply {
                text = label
                textSize = 12f
                isAllCaps = false
                setOnClickListener { action() }
            }
            chipRow.addView(b, LinearLayout.LayoutParams(WRAP, WRAP).apply { rightMargin = Ui.dp(6) })
        }
        fun prefill(s: String) {
            input.setText(s)
            input.setSelection(s.length)
            input.requestFocus()
        }
        chipBtn("Explain this class") { send("Explain the currently open class: what it does and its most important functions.") }
        chipBtn("Search the code") { prefill("Search the code for ") }
        chipBtn("Smart scan") { send("Run the smart security scan and tell me the most important real problems.") }
        chipBtn("Review security scan") { send("Review the top security findings: which are real and which are likely false positives, rank them by priority, and tell me where to start.") }
        chipBtn("Manifest") { send("Review the manifest: explain the permissions and exported components, and flag anything unusual or risky.") }
        chipBtn("Edit this class") { prefill("Edit the open class to ") }
        chipBtn("Build + install") { send("Build and sign the APK, then install it.") }
        toolsBtn.setOnClickListener {
            showToolsPalette { t -> if (t.request.endsWith(" ")) prefill(t.request) else send(t.request) }
        }
        // 0.37.3: suggestion cards on an empty chat (replace the old chip row)
        welcomeBuilder = {
            fun suggestion(title: String, sub: String, color: Int, onTap: () -> Unit): View {
                val c = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    background = Ui.GlassDrawable(18, Ui.p.surface, true, false)
                    setPadding(Ui.dp(12), Ui.dp(10), Ui.dp(12), Ui.dp(10))
                    setOnClickListener { onTap() }
                }
                c.addView(TextView(this).apply { text = title; textSize = 14f; typeface = Typeface.DEFAULT_BOLD; setTextColor(color) })
                c.addView(TextView(this).apply { text = sub; textSize = 11f; setTextColor(Ui.p.sub); setPadding(0, Ui.dp(2), 0, 0) })
                return c
            }
            val w = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(Ui.dp(2), Ui.dp(8), Ui.dp(2), Ui.dp(8))
            }
            w.addView(TextView(this).apply { text = "What do you want to do?"; textSize = 20f; typeface = Typeface.DEFAULT_BOLD; setTextColor(Ui.p.ink) })
            w.addView(TextView(this).apply {
                text = "Tap a card or type your request. The lead AI plans, workers help, and anything that changes your app asks you first."
                textSize = 12f
                setTextColor(Ui.p.sub)
                setPadding(0, Ui.dp(4), 0, Ui.dp(10))
            })
            val cards = listOf(
                suggestion("Explain a class", "Step by step, from the open class", AgentMapView.colorFor("Inspect")) { send("Explain the currently open class: what it does and its most important functions.") },
                suggestion("Smart scan", "Find the real security problems", AgentMapView.colorFor("Security")) { send("Run the smart security scan and tell me the most important real problems.") },
                suggestion("Review manifest", "Permissions and exported parts", AgentMapView.colorFor("AI analysis")) { send("Review the manifest: explain the permissions and exported components, and flag anything unusual or risky.") },
                suggestion("Search the code", "A string, an API or a URL", AgentMapView.colorFor("Inspect")) { prefill("Search the code for ") },
                suggestion("Edit a class", "You approve every change", AgentMapView.colorFor("Edit")) { prefill("Edit the open class to ") },
                suggestion("Build + install", "Sign it and install it", AgentMapView.colorFor("Build & install")) { send("Build and sign the APK, then install it.") }
            )
            var i = 0
            while (i < cards.size) {
                val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
                row.addView(cards[i], LinearLayout.LayoutParams(0, WRAP, 1f).apply { setMargins(0, 0, Ui.dp(5), Ui.dp(10)) })
                if (i + 1 < cards.size) row.addView(cards[i + 1], LinearLayout.LayoutParams(0, WRAP, 1f).apply { setMargins(Ui.dp(5), 0, 0, Ui.dp(10)) })
                w.addView(row, LinearLayout.LayoutParams(MATCH, WRAP))
                i += 2
            }
            welcomeView = w
            msgBox.addView(w)
        }
        if (agentLog.isEmpty()) welcomeBuilder?.invoke()
        agentMap.onPick = { t -> if (t.request.endsWith(" ")) prefill(t.request) else send(t.request) }
        var hubTab = 0
        fun showTab(i: Int) {
            hubTab = i
            msgScroll.visibility = if (i == 0) View.VISIBLE else View.GONE
            mapScroll.visibility = if (i == 1) View.VISIBLE else View.GONE
            for ((k, tv) in listOf(tabChat, tabMap).withIndex()) {
                val sel = k == i
                tv.setTextColor(if (sel) Color.WHITE else Ui.p.sub)
                tv.typeface = if (sel) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
                tv.background = if (sel) Ui.GlassDrawable(30, Ui.p.primary, true, false) else null
            }
            if (i == 1) hideKeyboard()
        }
        tabChat.setOnClickListener { showTab(0) }
        tabMap.setOnClickListener { showTab(1) }
        liveStrip.setOnClickListener { showTab(1 - hubTab) }
        agentMap.onState = {
            if (agentMap.isRunning()) {
                val what = agentMap.activeLabel() ?: "Thinking..."
                val other = if (hubTab == 0) "  (tap: map)" else "  (tap: chat)"
                val detail = if (agentMap.activeLabel() != null && liveDetail.isNotEmpty()) "  \u00B7  " + liveDetail else "  \u00B7  " + agentMap.stepCount() + " steps"
                liveStrip.text = "\u25CF  " + what + detail + other
                liveStrip.visibility = View.VISIBLE
            } else {
                liveStrip.visibility = View.GONE
            }
        }
        showTab(0)

        root.setOnApplyWindowInsetsListener { v, ins ->
            var top = 0
            var bottom = 0
            if (Build.VERSION.SDK_INT >= 30) {
                val bars = ins.getInsets(android.view.WindowInsets.Type.systemBars() or android.view.WindowInsets.Type.ime())
                top = bars.top
                bottom = bars.bottom
            } else {
                top = ins.systemWindowInsetTop
                bottom = ins.systemWindowInsetBottom
            }
            v.setPadding(0, top, 0, bottom)
            ins
        }
        Ui.skin(root)
        sendBtn.minWidth = 0
        sendBtn.minimumWidth = 0
        sendBtn.minHeight = 0
        sendBtn.minimumHeight = 0
        sendBtn.setPadding(0, 0, 0, 0)
        sendBtn.setTextColor(Color.WHITE)
        sendBtn.background = Ui.ripple(Ui.GlassDrawable(40, Ui.p.primary, true, false), 40)
        attachBtn.minWidth = 0
        attachBtn.minimumWidth = 0
        attachBtn.minHeight = 0
        attachBtn.minimumHeight = 0
        attachBtn.setPadding(0, 0, 0, 0)
        attachBtn.setTextColor(Ui.p.ink)
        attachBtn.background = Ui.ripple(Ui.GlassDrawable(40, Ui.p.surface, true, false), 40)
        for (b in listOf(toolsBtn, clearBtn, closeBtn)) {
            b.minWidth = 0
            b.minimumWidth = 0
            b.minHeight = 0
            b.minimumHeight = 0
            b.setPadding(Ui.dp(14), Ui.dp(7), Ui.dp(14), Ui.dp(7))
        }
        dlg.setContentView(root)
        dlg.window?.let { w ->
            w.setLayout(MATCH, MATCH)
            w.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
            w.statusBarColor = Color.TRANSPARENT
            w.navigationBarColor = Color.TRANSPARENT
            if (Build.VERSION.SDK_INT >= 29) w.isNavigationBarContrastEnforced = false
            if (Build.VERSION.SDK_INT >= 30) {
                w.setDecorFitsSystemWindows(false)
                val light = android.view.WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                    android.view.WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
                w.insetsController?.setSystemBarsAppearance(if (Ui.p.dark) 0 else light, light)
            } else {
                w.decorView.systemUiVisibility = View.SYSTEM_UI_FLAG_LAYOUT_STABLE or View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN or
                    (if (Ui.p.dark) 0 else (View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR))
            }
        }
        dlg.show()
    }

    // ---------- file tree ----------

    private fun showTree() {
        val folders = LinkedHashMap<String, LongArray>()
        val files = ArrayList<Pair<String, Long>>()
        for ((name, size) in entries) {
            if (!name.startsWith(currentPath)) continue
            val rest = name.substring(currentPath.length)
            if (rest.isEmpty()) continue
            val slash = rest.indexOf('/')
            if (slash >= 0) {
                val a = folders.getOrPut(rest.substring(0, slash)) { LongArray(2) }
                a[0]++
                a[1] += size
            } else {
                files.add(rest to size)
            }
        }

        val out = ArrayList<Row>()
        if (currentPath.isNotEmpty()) out.add(Row("⬆ ..", isUp = true))
        for (f in folders.keys.sorted()) {
            val a = folders[f]!!
            out.add(Row("📁 $f/\n${a[0]} files · ${fmt(a[1])}", folder = "$currentPath$f/"))
        }
        for ((n, s) in files.sortedBy { it.first }) {
            out.add(Row("📄 $n\n${fmt(s)}", file = "$currentPath$n"))
        }
        rows = out
        pathView.text = "/$currentPath"
        list.adapter = Ui.RowAdapter(this, out.map { it.label })
    }

    private fun goUp() {
        val trimmed = currentPath.trimEnd('/')
        val i = trimmed.lastIndexOf('/')
        currentPath = if (i < 0) "" else trimmed.substring(0, i + 1)
        showTree()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        when {
            editing -> finishEdit()
            buildScroll.visibility == View.VISIBLE -> { inClasses = false; showTree(); showList() }
            viewingFile -> showList()
            currentPath.isNotEmpty() && list.visibility == View.VISIBLE -> goUp()
            else -> @Suppress("DEPRECATION") super.onBackPressed()
        }
    }

    private fun fmt(bytes: Long): String = when {
        bytes >= 1024 * 1024 -> String.format("%.1f MB", bytes / 1048576.0)
        bytes >= 1024 -> String.format("%.1f KB", bytes / 1024.0)
        else -> "$bytes B"
    }
}

/** 0.37.3: one tool step shown as a card in the AI Hub chat. */
private class StepInfo(val label: String, val args: String, val color: Int)
