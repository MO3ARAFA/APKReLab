package dev.apkrelab

import java.util.concurrent.ConcurrentHashMap

/**
 * 0.106.0: which classes that R8 renamed into the ROOT package (`La;`, `Laq8;`) belong to a bundled SDK, by structure only. A library's own code can only name the library's own types,
 * so a renamed class that kept library classes name (Firebase's AppMeasurementService names `aq8`; MoEngage's PushTracker names `u5`) is that library's code. One more hop: a renamed class
 * named ONLY by classes already given to one family belongs to it as well (up to [MAX_HOPS]).
 *
 * Three ways this can be wrong, each measured and guarded (Axis Pay 3.0.1 + 5 R8-repackaged open-source apps of the F-Droid corpus, where the app's own readable classes are known):
 *  - R8 merges classes horizontally, app and library code into one (`k4` in Keep It: named by the app's CacheSnapshot AND by androidx.work); such a class carries a synthetic int,
 *    short or byte discriminator field (`w` in Keep It: `synthetic p:B`, app lambdas inside): never attributed. Its static class merger puts unrelated static methods into one class
 *    without instance state (`ct1` in webviewkiosk: 48 statics, the app's WebView loading among them): never attributed either.
 *  - R8 devirtualises a library call into the app's only implementation (an androidx.startup Initializer, a Glance widget): the class names the app's own package or is named by it:
 *    never attributed.
 *  - Two SDKs name the class (another merge): not attributed.
 * Measured: without the guards 36 of 2,482 attributions in 3 of those apps named the app's package; with them, 0. A class that is the app's and names nothing of the app's package
 * cannot be told apart this way: that residual risk is why the result only re-scopes findings and leaves classes out of the data-flow step behind a setting.
 */
class SdkAttribution(appPkg: String) {
    companion object {
        const val MAX_HOPS = 3
        private val rootType = Regex("L[A-Za-z0-9_$]+;")
        private val merged = Regex("^\\.field [^\\n]*\\bsynthetic\\b[^\\n]*:[BSI]$", RegexOption.MULTILINE)    // R8's class-id discriminator (int, short or byte)
        private val method = Regex("^\\.method ([^\\n]*)$", RegexOption.MULTILINE)
        private val instanceField = Regex("^\\.field (?![^\\n]*\\bstatic\\b)", RegexOption.MULTILINE)
        const val STATIC_HOLDER_MIN = 10

        /** R8's static class merger: many static methods of unrelated origins in one class with no instance state (webviewkiosk's ct1: 48 statics with app code; Axis Pay's jn0: 19 statics, Gson + Crashlytics). 10 keeps the measured SDK classes and blocks both. */
        fun staticHolder(text: String): Boolean {
            var n = 0
            for (m in method.findAll(text)) { if (!m.groupValues[1].contains(" static ") && !m.groupValues[1].startsWith("static ")) return false; n++ }
            return n >= STATIC_HOLDER_MIN && !instanceField.containsMatchIn(text)
        }

        /** "com.google.firebase" for Lcom/google/firebase/..., otherwise the first two segments ("com.moengage"); null for a class with no package. */
        fun family(type: String): String? {
            val s = type.removePrefix("L").removeSuffix(";").split('/')
            if (s.size < 3) return null
            return if (s[0] == "com" && s[1] == "google" && s.size > 3) s[0] + "." + s[1] + "." + s[2] else s[0] + "." + s[1]
        }
    }

    private val appPrefix: String = appPkg.split('.').let { if (it.size >= 2) "L" + it[0] + "/" + it[1] + "/" else if (appPkg.isNotEmpty()) "L$appPkg/" else "\u0000" }
    private val named = ConcurrentHashMap<String, Array<String>>()        // class -> the root-package types its text names
    private val blocked = ConcurrentHashMap.newKeySet<String>()             // root classes that may hold app code (merged, or naming the app's package)
    private val seen = ConcurrentHashMap.newKeySet<String>()                // every class of the scan
    /** 1.0.0: renamed root classes with R8's class-id field (horizontally merged) and static-method holders (static merger), for the OBF card hint (ClassTools.obfHint). */
    val mergedTypes: MutableSet<String> = ConcurrentHashMap.newKeySet()
    val holderTypes: MutableSet<String> = ConcurrentHashMap.newKeySet()

    /** Called with the text of every class of the scan (library classes included); thread-safe. */
    fun observe(type: String, text: String) {
        seen.add(type)
        val out = LinkedHashSet<String>()
        for (m in rootType.findAll(text)) if (m.value != type) out.add(m.value)
        if (out.isNotEmpty()) named[type] = out.toTypedArray()
        if (type.indexOf('/') < 0) {
            val isMerged = merged.containsMatchIn(text); val isHolder = !isMerged && staticHolder(text)
            if (isMerged) mergedTypes.add(type)
            if (isHolder) holderTypes.add(type)
            if (text.contains(appPrefix) || isMerged || isHolder) blocked.add(type)
        }
    }

    /** Root-package class -> SDK family, for the classes the evidence gives to exactly one family. [isLibrary] = the scanner's own known-library test. */
    fun compute(isLibrary: (String) -> Boolean): Map<String, String> {
        val namers = HashMap<String, MutableList<String>>()
        for ((n, ts) in named) for (t in ts) namers.getOrPut(t) { ArrayList() }.add(n)
        val fam = HashMap<String, String>()
        for (hop in 0..MAX_HOPS) {
            val add = HashMap<String, String>()
            for ((t, ns) in namers) {
                if (t.indexOf('/') >= 0 || t in fam || t in blocked || t !in seen) continue
                val fams = HashSet<String>(); var unknown = false; var byApp = false
                for (n in ns) {
                    when {
                        n.startsWith(appPrefix) -> byApp = true
                        n.indexOf('/') >= 0 && isLibrary(n) -> family(n)?.let { fams.add(it) }
                        n in fam -> fams.add(fam.getValue(n))
                        else -> unknown = true
                    }
                }
                if (byApp || fams.size != 1) continue
                if (hop > 0 && unknown) continue
                add[t] = fams.first()
            }
            if (add.isEmpty()) break
            fam.putAll(add)
        }
        return fam
    }
}
