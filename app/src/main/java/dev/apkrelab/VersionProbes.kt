package dev.apkrelab

/**
 * 0.88.0: the version of a bundled library from a CONSTANT that the library itself compiled into its classes, for the libraries that show up with version "?" because R8
 * stripped META-INF. Not a guess from class names: the value is text in the smali (a static final String, or the three ints handed to a constructor).
 * Validated on 37 real APKs (tools/sca/RESULTS_0880.md): Gson (`GsonBuildConfig.VERSION`) is carried by 9 of them, Kotlin's own version by most Kotlin apps.
 *
 * Pure functions on class text; the app reads the 2-6 class texts it needs (MainActivity), the sandbox reads them from the decoded smali.
 */
object VersionProbes {

    private class Probe(val group: String, val artifact: String, val classType: String, val read: (String) -> String?)

    private val versionLike = Regex("^\\d+\\.\\d+(?:\\.\\d+){0,3}(?:[.\\-][A-Za-z0-9]+)?$")

    /** `.field ... NAME:Ljava/lang/String; = "x.y.z"` -> x.y.z when it looks like a version. */
    internal fun fieldString(text: String, name: String): String? =
        Regex("\\.field [^\\n]*\\b" + Regex.escape(name) + ":Ljava/lang/String; = \"([^\"]+)\"").find(text)?.groupValues?.get(1)?.takeIf { versionLike.matches(it) }

    /**
     * The constants given to `KotlinVersion.<init>(III)V` (kotlin/KotlinVersion.<clinit> up to Kotlin 1.4, kotlin/KotlinVersionCurrentValue.get() after it):
     * "const/4 v1, 0x1  const/4 v2, 0x3  const/16 v3, 0x48  invoke-direct {v0, v1, v2, v3}, Lkotlin/KotlinVersion;-><init>(III)V" = 1.3.72.
     * Anything that is not three plain constants (the (II)V constructor passing registers on) is not read.
     */
    internal fun kotlinVersion(text: String): String? {
        val lines = text.lines()
        for ((i, l) in lines.withIndex()) {
            if (!l.contains("Lkotlin/KotlinVersion;-><init>(III)V")) continue
            val regs = Regex("\\{([^}]*)\\}").find(l)?.groupValues?.get(1)?.split(',')?.map { it.trim() } ?: continue
            if (regs.size != 4) continue
            val vals = IntArray(3) { -1 }
            for (k in 1..3) {
                var j = i - 1; var n = 0
                while (j >= 0 && n++ < 40) {
                    val m = Regex("^\\s*const(?:/4|/16)?\\s+" + Regex.escape(regs[k]) + ",\\s*(-?0x[0-9a-fA-F]+|-?\\d+)\\s*$").find(lines[j])
                    if (m != null) { vals[k - 1] = m.groupValues[1].let { if (it.startsWith("0x")) it.substring(2).toInt(16) else if (it.startsWith("-0x")) -it.substring(3).toInt(16) else it.toInt() }; break }
                    if (lines[j].trimStart().startsWith(".method")) break
                    j--
                }
            }
            if (vals.all { it in 0..255 }) return vals.joinToString(".")
        }
        return null
    }

    private val fixed: List<Probe> = listOf(
        Probe("com.google.code.gson", "gson", "Lcom/google/gson/internal/GsonBuildConfig;") { fieldString(it, "VERSION") },
        Probe("org.jetbrains.kotlin", "kotlin-stdlib", "Lkotlin/KotlinVersionCurrentValue;") { kotlinVersion(it) },
        Probe("org.jetbrains.kotlin", "kotlin-stdlib", "Lkotlin/KotlinVersion;") { kotlinVersion(it) }
    )

    /**
     * 0.88.0 (found by running it on 37 APKs): a path group that stands for MANY libraries (androidx-libraries, jitpack-libraries ...) has no single version, and a BuildConfig in a
     * SUB-package (com/google/firebase/installations/BuildConfig) belongs to another artifact than the root one: only `<library root package>/BuildConfig` of a single library is read.
     */
    private fun isAggregate(l: DetectedLib) = LibraryScanner.isAggregate(l) || ScaScanner.isLowSignal(l)

    /** The class types to read for [pathLibs] (library path detections) among [types]: the fixed carriers, and `<library root package>/BuildConfig` of each detected single library. */
    fun wanted(types: Set<String>, pathLibs: List<DetectedLib>): List<String> {
        val out = LinkedHashSet<String>()
        for (p in fixed) if (p.classType in types) out.add(p.classType)
        for (l in pathLibs) {
            if (l.version != "?") continue
            val pkg = l.evidence.removeSuffix("**")
            if (pkg.isEmpty() || !pkg.endsWith("/")) continue
            if (isAggregate(l)) continue
            val t = "L" + pkg + "BuildConfig;"
            if (t in types) out.add(t)
        }
        return out.toList()
    }

    /** Libraries with a version taken from [textOf] (the class text of a type, null when unavailable). */
    fun resolve(types: Set<String>, pathLibs: List<DetectedLib>, textOf: (String) -> String?): List<DetectedLib> {
        val out = LinkedHashMap<String, DetectedLib>()
        for (p in fixed) {
            val key = p.group + ":" + p.artifact
            if (key in out || p.classType !in types) continue
            val v = try { textOf(p.classType)?.let(p.read) } catch (_: Throwable) { null } ?: continue
            out[key] = DetectedLib(p.group, p.artifact, v, p.classType, "code constant")
        }
        for (l in pathLibs) {
            val key = l.group + ":" + l.artifact
            if (l.version != "?" || key in out) continue
            val pkg = l.evidence.removeSuffix("**")
            if (pkg.isEmpty() || !pkg.endsWith("/")) continue
            if (isAggregate(l)) continue
            val t = "L" + pkg + "BuildConfig;"
            if (t !in types) continue
            val v = try { textOf(t)?.let { fieldString(it, "VERSION_NAME") } } catch (_: Throwable) { null } ?: continue
            out[key] = DetectedLib(l.group, l.artifact, v, t, "code constant")
        }
        return out.values.toList()
    }
}
