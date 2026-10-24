package dev.apkrelab

import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * 0.99.0: APKs from the Play Store are SPLIT: the base APK holds the DEX and the manifest, the native libraries (Flutter's libapp.so, a protector's library, JNI code) live in
 * `split_config.<abi>.apk`, resources in `split_config.<density>.apk`. A scan of the base alone says "native code not analysed". This reads a bundle (.apks / .xapk / .apkm:
 * a zip of APKs) or a set of picked APKs, tells the base from the splits, and hands the splits to NativeScanner.
 */
object SplitApks {
    private val splitName = Regex("(?i)(^|[/_.-])(split[_.-].*|config\\..*|.*[_.]config\\..*|.*\\.split\\..*)\\.apk$")

    /** A zip of APKs (no manifest and no DEX of its own): .apks, .xapk, .apkm. */
    fun isBundle(f: File): Boolean = try {
        ZipFile(f).use { z ->
            val names = z.entries().asSequence().filter { !it.isDirectory }.map { it.name }.toList()
            names.any { it.endsWith(".apk", true) } && "AndroidManifest.xml" !in names && names.none { it.matches(Regex("classes\\d*\\.dex")) }
        }
    } catch (_: Throwable) { false }

    /** Copies every *.apk of the bundle into [dir] under a flat, unique, safe name (a path inside the zip never reaches the file system); returns the files. */
    fun extractApks(bundle: File, dir: File): List<File> {
        dir.mkdirs()
        val out = ArrayList<File>(); val used = HashSet<String>()
        ZipFile(bundle).use { z ->
            for (e in z.entries().asSequence().filter { !it.isDirectory && it.name.endsWith(".apk", true) }.toList()) {
                var name = e.name.substringAfterLast('/').replace(Regex("[^A-Za-z0-9._-]"), "_").ifEmpty { "x.apk" }
                var n = 1; while (!used.add(name.lowercase())) name = "${n++}_" + e.name.substringAfterLast('/').replace(Regex("[^A-Za-z0-9._-]"), "_")
                val f = File(dir, name)
                z.getInputStream(e).use { i -> f.outputStream().use { o -> i.copyTo(o) } }
                out.add(f)
            }
        }
        return out
    }

    /** Whether this APK is a split of another one: its name says so, or its manifest root carries a `split` attribute, or it has no DEX and a tiny manifest (a config split). */
    fun isSplit(f: File): Boolean {
        if (splitName.containsMatchIn(f.name)) return true
        return try {
            ZipFile(f).use { z ->
                val man = z.getEntry("AndroidManifest.xml") ?: return@use false
                val text = Axml.decode(z.getInputStream(man).use { it.readBytes() })
                if (text != null && Regex("<manifest[^>]*\\ssplit\\s*=").containsMatchIn(text)) return@use true
                val hasDex = z.entries().asSequence().any { it.name.matches(Regex("classes\\d*\\.dex")) }
                !hasDex && man.size < 4096 && z.entries().asSequence().any { it.name.startsWith("lib/") || it.name == "resources.arsc" }
            }
        } catch (_: Throwable) { false }
    }

    /** (the base APK, the splits): the base is the file that is not a split, `base.apk` first, then the one with a DEX. */
    fun partition(files: List<File>): Pair<File?, List<File>> {
        val splits = files.filter { isSplit(it) }; val rest = files - splits.toSet()
        val base = rest.firstOrNull { it.name.equals("base.apk", true) } ?: rest.maxByOrNull { it.length() }
        return base to (files - listOfNotNull(base).toSet())
    }
}
