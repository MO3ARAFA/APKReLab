package dev.apkrelab

import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.DexFile
import com.android.tools.smali.dexlib2.writer.pool.DexPool
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.io.PrintStream
import java.lang.reflect.InvocationTargetException
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

class BuildError(msg: String) : RuntimeException(msg)

class Rebuilder(private val ws: File, private val log: (String) -> Unit) {

    private val apk = File(ws, "original.apk")
    private val outDir = File(ws, "out")

    /** "classes.dex" -> edited smali files (workspace folder smali/classes/, smali/classes2/, ...) */
    fun editedFiles(): Map<String, List<File>> {
        val root = File(ws, "smali")
        val map = LinkedHashMap<String, List<File>>()
        if (!root.exists()) return map
        for (dir in root.listFiles().orEmpty().sortedBy { it.name }) {
            if (!dir.isDirectory) continue
            val files = dir.walkTopDown().filter { it.isFile && it.name.endsWith(".smali") }.toList()
            if (files.isNotEmpty()) map[dir.name + ".dex"] = files
        }
        return map
    }

    fun signedApk(): File = File(outDir, "signed.apk")

    // ------------------------------------------------------------------ main entry

    fun build(newPackage: String? = null): File {
        if (!apk.exists()) throw BuildError("original.apk not found - pick an APK first")
        outDir.mkdirs()
        val tmp = File(outDir, "tmp")
        tmp.deleteRecursively()
        tmp.mkdirs()
        signedApk().delete()

        try {
        val edited = editedFiles()
        val total = edited.values.sumOf { it.size }
        log("[1/4] Edited classes: $total in ${edited.size} dex file(s)")

        val repl = LinkedHashMap<String, File>()
        for ((dexName, files) in edited) {
            val origDex = File(tmp, "orig_$dexName")
            extract(dexName, origDex)
            val api = apiForDex(origDex)
            log("      $dexName: assembling ${files.size} class(es) (api $api)")
            val patch = File(tmp, "patch_$dexName")
            val err = assemble(files, patch, api)
            if (err != null) throw BuildError("Smali assemble failed:\n$err")
            if (!patch.exists()) throw BuildError("Assembler produced no dex for $dexName")
            val merged = File(tmp, "new_$dexName")
            val count = merge(origDex, patch, merged, api, files.size)
            log("      $dexName: merged OK ($count classes, ${fmt(merged.length())})")
            origDex.delete()
            patch.delete()
            repl[dexName] = merged
        }
        if (total == 0) log("      (no edits - the original code is kept, APK is only re-signed)")

        if (!newPackage.isNullOrEmpty()) {
            // 0.17.0: package rename = patch the binary AndroidManifest.xml (see ManifestPatcher.java)
            val mf = File(tmp, "manifest_new.xml")
            val res = patchManifestOf(apk, mf, newPackage)
            repl["AndroidManifest.xml"] = mf
            log("      package rename: ${res.oldPackage} -> $newPackage (${res.patched} attribute(s) patched)")
            for (n in res.notes.distinct()) log("      $n")
        }

        // 0.38.0: pending manifest edits (boolean attributes), applied after the optional package rename
        val medits = ManifestEdits.load(ws)
        if (medits.isNotEmpty()) {
            val baseBytes = repl["AndroidManifest.xml"]?.readBytes() ?: ZipFile(apk).use { zip ->
                val e = zip.getEntry("AndroidManifest.xml") ?: throw BuildError("AndroidManifest.xml not found in the APK")
                zip.getInputStream(e).use { it.readBytes() }
            }
            val res = try {
                ManifestPatcher.setBooleans(baseBytes, medits.map { ManifestPatcher.BoolEdit(it.element, it.attr, it.component, it.value) })
            } catch (t: java.io.IOException) { throw BuildError("Manifest edit failed: ${t.message}") }
            val mf2 = File(tmp, "manifest_edit.xml")
            mf2.writeBytes(res.data)
            repl["AndroidManifest.xml"] = mf2
            log("      manifest edits: ${medits.size} requested, ${res.patched} attribute(s) changed")
            for (n in res.notes.distinct()) log("      $n")
        }

        log("[2/4] Re-packing APK (resources.arsc kept stored, entries aligned)")
        val unsigned = File(outDir, "unsigned.apk")
        repack(apk, repl, unsigned)
        log("      unsigned.apk ${fmt(unsigned.length())}")

        log("[3/4] Signing (v1 + v2 + v3)")
        sign(unsigned, signedApk())

        log("[4/4] Verifying signature")
        verify(signedApk())

        return signedApk()
        } finally {
            // 0.12.3: always clean temp files, also when the build fails
            File(outDir, "unsigned.apk").delete()
            tmp.deleteRecursively()
        }
    }

    // ------------------------------------------------------------------ package rename (0.17.0)

    /** Reads AndroidManifest.xml from [zipFile], renames the package, writes the new binary XML to [to]. */
    private fun patchManifestOf(zipFile: File, to: File, newPackage: String): ManifestPatcher.Result {
        val bytes = ZipFile(zipFile).use { zip ->
            val e = zip.getEntry("AndroidManifest.xml") ?: throw BuildError("AndroidManifest.xml not found in ${zipFile.name}")
            zip.getInputStream(e).use { it.readBytes() }
        }
        val res = try { ManifestPatcher.renamePackage(bytes, newPackage) }
        catch (t: java.io.IOException) { throw BuildError("Package rename failed (${zipFile.name}): ${t.message}") }
        to.writeBytes(res.data)
        return res
    }

    /** Split APKs: same manifest patch, re-packed unsigned (the caller signs it). */
    fun renameApk(src: File, out: File, newPackage: String) {
        val tmpM = File(out.parentFile, out.name + ".manifest")
        try {
            patchManifestOf(src, tmpM, newPackage)
            repack(src, mapOf("AndroidManifest.xml" to tmpM), out)
        } finally {
            tmpM.delete()
        }
    }

    // ------------------------------------------------------------------ helpers

    private fun extract(name: String, to: File) {
        ZipFile(apk).use { zip ->
            val e = zip.getEntry(name) ?: throw BuildError("$name not found inside the APK")
            zip.getInputStream(e).use { i -> to.outputStream().use { o -> i.copyTo(o) } }
        }
    }

    /** Opcodes API level that matches the dex version of the original file (035 -> 19, 037 -> 24, 038 -> 26, 039 -> 28). */
    private fun apiForDex(f: File): Int {
        val h = ByteArray(8)
        f.inputStream().use { it.read(h) }
        return apiForHeader(h)
    }

    private fun apiForHeader(h: ByteArray): Int {
        val v = String(h, 4, 3, Charsets.US_ASCII).toIntOrNull() ?: 35
        return when {
            v <= 36 -> 19
            v == 37 -> 24
            v == 38 -> 26
            v == 39 -> 28
            else -> 34
        }
    }

    /**
     * 0.31.0: dry run for ONE class text (agent edits): assembles it alone with smali into a temp dex (no merge, no signing, nothing is written to the smali folder).
     * Returns null when it assembles, else the assembler's error text.
     */
    fun dryAssemble(text: String): String? {
        val dir = File(ws, "dryrun")
        dir.deleteRecursively()
        dir.mkdirs()
        try {
            val api = try {
                ZipFile(apk).use { z ->
                    val e = z.getEntry("classes.dex")
                    if (e == null) 28 else {
                        val h = ByteArray(8)
                        z.getInputStream(e).use { it.read(h) }
                        apiForHeader(h)
                    }
                }
            } catch (_: Throwable) { 28 }
            val src = File(dir, "Test.smali")
            src.writeText(text)
            val out = File(dir, "test.dex")
            val err = assemble(listOf(src), out, api)
            return err?.replace(dir.absolutePath + "/", "")
        } finally {
            dir.deleteRecursively()
        }
    }

    /**
     * 0.37.0 (Java view): assembles several smali texts (one class each) into ONE small dex inside [workDir] (created here).
     * Returns the dex file, or null + the assembler's error text. The caller deletes [workDir] when done.
     */
    fun assembleTexts(texts: List<String>, workDir: File): Pair<File?, String?> {
        workDir.deleteRecursively()
        workDir.mkdirs()
        val api = try {
            ZipFile(apk).use { z ->
                val e = z.getEntry("classes.dex")
                if (e == null) 28 else {
                    val h = ByteArray(8)
                    z.getInputStream(e).use { it.read(h) }
                    apiForHeader(h)
                }
            }
        } catch (_: Throwable) { 28 }
        val files = ArrayList<File>()
        for ((i, t) in texts.withIndex()) {
            val f = File(workDir, "C$i.smali")
            f.writeText(t)
            files.add(f)
        }
        val out = File(workDir, "view.dex")
        val err = assemble(files, out, api)
        return if (err == null) Pair(out, null) else Pair(null, err.replace(workDir.absolutePath + "/", ""))
    }

    /** Returns null on success, or the assembler's error text. smali classes are reached by reflection (API not verified at compile time). */
    private fun assemble(files: List<File>, out: File, api: Int): String? {
        val smaliCls = try { Class.forName("com.android.tools.smali.smali.Smali") }
        catch (t: Throwable) { return "smali assembler library missing: $t" }
        val optCls = Class.forName("com.android.tools.smali.smali.SmaliOptions")
        val opts = optCls.getDeclaredConstructor().newInstance()
        try { optCls.getField("apiLevel").setInt(opts, api) } catch (_: Throwable) { }
        optCls.getField("outputDexFile").set(opts, out.absolutePath)
        val paths = files.map { it.absolutePath }

        val errBuf = ByteArrayOutputStream()
        val oldErr = System.err
        System.setErr(PrintStream(errBuf, true, "UTF-8"))
        var ok = false
        var thrown: String? = null
        try {
            val withList = smaliCls.methods.firstOrNull {
                it.name == "assemble" && it.parameterTypes.size == 2 &&
                    it.parameterTypes[0] == optCls && List::class.java.isAssignableFrom(it.parameterTypes[1])
            }
            val withArray = smaliCls.methods.firstOrNull {
                it.name == "assemble" && it.parameterTypes.size == 2 &&
                    it.parameterTypes[0] == optCls && it.parameterTypes[1] == Array<String>::class.java
            }
            ok = when {
                withList != null -> withList.invoke(null, opts, paths) as Boolean
                withArray != null -> withArray.invoke(null, opts, paths.toTypedArray()) as Boolean
                else -> { thrown = "Smali.assemble(...) not found in this smali version"; false }
            }
        } catch (t: InvocationTargetException) {
            thrown = (t.targetException ?: t).let { "${it.javaClass.simpleName}: ${it.message}" }
        } catch (t: Throwable) {
            thrown = "${t.javaClass.simpleName}: ${t.message}"
        } finally {
            System.setErr(oldErr)
        }
        if (ok && out.exists()) return null
        val prefix = File(ws, "smali").absolutePath + "/"
        val text = (errBuf.toString("UTF-8") + (thrown?.let { "\n$it" } ?: "")).replace(prefix, "").trim()
        return text.ifEmpty { "unknown assembler error" }.take(3000)
    }

    /** Replaces the edited ClassDefs inside the original dex and writes a new dex (DexPool). Returns class count. */
    private fun merge(origDex: File, patchDex: File, out: File, api: Int, expectedEdited: Int): Int {
        val ops = Opcodes.forApi(api)
        val orig = DexFileFactory.loadDexFile(origDex, ops)
        val patch = DexFileFactory.loadDexFile(patchDex, ops)
        val repl = HashMap<String, ClassDef>()
        for (c in patch.classes) repl[c.type] = c

        val set = LinkedHashSet<ClassDef>()
        var replaced = 0
        for (c in orig.classes) {
            val r = repl.remove(c.type)
            if (r != null) { set.add(r); replaced++ } else set.add(c)
        }
        if (repl.isNotEmpty()) throw BuildError("Edited class not found in original dex: " + repl.keys.first())
        if (replaced != expectedEdited) log("      warning: replaced $replaced of $expectedEdited edited classes")

        val merged = object : DexFile {
            override fun getClasses(): MutableSet<out ClassDef> = set
            override fun getOpcodes(): Opcodes = ops
        }
        DexPool.writeTo(out.absolutePath, merged)
        if (!out.exists() || out.length() < 100) throw BuildError("Dex writer produced an empty file")
        return DexFileFactory.loadDexFile(out, ops).classes.size
    }

    private class CountingOut(private val o: OutputStream) : OutputStream() {
        var count = 0L
        override fun write(b: Int) { o.write(b); count++ }
        override fun write(b: ByteArray, off: Int, len: Int) { o.write(b, off, len); count += len }
        override fun flush() { o.flush() }
        override fun close() { o.close() }
    }

    private fun isSignatureFile(n: String): Boolean {
        val u = n.uppercase()
        if (!u.startsWith("META-INF/")) return false
        val rest = u.removePrefix("META-INF/")
        if (rest.contains('/')) return false
        return rest == "MANIFEST.MF" || rest.endsWith(".SF") || rest.endsWith(".RSA") ||
            rest.endsWith(".DSA") || rest.endsWith(".EC")
    }

    private fun crcOf(f: File): Long {
        val c = CRC32()
        val buf = ByteArray(65536)
        f.inputStream().use { i ->
            while (true) {
                val n = i.read(buf)
                if (n < 0) break
                c.update(buf, 0, n)
            }
        }
        return c.value
    }

    /** zipalign-style padding field (id 0xD935) of exactly [size] bytes (size >= 4). */
    private fun alignExtra(size: Int): ByteArray {
        val b = ByteArray(size)
        b[0] = 0x35
        b[1] = 0xD9.toByte()
        val data = size - 4
        b[2] = (data and 0xFF).toByte()
        b[3] = ((data shr 8) and 0xFF).toByte()
        return b
    }

    fun repack(src: File, repl: Map<String, File>, out: File) {
        val counter = CountingOut(BufferedOutputStream(FileOutputStream(out), 1 shl 16))
        val zos = ZipOutputStream(counter)
        zos.setLevel(6)
        var written = 0
        var skipped = 0
        var misaligned = 0
        val seen = HashSet<String>()
        ZipFile(src).use { zf ->
            val en = zf.entries()
            while (en.hasMoreElements()) {
                val e = en.nextElement()
                if (e.isDirectory) continue
                val name = e.name
                if (isSignatureFile(name)) { skipped++; continue }
                if (!seen.add(name)) continue
                val replFile = repl[name]
                val stored = e.method == ZipEntry.STORED
                val ne = ZipEntry(name)
                var align = 1
                if (stored) {
                    ne.method = ZipEntry.STORED
                    if (replFile != null) {
                        ne.size = replFile.length()
                        ne.crc = crcOf(replFile)
                    } else {
                        ne.size = e.size
                        ne.crc = e.crc
                    }
                    ne.compressedSize = ne.size
                    align = if (name.endsWith(".so")) 16384 else 4
                    val base = counter.count + 30 + name.toByteArray(Charsets.UTF_8).size
                    val rem = (base % align).toInt()
                    var pad = if (rem == 0) 0 else align - rem
                    if (pad in 1..3) pad += align
                    if (pad > 0) ne.extra = alignExtra(pad)
                } else {
                    ne.method = ZipEntry.DEFLATED
                }
                zos.putNextEntry(ne)
                if (stored && counter.count % align != 0L) misaligned++
                val input = replFile?.inputStream() ?: zf.getInputStream(e)
                input.use { it.copyTo(zos) }
                zos.closeEntry()
                written++
            }
        }
        zos.finish()
        zos.close()
        for (name in repl.keys) if (name !in seen) throw BuildError("$name was not found in the APK")
        log("      entries: $written, old signature files removed: $skipped" +
            if (misaligned > 0) ", WARNING misaligned: $misaligned" else ", alignment OK")
    }

    /** minSdk > 0 forces apksig's minSdk (needed for split APKs, which have no uses-sdk: apksig would otherwise ask for SHA-1, which the Keystore key does not allow). */
    fun sign(unsigned: File, signed: File, minSdk: Int = 0) {
        val (pk, cert) = SigningKey.load()
        val fp = SigningKey.fingerprint()
        if (fp != null) log("      key SHA-256: ${fp.take(23)}...")
        val cfg = ApkSigner.SignerConfig.Builder("RELAB", pk, listOf(cert)).build()
        val b = ApkSigner.Builder(listOf(cfg))
            .setInputApk(unsigned)
            .setOutputApk(signed)
            .setCreatedBy("APK ReLab")
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(true)
            .setV4SigningEnabled(false)
        if (minSdk > 0) b.setMinSdkVersion(minSdk)
        b.build().sign()
        log("      signed.apk ${fmt(signed.length())}")
    }

    private fun verify(signed: File) {
        try {
            val r = ApkVerifier.Builder(signed).build().verify()
            if (r.isVerified) {
                log("      OK (v1=${r.isVerifiedUsingV1Scheme}, v2=${r.isVerifiedUsingV2Scheme}, v3=${r.isVerifiedUsingV3Scheme})")
            } else {
                throw BuildError("Signature verification failed: " + r.errors.joinToString("; "))
            }
        } catch (e: BuildError) {
            throw e
        } catch (t: Throwable) {
            log("      (verify skipped: ${t.javaClass.simpleName}: ${t.message})")
        }
    }

    private fun fmt(bytes: Long): String = when {
        bytes >= 1024 * 1024 -> String.format(java.util.Locale.US, "%.1f MB", bytes / 1048576.0)
        bytes >= 1024 -> String.format(java.util.Locale.US, "%.1f KB", bytes / 1024.0)
        else -> "$bytes B"
    }
}
