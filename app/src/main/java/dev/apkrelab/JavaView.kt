package dev.apkrelab

import java.io.File
import java.lang.reflect.InvocationTargetException

/**
 * 0.37.0: Java view through jadx, ONE class (plus its inner classes) at a time.
 * jadx is reached by reflection so a different jadx version can never break the compile; any problem comes back as a readable message.
 * The input is a small dex assembled from the class smali (see Rebuilder.assembleTexts), never the whole APK: that keeps memory low on a phone.
 */
object JavaView {
    /** Above this much smali (all classes of the group together) the Java view is refused: jadx would be too slow / too big for a phone. */
    const val MAX_SMALI_CHARS = 350_000
    const val TIMEOUT_MS = 45_000L

    fun available(): Boolean = try { Class.forName("jadx.api.JadxDecompiler"); true } catch (_: Throwable) { false }

    /** Blocking. Decompiles [origName] (dotted, e.g. com.x.Foo) from [dex]. Throws IllegalStateException with a readable message. */
    fun decompile(dex: File, origName: String, timeoutMs: Long = TIMEOUT_MS): String {
        var result: String? = null
        var failure: Throwable? = null
        // jadx recurses deeply on big methods: give it a big stack instead of crashing the app
        val worker = Thread(null, Runnable {
            try { result = run(dex, origName) } catch (e: Throwable) { failure = e }
        }, "jadx", 32L * 1024 * 1024)
        worker.isDaemon = true
        worker.start()
        worker.join(timeoutMs)
        if (worker.isAlive) {
            worker.interrupt()
            throw IllegalStateException("jadx did not finish in ${timeoutMs / 1000} s (the class is too complex). Use the Smali view for this one.")
        }
        val f = failure
        if (f != null) {
            val real = if (f is InvocationTargetException) (f.targetException ?: f) else f
            when (real) {
                is StackOverflowError -> throw IllegalStateException("jadx ran out of stack on this class (very deep code). Use the Smali view.")
                is OutOfMemoryError -> throw IllegalStateException("jadx ran out of memory on this class. Use the Smali view.")
                is IllegalStateException -> throw real
                else -> throw IllegalStateException("jadx failed: " + real.javaClass.simpleName + ": " + (real.message ?: "").take(300))
            }
        }
        return result ?: throw IllegalStateException("jadx returned nothing")
    }

    private fun run(dex: File, origName: String): String {
        val argsCls = Class.forName("jadx.api.JadxArgs")
        val args = argsCls.getConstructor().newInstance()
        fun set(name: String, v: Any?) {
            val m = argsCls.methods.firstOrNull { it.name == name && it.parameterTypes.size == 1 } ?: return
            try { m.invoke(args, v) } catch (_: Throwable) { }
        }
        if (argsCls.methods.any { it.name == "setInputFiles" }) set("setInputFiles", listOf(dex)) else set("setInputFile", dex)
        set("setSkipResources", true)          // only code is needed
        set("setThreadsCount", 1)              // one class: no thread pool, lowest memory
        set("setShowInconsistentCode", true)   // show partial code instead of failing
        set("setDeobfuscationOn", false)       // keep the names the app really uses
        val decCls = Class.forName("jadx.api.JadxDecompiler")
        val dec = decCls.getConstructor(argsCls).newInstance(args)
        try {
            decCls.getMethod("load").invoke(dec)
            var jc: Any? = null
            val search = decCls.methods.firstOrNull { it.name == "searchJavaClassByOrigClassName" && it.parameterTypes.size == 1 }
            if (search != null) jc = search.invoke(dec, origName)
            if (jc == null) {
                val list = decCls.getMethod("getClasses").invoke(dec) as? List<*> ?: emptyList<Any>()
                for (c in list) {
                    if (c == null) continue
                    val n = try { c.javaClass.getMethod("getFullName").invoke(c) as? String } catch (_: Throwable) { null }
                    if (n == origName) { jc = c; break }
                }
            }
            val cls = jc ?: throw IllegalStateException("jadx did not find the class $origName in the small dex")
            val code = cls.javaClass.getMethod("getCode").invoke(cls) as? String
            if (code.isNullOrBlank()) throw IllegalStateException("jadx produced no code for $origName")
            return code
        } finally {
            try { (dec as? java.io.Closeable)?.close() } catch (_: Throwable) { }
        }
    }
}
