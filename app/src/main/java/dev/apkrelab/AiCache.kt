package dev.apkrelab

import android.content.Context
import java.io.File
import java.security.MessageDigest

/** Simple file cache for AI answers: key = SHA-256(model + prompt). Saves API calls when the same code is asked twice. */
object AiCache {
    private var dir: File? = null
    private const val MAX_FILES = 300

    fun init(ctx: Context) {
        dir = File(ctx.filesDir, "ai_cache").also { it.mkdirs() }
    }

    fun key(model: String, prompt: String): String {
        val md = MessageDigest.getInstance("SHA-256").digest((model + "\u0000" + prompt).toByteArray(Charsets.UTF_8))
        return md.joinToString("") { "%02x".format(it) }
    }

    fun get(key: String): String? = try {
        val f = File(dir ?: return null, "$key.txt")
        if (f.exists()) {
            // 0.69.2: LRU - a cache hit refreshes the file time, so the eviction in put() deletes the least-recently-used entry instead of the oldest-written one
            f.setLastModified(System.currentTimeMillis())
            f.readText(Charsets.UTF_8).takeIf { it.isNotBlank() }
        } else null
    } catch (_: Throwable) { null }

    fun put(key: String, value: String) {
        try {
            val d = dir ?: return
            File(d, "$key.txt").writeText(value, Charsets.UTF_8)
            val files = d.listFiles() ?: return
            if (files.size > MAX_FILES) {
                files.sortedBy { it.lastModified() }.take(files.size - MAX_FILES).forEach { it.delete() }
            }
        } catch (_: Throwable) { }
    }

    fun remove(key: String) {
        try { File(dir ?: return, "$key.txt").delete() } catch (_: Throwable) { }
    }

    fun count(): Int = dir?.listFiles()?.size ?: 0

    fun clear(): Int {
        val files = dir?.listFiles() ?: return 0
        var n = 0
        for (f in files) if (f.delete()) n++
        return n
    }
}
