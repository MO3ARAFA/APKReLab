package dev.apkrelab

import java.io.File

/**
 * 0.38.0: pending manifest changes (boolean attributes only: debuggable, allowBackup, usesCleartextTraffic, exported).
 * Stored as text lines `element|attr|component|value` in the workspace (wiped together with it when a new APK is
 * picked) and applied to the binary AndroidManifest.xml at build time by [ManifestPatcher.setBooleans].
 */
object ManifestEdits {
    data class Edit(val element: String, val attr: String, val component: String, val value: Boolean)

    private fun file(ws: File) = File(ws, "manifest_edits.txt")

    fun load(ws: File): List<Edit> {
        val f = file(ws)
        if (!f.exists()) return emptyList()
        val out = ArrayList<Edit>()
        for (line in f.readLines()) {
            val p = line.split("|")
            if (p.size < 4) continue
            out.add(Edit(p[0], p[1], p[2], p[3] == "true"))
        }
        return out
    }

    private fun save(ws: File, list: List<Edit>) {
        val f = file(ws)
        if (list.isEmpty()) { f.delete(); return }
        ws.mkdirs()
        f.writeText(list.joinToString("\n") { it.element + "|" + it.attr + "|" + it.component + "|" + it.value })
    }

    /** Adds [e]; an older edit of the same element / attribute / component is replaced. */
    fun add(ws: File, e: Edit) {
        val l = load(ws).filter { !(it.element == e.element && it.attr == e.attr && it.component == e.component) }
        save(ws, l + e)
    }

    /** 0.38.2: adds several edits at once (same replace rule as [add]). */
    fun addAll(ws: File, list: List<Edit>) {
        var l: List<Edit> = load(ws)
        for (e in list) l = l.filter { !(it.element == e.element && it.attr == e.attr && it.component == e.component) } + e
        save(ws, l)
    }

    fun clear(ws: File) { file(ws).delete() }

    fun describe(e: Edit): String =
        (if (e.component.isEmpty()) e.element else e.component.substringAfterLast('.')) + "  android:" + e.attr + " = " + e.value
}
