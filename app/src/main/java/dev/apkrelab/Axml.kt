package dev.apkrelab

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 0.34.1: minimal Android binary XML (AXML) to text decoder with no library, used for res XML files
 * (the ARSCLib based decoder failed on all 698 resource files of the AndroGoat APK).
 * Output is plain XML-like text: one tag per line, attributes as name="value".
 * Resource references print as @0x7f..., enum/flag values print as hex numbers (e.g. inputType 0x81).
 */
object Axml {

    private val knownAttrs = mapOf(
        0x010100d0 to "id", 0x01010220 to "inputType", 0x01010150 to "hint", 0x0101014f to "text",
        0x010103d1 to "usesCleartextTraffic", 0x01010027 to "scheme", 0x01010028 to "host",
        0x010102c4 to "filterTouchesWhenObscured", 0x0101020c to "minSdkVersion"   // 0.75.0: names may be stripped from the pool by shrinkers
    )

    fun decode(b: ByteArray): String? {
        try {
            if (b.size < 16) return null
            val bb = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN)
            if ((bb.getShort(0).toInt() and 0xFFFF) != 0x0003) return null
            val total = minOf(bb.getInt(4), b.size)
            var pos = bb.getShort(2).toInt() and 0xFFFF
            var strings: List<String> = emptyList()
            val resIds = ArrayList<Int>()
            val prefixes = HashMap<Int, String>()
            val sb = StringBuilder()
            var depth = 0
            while (pos + 8 <= total) {
                val type = bb.getShort(pos).toInt() and 0xFFFF
                val hdr = bb.getShort(pos + 2).toInt() and 0xFFFF
                val size = bb.getInt(pos + 4)
                if (size < 8 || pos + size > b.size) break
                if (type == 0x0001) {
                    strings = readPool(bb, pos)
                } else if (type == 0x0180) {
                    val n = (size - hdr) / 4
                    for (i in 0 until n) resIds.add(bb.getInt(pos + hdr + i * 4))
                } else if (type == 0x0100) {
                    prefixes[bb.getInt(pos + 20)] = str(strings, bb.getInt(pos + 16))
                } else if (type == 0x0102) {
                    val ext = pos + 16
                    val name = bb.getInt(ext + 4)
                    val attrStart = bb.getShort(ext + 8).toInt() and 0xFFFF
                    val attrSize = bb.getShort(ext + 10).toInt() and 0xFFFF
                    val attrCount = bb.getShort(ext + 12).toInt() and 0xFFFF
                    sb.append("  ".repeat(depth)).append('<').append(str(strings, name))
                    for (i in 0 until attrCount) {
                        val a = ext + attrStart + i * attrSize
                        val ns = bb.getInt(a)
                        val an = bb.getInt(a + 4)
                        val raw = bb.getInt(a + 8)
                        val vtype = bb.get(a + 15).toInt() and 0xFF
                        val vdata = bb.getInt(a + 16)
                        var aname = str(strings, an)
                        if (aname.isEmpty() && an >= 0 && an < resIds.size) aname = knownAttrs[resIds[an]] ?: ("attr_" + Integer.toHexString(resIds[an]))
                        val pre = if (ns == -1) "" else {
                            val uri = str(strings, ns)
                            if (uri == "http://schemas.android.com/apk/res/android") "android:" else ((prefixes[ns] ?: "ns") + ":")
                        }
                        val value = if (raw != -1) str(strings, raw) else when (vtype) {
                            0x03 -> str(strings, vdata)
                            0x01 -> "@0x" + Integer.toHexString(vdata)
                            0x02 -> "?0x" + Integer.toHexString(vdata)
                            0x10 -> vdata.toString()
                            0x12 -> if (vdata != 0) "true" else "false"
                            0x04 -> java.lang.Float.intBitsToFloat(vdata).toString()
                            else -> "0x" + Integer.toHexString(vdata)
                        }
                        sb.append(' ').append(pre).append(aname).append("=\"").append(esc(value)).append('"')
                    }
                    sb.append(">\n")
                    depth++
                } else if (type == 0x0104) {
                    // 0.43.0: text node (CDATA). Needed for <domain>host</domain> and <pin>digest</pin> in network_security_config.xml;
                    // blank text (indentation) is dropped. Nothing else in the decoded output changes.
                    val t = str(strings, bb.getInt(pos + 16)).trim()
                    if (t.isNotEmpty()) sb.append("  ".repeat(depth)).append(esc(t)).append('\n')
                } else if (type == 0x0103) {
                    if (depth > 0) depth--
                    sb.append("  ".repeat(depth)).append("</").append(str(strings, bb.getInt(pos + 20))).append(">\n")
                }
                pos += size
            }
            return if (sb.isEmpty()) null else sb.toString()
        } catch (_: Throwable) {
            return null
        }
    }

    private fun esc(s: String): String = s.replace("&", "&amp;").replace("\"", "&quot;").replace("<", "&lt;")

    private fun str(list: List<String>, i: Int): String = if (i >= 0 && i < list.size) list[i] else ""

    private fun readPool(bb: ByteBuffer, pos: Int): List<String> {
        val count = bb.getInt(pos + 8)
        val flags = bb.getInt(pos + 16)
        val start = bb.getInt(pos + 20)
        val hdr = bb.getShort(pos + 2).toInt() and 0xFFFF
        val utf8 = (flags and 0x100) != 0
        val out = ArrayList<String>(count)
        for (i in 0 until count) {
            var p = pos + start + bb.getInt(pos + hdr + i * 4)
            if (utf8) {
                var l = bb.get(p).toInt() and 0xFF
                p++
                if ((l and 0x80) != 0) { l = ((l and 0x7F) shl 8) or (bb.get(p).toInt() and 0xFF); p++ }
                var bl = bb.get(p).toInt() and 0xFF
                p++
                if ((bl and 0x80) != 0) { bl = ((bl and 0x7F) shl 8) or (bb.get(p).toInt() and 0xFF); p++ }
                val arr = ByteArray(bl)
                for (k in 0 until bl) arr[k] = bb.get(p + k)
                out.add(String(arr, Charsets.UTF_8))
            } else {
                var l = bb.getShort(p).toInt() and 0xFFFF
                p += 2
                if ((l and 0x8000) != 0) { l = ((l and 0x7FFF) shl 16) or (bb.getShort(p).toInt() and 0xFFFF); p += 2 }
                val cs = StringBuilder()
                for (k in 0 until l) cs.append((bb.getShort(p + k * 2).toInt() and 0xFFFF).toChar())
                out.add(cs.toString())
            }
        }
        return out
    }
}
