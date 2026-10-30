package dev.apkrelab

import android.content.ContentResolver
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Canvas
import android.graphics.Color
import android.net.Uri
import android.provider.OpenableColumns
import android.util.Base64
import java.io.ByteArrayOutputStream

/**
 * 0.37.5: one file the user attached in the AI Hub chat.
 * Exactly one of [media] (image / PDF, sent to Gemini as inline data) or [text] (a text / code file, pasted into the prompt) is set.
 */
class Attach(val name: String, val kind: String, val media: Media?, val text: String?, val note: String, val sizeLabel: String, val thumb: Bitmap? = null) {
    /** 0.37.8: true when the file stays attached for the follow-up questions (it is sent again with the next message until the user removes it). */
    var kept = false
}

object Attachments {
    const val MAX_FILES = 5
    const val MAX_TEXT_PER_FILE = 40_000          // chars; Groq's free limit (24k chars per prompt) is skipped automatically when the prompt is bigger
    const val MAX_TEXT_TOTAL = 80_000
    const val MAX_MEDIA_TOTAL = 12_000_000        // base64 chars of all images + PDFs together (Gemini inline limit is ~20 MB per request)
    private const val MAX_PDF_BYTES = 8_000_000
    private const val MAX_TEXT_BYTES = 400_000    // never read more than this from a text file
    private const val MAX_SIDE = 1600             // images are scaled down so that the longest side is at most this (code screenshots stay readable)

    private val textExt = setOf(
        "txt", "md", "json", "xml", "smali", "java", "kt", "kts", "js", "ts", "html", "htm", "css", "log", "csv", "tsv",
        "yml", "yaml", "properties", "gradle", "sh", "py", "c", "cc", "cpp", "h", "hpp", "sql", "ini", "cfg", "conf",
        "pro", "toml", "rules", "diff", "patch", "swift", "go", "rs", "php", "rb"
    )

    private fun displayName(cr: ContentResolver, uri: Uri): String {
        try {
            cr.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
                if (c.moveToFirst()) {
                    val n = c.getString(0)
                    if (!n.isNullOrBlank()) return n
                }
            }
        } catch (_: Throwable) { }
        return uri.lastPathSegment?.substringAfterLast('/') ?: "file"
    }

    private fun sizeLabel(bytes: Long): String =
        if (bytes >= 1_000_000) String.format(java.util.Locale.US, "%.1f MB", bytes / 1_000_000.0) else (bytes / 1000).coerceAtLeast(1).toString() + " KB"

    /** Blocking (decodes images): run it on a background thread. Returns (attachment, "") or (null, readable error). */
    fun load(cr: ContentResolver, uri: Uri): Pair<Attach?, String> {
        val name = displayName(cr, uri)
        val ext = name.substringAfterLast('.', "").lowercase()
        var mime = (cr.getType(uri) ?: "").lowercase()
        if (mime.isEmpty() || mime == "application/octet-stream") {
            mime = when {
                ext in setOf("jpg", "jpeg") -> "image/jpeg"
                ext == "png" -> "image/png"
                ext == "webp" -> "image/webp"
                ext == "pdf" -> "application/pdf"
                else -> mime
            }
        }
        return try {
            when {
                mime.startsWith("image/") -> loadImage(cr, uri, name)
                mime == "application/pdf" -> loadPdf(cr, uri, name)
                mime.startsWith("text/") || ext in textExt || mime == "application/json" || mime == "application/xml" ||
                    mime == "application/javascript" || mime == "application/x-sh" -> loadText(cr, uri, name)
                else -> null to "$name: this file type is not supported (use an image, a PDF or a text / code file)"
            }
        } catch (t: OutOfMemoryError) {
            null to "$name: too big to read on this device"
        } catch (t: Throwable) {
            null to "$name: could not read (" + (t.message ?: t.javaClass.simpleName).take(80) + ")"
        }
    }

    private fun loadImage(cr: ContentResolver, uri: Uri, name: String): Pair<Attach?, String> {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        cr.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null to "$name: not a readable image"
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / (sample * 2) >= MAX_SIDE) sample *= 2
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        val decoded = cr.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) }
            ?: return null to "$name: not a readable image"
        var bmp = decoded
        val longest = maxOf(bmp.width, bmp.height)
        if (longest > MAX_SIDE) {
            val k = MAX_SIDE.toFloat() / longest
            val scaled = Bitmap.createScaledBitmap(bmp, (bmp.width * k).toInt().coerceAtLeast(1), (bmp.height * k).toInt().coerceAtLeast(1), true)
            if (scaled !== bmp) { bmp.recycle(); bmp = scaled }
        }
        // PNG screenshots may have transparency: JPEG would turn it black, so paint on white first
        val flat = Bitmap.createBitmap(bmp.width, bmp.height, Bitmap.Config.ARGB_8888)
        Canvas(flat).apply { drawColor(Color.WHITE); drawBitmap(bmp, 0f, 0f, null) }
        bmp.recycle()
        val out = ByteArrayOutputStream()
        flat.compress(Bitmap.CompressFormat.JPEG, 88, out)
        val w = flat.width
        val h = flat.height
        val tk = 160f / maxOf(w, h)      // 0.37.8: small thumbnail for the chat bubble
        val thumb = Bitmap.createScaledBitmap(flat, (w * tk).toInt().coerceAtLeast(1), (h * tk).toInt().coerceAtLeast(1), true)
        if (thumb !== flat) flat.recycle()
        val bytes = out.toByteArray()
        val m = Media(name, "image/jpeg", Base64.encodeToString(bytes, Base64.NO_WRAP))
        return Attach(name, "image", m, null, "image ${w}x$h", sizeLabel(bytes.size.toLong()), thumb) to ""
    }

    private fun loadPdf(cr: ContentResolver, uri: Uri, name: String): Pair<Attach?, String> {
        val buf = ByteArrayOutputStream()
        cr.openInputStream(uri)?.use { ins ->
            val chunk = ByteArray(64 * 1024)
            while (true) {
                val n = ins.read(chunk)
                if (n < 0) break
                buf.write(chunk, 0, n)
                if (buf.size() > MAX_PDF_BYTES) return null to "$name: PDF is bigger than 8 MB"
            }
        } ?: return null to "$name: could not open"
        val bytes = buf.toByteArray()
        if (bytes.size < 5 || String(bytes, 0, 4, Charsets.ISO_8859_1) != "%PDF") return null to "$name: not a valid PDF"
        val m = Media(name, "application/pdf", Base64.encodeToString(bytes, Base64.NO_WRAP))
        return Attach(name, "pdf", m, null, "PDF", sizeLabel(bytes.size.toLong())) to ""
    }

    private fun loadText(cr: ContentResolver, uri: Uri, name: String): Pair<Attach?, String> {
        val buf = ByteArrayOutputStream()
        var cut = false
        cr.openInputStream(uri)?.use { ins ->
            val chunk = ByteArray(32 * 1024)
            while (true) {
                val n = ins.read(chunk)
                if (n < 0) break
                val room = MAX_TEXT_BYTES - buf.size()
                if (n >= room) { buf.write(chunk, 0, room); cut = true; break }
                buf.write(chunk, 0, n)
            }
        } ?: return null to "$name: could not open"
        val bytes = buf.toByteArray()
        for (i in 0 until minOf(bytes.size, 4000)) if (bytes[i].toInt() == 0) return null to "$name: looks like a binary file, not text"
        var text = String(bytes, Charsets.UTF_8)
        if (text.length > MAX_TEXT_PER_FILE) { text = text.take(MAX_TEXT_PER_FILE); cut = true }
        if (text.isBlank()) return null to "$name: the file is empty"
        val note = if (cut) "text, shortened to the first ${text.length} chars" else "text, ${text.length} chars"
        return Attach(name, "text", null, text, note, sizeLabel(bytes.size.toLong())) to ""
    }

    /** The text files as one block for the prompt (fenced with their names; the prompt tells the model it is data, not instructions). */
    fun textBlock(list: List<Attach>): String {
        val sb = StringBuilder()
        var left = MAX_TEXT_TOTAL
        for (a in list) {
            val t = a.text ?: continue
            if (left <= 0) { sb.append("--- ").append(a.name).append(": skipped (attached text limit reached) ---\n"); continue }
            val part = if (t.length > left) t.take(left) + "\n...(shortened)" else t
            left -= part.length
            sb.append("--- FILE: ").append(a.name).append(" (").append(a.note).append(") ---\n").append(part).append("\n--- END OF ").append(a.name).append(" ---\n\n")
        }
        return sb.toString().trim()
    }

    fun mediaList(list: List<Attach>): List<Media> = list.mapNotNull { it.media }
}
