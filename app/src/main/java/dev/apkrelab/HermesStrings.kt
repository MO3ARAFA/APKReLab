package dev.apkrelab

/**
 * 0.104.0: the string table of a Hermes bytecode file (the compiled JavaScript of a React Native app, `assets/index.android.bundle`). Only the TABLE is read, no function is decoded:
 * enough for the secret formats, URLs and endpoints that the JavaScript layer holds as string constants.
 *
 * The layout is the one of Hermes' own `BytecodeFileFormat.h` / `BytecodeSerializer` (bytecode version 96, checked against its source and against real bundles): a 128-byte header
 * (magic, version, source hash, file length, ... counts ..., options, padding), then, each section aligned to 4 bytes: the function headers (16 bytes each), the string kinds (4),
 * the identifier hashes (4), the small string table (4 bytes: isUTF16:1, offset:23, length:8; length 255 = the entry is in the overflow table), the overflow table (offset, length: 8)
 * and the string storage (the bytes; a UTF-16 string's length counts 16-bit units, its offset counts bytes).
 *
 * Only version 96 is read: other versions move header fields, and a wrong guess would print garbage as strings. A file that is not self-consistent (length, sections beyond the end,
 * an entry outside the storage) returns null: nothing is guessed, nothing throws.
 */
object HermesStrings {
    const val SUPPORTED_VERSION = 96
    private const val HEADER = 128
    private const val FUNC_HEADER = 16

    class Result(val version: Int, val total: Int, val strings: List<String>)

    private fun u32(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 255) or ((b[o + 1].toLong() and 255) shl 8) or ((b[o + 2].toLong() and 255) shl 16) or ((b[o + 3].toLong() and 255) shl 24)

    private fun align4(x: Long) = (x + 3) and 3L.inv()

    /** The version of a Hermes bytecode file, or null when [b] does not start with its magic. */
    fun version(b: ByteArray): Int? {
        if (b.size < 12) return null
        val magic = byteArrayOf(0xC6.toByte(), 0x1F, 0xBC.toByte(), 0x03, 0xC1.toByte(), 0x03, 0x19, 0x1F)
        for (i in 0 until 8) if (b[i] != magic[i]) return null
        return u32(b, 8).toInt()
    }

    /**
     * 0.104.1: how many bytes from the start of the file hold the header, the tables and the whole string storage (the function bytecode comes after them), from the 128-byte header
     * alone; null when [head] is not a version-96 header or the sections do not fit in [fileSize]. A big bundle is read only up to there instead of being skipped.
     */
    fun prefixNeeded(head: ByteArray, fileSize: Long): Long? {
        val v = version(head) ?: return null
        if (v != SUPPORTED_VERSION || head.size < HEADER) return null
        if (u32(head, 32) != fileSize) return null
        val functionCount = u32(head, 40); val stringKindCount = u32(head, 44); val identifierCount = u32(head, 48)
        val stringCount = u32(head, 52); val overflowCount = u32(head, 56); val storageSize = u32(head, 60)
        var off = align4(HEADER.toLong())
        off = align4(off + functionCount * FUNC_HEADER)
        off = align4(off + stringKindCount * 4)
        off = align4(off + identifierCount * 4)
        off = align4(off + stringCount * 4)
        off = align4(off + overflowCount * 8)
        val end = off + storageSize
        return if (end <= fileSize) end else null
    }

    /** Up to [max] strings of at most [maxLen] characters (longer ones are cut), in table order; null when the file is not a consistent version-96 file. */
    fun read(b: ByteArray, max: Int = 400_000, maxLen: Int = 2000): Result? = read(b, b.size.toLong(), max, maxLen)

    /** The same for the first bytes [b] of a file of [fileSize] bytes: [b] must reach the end of the string storage (see [prefixNeeded]). */
    fun read(b: ByteArray, fileSize: Long, max: Int = 400_000, maxLen: Int = 2000): Result? {
        val v = version(b) ?: return null
        if (v != SUPPORTED_VERSION || b.size < HEADER || fileSize < HEADER + 20) return null
        val fileLength = u32(b, 32)
        if (fileLength != fileSize) return null                                  // the header's own length must be the file's
        val functionCount = u32(b, 40); val stringKindCount = u32(b, 44); val identifierCount = u32(b, 48)
        val stringCount = u32(b, 52); val overflowCount = u32(b, 56); val storageSize = u32(b, 60)
        if (functionCount > fileLength / FUNC_HEADER || stringCount > fileLength || overflowCount > stringCount || stringKindCount > fileLength || identifierCount > fileLength) return null
        var off = align4(HEADER.toLong())
        off = align4(off + functionCount * FUNC_HEADER)
        off = align4(off + stringKindCount * 4)
        off = align4(off + identifierCount * 4)
        val smallAt = off
        off = align4(off + stringCount * 4)
        val overflowAt = off
        off = align4(off + overflowCount * 8)
        val storageAt = off
        if (storageAt + storageSize > fileLength || storageAt + storageSize > b.size) return null
        val out = ArrayList<String>(minOf(stringCount, max.toLong()).toInt())
        for (i in 0 until minOf(stringCount, max.toLong()).toInt()) {
            val e = u32(b, (smallAt + 4L * i).toInt())
            val utf16 = (e and 1L) != 0L
            var offset = (e shr 1) and 0x7FFFFFL
            var length = (e shr 24) and 0xFFL
            if (length == 255L) {                                              // overflow: the real offset (into the overflow table) is in `offset`
                if (offset >= overflowCount) return null
                val oe = (overflowAt + 8 * offset).toInt()
                offset = u32(b, oe); length = u32(b, oe + 4)
            }
            val bytes = if (utf16) length * 2 else length
            if (offset + bytes > storageSize) return null
            val n = minOf(length, maxLen.toLong()).toInt()
            val at = (storageAt + offset).toInt()
            out.add(if (utf16) String(b, at, n * 2, Charsets.UTF_16LE) else String(b, at, n, Charsets.ISO_8859_1))
        }
        return Result(v, stringCount.toInt(), out)
    }
}
