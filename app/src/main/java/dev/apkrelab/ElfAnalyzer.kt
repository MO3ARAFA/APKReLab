package dev.apkrelab

/**
 * 0.90.0: a reader for the ELF files in an APK's lib/ directory (Android: little-endian ELF32 / ELF64 shared objects). Pure Kotlin on a byte array: program headers (stack
 * executability, RELRO, load alignment), the dynamic section (BIND_NOW, TEXTREL, RPATH / RUNPATH, SONAME, NEEDED) and the dynamic SYMBOL table (imports and exports, from
 * `.dynsym` + `.dynstr`, never a text search of the file), plus the printable strings of the read-only / data sections (not the symbol-name tables).
 * Validated field by field against `readelf -W -h -l -d --dyn-syms` on the real libraries of 37 APKs (tools/native).
 */
object ElfAnalyzer {

    class ElfInfo(
        val is64: Boolean, val machine: Int, val type: Int,
        val gnuStack: Boolean, val stackExecutable: Boolean,
        val relroSegment: Boolean, val bindNow: Boolean, val textrel: Boolean,
        val rpath: String?, val runpath: String?, val soname: String?, val needed: List<String>,
        val imports: List<String>, val exports: Int, val dynsymCount: Int,
        val minLoadAlign: Long, val hasSectionHeaders: Boolean
    ) {
        /** "full" (RELRO segment + BIND_NOW), "partial" (segment only), "none". */
        val relro: String get() = if (!relroSegment) "none" else if (bindNow) "full" else "partial"
        val importSet: Set<String> by lazy { imports.toHashSet() }
        val stackCanary: Boolean get() = "__stack_chk_fail" in importSet || "__stack_chk_guard" in importSet
        val fortified: List<String> get() = imports.filter { it.startsWith("__") && it.endsWith("_chk") && it != "__stack_chk_fail" }
        val dangerous: List<String> get() = imports.filter { it in DANGEROUS }
        /** The 16 KB page-size requirement of Android 15+ (Google Play, apps targeting API 35): every PT_LOAD segment aligned to at least 0x4000 on a 64-bit ABI. */
        val aligned16k: Boolean get() = !is64 || minLoadAlign >= 0x4000
    }

    val DANGEROUS = setOf("gets", "strcpy", "strcat", "sprintf", "vsprintf", "system", "popen", "tmpnam", "tempnam", "mktemp", "getwd", "stpcpy")

    private const val PT_LOAD = 1; private const val PT_DYNAMIC = 2
    private const val PT_GNU_STACK = 0x6474e551; private const val PT_GNU_RELRO = 0x6474e552
    private const val SHT_DYNSYM = 11

    private class Rd(val b: ByteArray) {
        fun u8(o: Long): Int = b[o.toInt()].toInt() and 0xff
        fun u16(o: Long): Int = u8(o) or (u8(o + 1) shl 8)
        fun u32(o: Long): Long = (u8(o).toLong()) or (u8(o + 1).toLong() shl 8) or (u8(o + 2).toLong() shl 16) or (u8(o + 3).toLong() shl 24)
        fun u64(o: Long): Long = u32(o) or (u32(o + 4) shl 32)
        fun ok(o: Long, n: Long) = o >= 0 && n >= 0 && o + n <= b.size
        fun cstr(o: Long, limit: Long = 4096): String? {
            if (o < 0 || o >= b.size) return null
            var e = o.toInt(); val end = minOf(b.size.toLong(), o + limit).toInt()
            while (e < end && b[e].toInt() != 0) e++
            return if (e >= end) null else String(b, o.toInt(), e - o.toInt(), Charsets.ISO_8859_1)
        }
    }

    private class Seg(val type: Long, val flags: Long, val off: Long, val vaddr: Long, val filesz: Long, val memsz: Long, val align: Long)

    fun isElf(b: ByteArray) = b.size > 64 && b[0].toInt() == 0x7f && b[1].toInt() == 'E'.code && b[2].toInt() == 'L'.code && b[3].toInt() == 'F'.code

    /** null when [b] is not a little-endian ELF32 / ELF64 file or is truncated beyond use. */
    fun parse(b: ByteArray): ElfInfo? {
        if (!isElf(b)) return null
        val is64 = b[4].toInt() == 2
        if ((b[4].toInt() != 1 && !is64) || b[5].toInt() != 1) return null
        val r = Rd(b)
        val type = r.u16(16); val machine = r.u16(18)
        val phoff = if (is64) r.u64(32) else r.u32(28)
        val shoff = if (is64) r.u64(40) else r.u32(32)
        val phentsize = r.u16(if (is64) 54 else 42).toLong(); val phnum = r.u16(if (is64) 56 else 44)
        val shentsize = r.u16(if (is64) 58 else 46).toLong(); val shnum = r.u16(if (is64) 60 else 48)
        val segs = ArrayList<Seg>()
        for (i in 0 until phnum) {
            val o = phoff + i * phentsize
            if (!r.ok(o, phentsize) || phentsize < (if (is64) 56 else 32)) break
            segs.add(if (is64) Seg(r.u32(o), r.u32(o + 4), r.u64(o + 8), r.u64(o + 16), r.u64(o + 32), r.u64(o + 40), r.u64(o + 48))
                     else Seg(r.u32(o), r.u32(o + 24), r.u32(o + 4), r.u32(o + 8), r.u32(o + 16), r.u32(o + 20), r.u32(o + 28)))
        }
        val loads = segs.filter { it.type == PT_LOAD.toLong() }
        fun vaToOff(va: Long): Long { for (s in loads) if (va >= s.vaddr && va < s.vaddr + maxOf(s.filesz, 1)) return s.off + (va - s.vaddr); return -1 }
        val stack = segs.firstOrNull { it.type == PT_GNU_STACK.toLong() }
        val relro = segs.any { it.type == PT_GNU_RELRO.toLong() }
        val minAlign = loads.minOfOrNull { it.align } ?: 0L

        // ---- dynamic section
        var bindNow = false; var textrel = false; var rpathOff = -1L; var runpathOff = -1L; var sonameOff = -1L
        var strtab = -1L; var symtab = -1L; var strsz = 0L; var hash = -1L; var gnuHash = -1L; var syment = if (is64) 24L else 16L
        val neededOffs = ArrayList<Long>()
        segs.firstOrNull { it.type == PT_DYNAMIC.toLong() }?.let { d ->
            val esz = if (is64) 16L else 8L
            var o = d.off
            while (r.ok(o, esz) && o < d.off + d.filesz) {
                val tag = if (is64) r.u64(o) else r.u32(o); val v = if (is64) r.u64(o + 8) else r.u32(o + 4)
                when (tag) {
                    0L -> break
                    1L -> neededOffs.add(v); 4L -> hash = v; 5L -> strtab = v; 6L -> symtab = v; 10L -> strsz = v; 11L -> syment = v
                    14L -> sonameOff = v; 15L -> rpathOff = v; 29L -> runpathOff = v
                    22L -> textrel = true; 24L -> bindNow = true
                    30L -> { if (v and 8L != 0L) bindNow = true; if (v and 4L != 0L) textrel = true }
                    0x6ffffffbL -> { if (v and 1L != 0L) bindNow = true }
                    0x6ffffef5L -> gnuHash = v
                }
                o += esz
            }
        }
        val strOff = if (strtab >= 0) vaToOff(strtab) else -1L
        fun dstr(i: Long): String? = if (strOff < 0) null else r.cstr(strOff + i)

        // ---- dynamic symbols: .dynsym by its section header, else the hash tables give the count
        var symOff = if (symtab >= 0) vaToOff(symtab) else -1L
        var count = 0L
        var hasSh = false
        if (shoff > 0 && shentsize >= (if (is64) 64 else 40) && shnum > 0) {
            for (i in 0 until shnum) {
                val o = shoff + i * shentsize
                if (!r.ok(o, shentsize)) break
                hasSh = true
                val sh = r.u32(o + 4)
                if (sh == SHT_DYNSYM.toLong()) {
                    val offs = if (is64) r.u64(o + 24) else r.u32(o + 16); val size = if (is64) r.u64(o + 32) else r.u32(o + 20)
                    val ent = if (is64) r.u64(o + 56) else r.u32(o + 36)
                    if (ent > 0) { symOff = offs; count = size / ent; syment = ent }
                    break
                }
            }
        }
        if (count == 0L && symOff >= 0) {
            if (hash >= 0) { val h = vaToOff(hash); if (h >= 0 && r.ok(h, 8)) count = r.u32(h + 4) }
            else if (gnuHash >= 0) count = gnuSymbolCount(r, vaToOff(gnuHash), is64)
        }
        val imports = ArrayList<String>(); var exports = 0; var total = 0
        if (symOff >= 0 && count > 0 && count < 2_000_000 && syment >= (if (is64) 24 else 16)) {
            for (i in 0 until count) {
                val o = symOff + i * syment
                if (!r.ok(o, syment)) break
                total++
                val nameIdx = r.u32(o)
                val info = if (is64) r.u8(o + 4) else r.u8(o + 12)
                val shndx = if (is64) r.u16(o + 6) else r.u16(o + 14)
                if (nameIdx == 0L) continue
                val name = dstr(nameIdx) ?: continue
                if (shndx == 0) imports.add(name) else if ((info shr 4) != 0) exports++          // defined and not LOCAL
            }
        }
        return ElfInfo(is64, machine, type, stack != null, stack != null && (stack.flags and 1L) != 0L, relro, bindNow, textrel,
            if (rpathOff >= 0) dstr(rpathOff) else null, if (runpathOff >= 0) dstr(runpathOff) else null, if (sonameOff >= 0) dstr(sonameOff) else null,
            neededOffs.mapNotNull { dstr(it) }, imports, exports, total, minAlign, hasSh)
    }

    /** Number of dynamic symbols from DT_GNU_HASH: the highest symbol reachable through the buckets, walked to the end of its chain. */
    private fun gnuSymbolCount(r: Rd, h: Long, is64: Boolean): Long {
        if (h < 0 || !r.ok(h, 16)) return 0
        val nbuckets = r.u32(h); val symoffset = r.u32(h + 4); val bloomSize = r.u32(h + 8)
        val bloomBytes = bloomSize * (if (is64) 8 else 4)
        val buckets = h + 16 + bloomBytes; val chains = buckets + nbuckets * 4
        var max = 0L
        for (i in 0 until nbuckets) { val v = r.u32(buckets + i * 4); if (v > max) max = v }
        if (max < symoffset) return symoffset
        var idx = max
        while (true) {
            val o = chains + (idx - symoffset) * 4
            if (!r.ok(o, 4)) break
            if (r.u32(o) and 1L != 0L) break
            idx++
        }
        return idx + 1
    }

    /**
     * Printable ASCII strings (at least [minLen] long) of the allocated, non-executable data sections (.rodata, .data, .data.rel.ro ...); the symbol and section name tables are left out,
     * so mangled C++ names do not drown the real constants. Without section headers the read-only / data LOAD segments are used. [cb] gets each string.
     */
    fun forEachString(b: ByteArray, minLen: Int = 8, cb: (String) -> Unit) {
        if (!isElf(b)) return
        val is64 = b[4].toInt() == 2; if (b[5].toInt() != 1) return
        val r = Rd(b)
        val ranges = ArrayList<LongArray>()
        val shoff = if (is64) r.u64(40) else r.u32(32)
        val shentsize = r.u16(if (is64) 58 else 46).toLong(); val shnum = r.u16(if (is64) 60 else 48)
        if (shoff > 0 && shnum > 0 && shentsize >= (if (is64) 64 else 40)) {
            for (i in 0 until shnum) {
                val o = shoff + i * shentsize
                if (!r.ok(o, shentsize)) break
                val type = r.u32(o + 4); val flags = if (is64) r.u64(o + 8) else r.u32(o + 8)
                val off = if (is64) r.u64(o + 24) else r.u32(o + 16); val size = if (is64) r.u64(o + 32) else r.u32(o + 20)
                if (type != 1L || flags and 2L == 0L || flags and 4L != 0L) continue                       // PROGBITS, ALLOC, not EXECINSTR
                if (r.ok(off, size) && size > 0) ranges.add(longArrayOf(off, off + size))
            }
        }
        if (ranges.isEmpty()) {
            val phoff = if (is64) r.u64(32) else r.u32(28); val phentsize = r.u16(if (is64) 54 else 42).toLong(); val phnum = r.u16(if (is64) 56 else 44)
            for (i in 0 until phnum) {
                val o = phoff + i * phentsize
                if (!r.ok(o, phentsize)) break
                val type = r.u32(o); val flags = if (is64) r.u32(o + 4) else r.u32(o + 24)
                val off = if (is64) r.u64(o + 8) else r.u32(o + 4); val filesz = if (is64) r.u64(o + 32) else r.u32(o + 16)
                if (type == PT_LOAD.toLong() && flags and 1L == 0L && r.ok(off, filesz)) ranges.add(longArrayOf(off, off + filesz))
            }
        }
        val sb = StringBuilder()
        for (rg in ranges) {
            var i = rg[0].toInt(); val end = rg[1].toInt()
            sb.setLength(0)
            while (i < end) {
                val c = b[i].toInt() and 0xff
                if (c in 0x20..0x7e || c == 9) { if (sb.length < 4096) sb.append(c.toChar()) }
                else { if (sb.length >= minLen) cb(sb.toString()); sb.setLength(0) }
                i++
            }
            if (sb.length >= minLen) cb(sb.toString())
        }
    }
}
