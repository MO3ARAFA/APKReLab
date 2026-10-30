package dev.apkrelab

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/** A minimal but valid little-endian ELF shared object for tests (tools/native/ElfSamples.kt writes two of them so that `readelf -W -a` can be run on them; its only complaint is a cosmetic sh_info of 0 on .dynsym). */
object ElfTestBuilder {
    fun build(
        is64: Boolean = true, withStack: Boolean = true, stackExec: Boolean = false, relro: Boolean = true, bindNow: Boolean = true, textrel: Boolean = false,
        imports: List<String> = emptyList(), exports: List<String> = emptyList(), needed: List<String> = emptyList(), soname: String? = "libtest.so",
        runpath: String? = null, align: Long = 0x4000, rodata: List<String> = emptyList()
    ): ByteArray {
        // string table
        val dynstr = ByteArrayOutputStream(); dynstr.write(0)
        fun str(s: String): Int { val o = dynstr.size(); dynstr.write(s.toByteArray(Charsets.ISO_8859_1)); dynstr.write(0); return o }
        val symNames = imports.map { it to str(it) } + exports.map { it to str(it) }
        val neededOffs = needed.map { str(it) }; val sonameOff = soname?.let { str(it) }; val runpathOff = runpath?.let { str(it) }
        val rod = ByteArrayOutputStream(); for (s in rodata) { rod.write(s.toByteArray(Charsets.ISO_8859_1)); rod.write(0) }
        val shstr = ByteArrayOutputStream(); shstr.write(0)
        fun shs(s: String): Int { val o = shstr.size(); shstr.write(s.toByteArray()); shstr.write(0); return o }
        val nDynsym = shs(".dynsym"); val nDynstr = shs(".dynstr"); val nRodata = shs(".rodata"); val nShstr = shs(".shstrtab"); val nDynamic = shs(".dynamic")

        val ehsz = if (is64) 64 else 52; val phsz = if (is64) 56 else 32; val symsz = if (is64) 24 else 16; val dynsz = if (is64) 16 else 8; val shsz = if (is64) 64 else 40
        val nph = 3 + (if (withStack) 1 else 0) + (if (relro) 1 else 0)      // LOAD, LOAD, DYNAMIC (+ GNU_STACK, GNU_RELRO)
        val nsym = 1 + symNames.size
        val dynEntries = ArrayList<Pair<Long, Long>>()
        val offPh = ehsz.toLong(); val offSym = offPh + nph * phsz; val offStr = offSym + nsym * symsz; val offRod = offStr + dynstr.size()
        val offDyn = (offRod + rod.size() + 7) / 8 * 8
        neededOffs.forEach { dynEntries.add(1L to it.toLong()) }
        sonameOff?.let { dynEntries.add(14L to it.toLong()) }; runpathOff?.let { dynEntries.add(29L to it.toLong()) }
        dynEntries.add(5L to offStr); dynEntries.add(6L to offSym); dynEntries.add(10L to dynstr.size().toLong()); dynEntries.add(11L to symsz.toLong())
        if (bindNow) { dynEntries.add(30L to 8L); dynEntries.add(0x6ffffffbL to 1L) }
        if (textrel) dynEntries.add(22L to 0L)
        dynEntries.add(0L to 0L)
        val dynSize = dynEntries.size * dynsz
        val offShstr = offDyn + dynSize; val offSh = (offShstr + shstr.size() + 7) / 8 * 8; val nsh = 6
        val total = (offSh + nsh * shsz).toInt()
        val bb = ByteBuffer.allocate(total).order(ByteOrder.LITTLE_ENDIAN)
        fun w(v: Long, size: Int) { when (size) { 1 -> bb.put(v.toByte()); 2 -> bb.putShort(v.toShort()); 4 -> bb.putInt(v.toInt()); else -> bb.putLong(v) } }
        fun addr(v: Long) = w(v, if (is64) 8 else 4)
        // header
        bb.put(byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), if (is64) 2 else 1, 1, 1, 0)); bb.position(16)
        w(3, 2); w(if (is64) 183 else 40, 2); w(1, 4); addr(0); addr(offPh); addr(offSh); w(0, 4)
        w(ehsz.toLong(), 2); w(phsz.toLong(), 2); w(nph.toLong(), 2); w(shsz.toLong(), 2); w(nsh.toLong(), 2); w(4, 2)       // shstrndx = 4
        // program headers
        fun ph(type: Long, flags: Long, off: Long, size: Long, al: Long) {
            if (is64) { w(type, 4); w(flags, 4); w(off, 8); w(off, 8); w(off, 8); w(size, 8); w(size, 8); w(al, 8) }
            else { w(type, 4); w(off, 4); w(off, 4); w(off, 4); w(size, 4); w(size, 4); w(flags, 4); w(al, 4) }
        }
        bb.position(offPh.toInt())
        ph(1, 5, 0, offDyn, align); ph(1, 6, offDyn, total - offDyn, align); ph(2, 6, offDyn, dynSize.toLong(), 8)
        if (withStack) ph(0x6474e551, if (stackExec) 7 else 6, 0, 0, 16)
        if (relro) ph(0x6474e552, 4, offDyn, dynSize.toLong(), 1)
        // dynsym: null, imports (UND), exports (defined in section 3 = .rodata, global)
        bb.position(offSym.toInt()); repeat(symsz) { bb.put(0) }
        for ((i, p) in symNames.withIndex()) {
            val und = i < imports.size
            val info = 0x12; val shndx = if (und) 0 else 3
            if (is64) { w(p.second.toLong(), 4); w(info.toLong(), 1); w(0, 1); w(shndx.toLong(), 2); w(0, 8); w(0, 8) }
            else { w(p.second.toLong(), 4); w(0, 4); w(0, 4); w(info.toLong(), 1); w(0, 1); w(shndx.toLong(), 2) }
        }
        bb.position(offStr.toInt()); bb.put(dynstr.toByteArray()); bb.put(rod.toByteArray())
        bb.position(offDyn.toInt()); for ((t, v) in dynEntries) { if (is64) { w(t, 8); w(v, 8) } else { w(t, 4); w(v, 4) } }
        bb.position(offShstr.toInt()); bb.put(shstr.toByteArray())
        // section headers: 0 null, 1 .dynsym, 2 .dynstr, 3 .rodata, 4 .shstrtab, 5 .dynamic
        fun sh(name: Int, type: Long, flags: Long, off: Long, size: Long, link: Long, ent: Long) {
            if (is64) { w(name.toLong(), 4); w(type, 4); w(flags, 8); w(off, 8); w(off, 8); w(size, 8); w(link, 4); w(0, 4); w(1, 8); w(ent, 8) }
            else { w(name.toLong(), 4); w(type, 4); w(flags, 4); w(off, 4); w(off, 4); w(size, 4); w(link, 4); w(0, 4); w(1, 4); w(ent, 4) }
        }
        bb.position(offSh.toInt()); repeat(shsz) { bb.put(0) }
        sh(nDynsym, 11, 2, offSym, (nsym * symsz).toLong(), 2, symsz.toLong()); sh(nDynstr, 3, 2, offStr, dynstr.size().toLong(), 0, 0)
        sh(nRodata, 1, 2, offRod, rod.size().toLong(), 0, 0); sh(nShstr, 3, 0, offShstr, shstr.size().toLong(), 0, 0); sh(nDynamic, 6, 3, offDyn, dynSize.toLong(), 2, dynsz.toLong())
        return bb.array()
    }
}
