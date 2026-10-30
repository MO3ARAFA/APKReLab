package dev.apkrelab

import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * 0.85.1: attribute names for a binary manifest whose string pool has no attribute names (resource-name shrinking).
 * The ids below were read from AOSP public-final.xml, NOT from the 0.85.0 table (which had a wrong entry and was missing these).
 */
class AxmlStrippedNamesTest {

    @Test fun theNamesTheManifestRulesSearchForAreKnown() {
        assertEquals("autoVerify", Axml.fallbackName(0x010104ee))
        assertEquals("testOnly", Axml.fallbackName(0x01010272))
        assertEquals("requestLegacyExternalStorage", Axml.fallbackName(0x01010603))
        assertEquals("fullBackupContent", Axml.fallbackName(0x010104eb))
        assertEquals("dataExtractionRules", Axml.fallbackName(0x0101063e))
        assertEquals("roundIcon", Axml.fallbackName(0x0101052c))
        assertEquals("usesCleartextTraffic", Axml.fallbackName(0x010104ec))
        assertEquals("networkSecurityConfig", Axml.fallbackName(0x01010527))
        assertEquals("allowBackup", Axml.fallbackName(0x01010280))
        assertEquals("debuggable", Axml.fallbackName(0x0101000f))
    }

    @Test fun theUnknownAttributesOfInstaPayAreNotSecurityOnes() {
        assertEquals("resizeableActivity", Axml.fallbackName(0x010104f6))
        assertEquals("supportsRtl", Axml.fallbackName(0x010103af))
    }

    @Test fun anIdThatWasMappedToCleartextByMistakeIsNoLongerThat() {                  // 0.85.0 had 0x010103d1 -> usesCleartextTraffic
        assertEquals("indicatorStart", Axml.fallbackName(0x010103d1))
    }

    @Test fun nonFrameworkIdsStayUnnamed() {
        assertNull(Axml.fallbackName(0x7f010001))
        assertNull(Axml.fallbackName(0x0101ffff))
        assertTrue(AxmlAttrIds.names.size > 1500)
    }

    @Test fun aManifestWithoutAttributeNamesDecodesToAndroidNames() {
        val xml = Axml.decode(strippedManifest())!!
        assertTrue(xml, xml.contains("android:name=\".Deep\""))
        assertTrue(xml, xml.contains("android:autoVerify=\"true\""))
        assertTrue(xml, xml.contains("android:testOnly=\"true\""))
        assertTrue(xml, xml.contains("android:scheme=\"https\""))
        assertFalse(xml, xml.contains("attr_"))
    }

    @Test fun theRulesSeeAutoVerifyAndTestOnlyOnAStrippedManifest() {
        val ctx = ManifestContext(Axml.decode(strippedManifest())!!)
        val links = ManifestDeepLinksRule.scan(ctx)
        assertEquals(1, links.size)
        assertEquals(Severity.INFO, links[0].severity)                                  // verified App Link: no "No android:autoVerify" LOW card
        assertFalse(links[0].detail.contains("No android:autoVerify"))
        assertEquals(1, ManifestTestOnlyRule.scan(ctx).size)
    }

    @Test fun theSameManifestWithoutAutoVerifyStillGetsTheLowCard() {                   // negative twin
        val ctx = ManifestContext(Axml.decode(strippedManifest(autoVerify = false))!!)
        val links = ManifestDeepLinksRule.scan(ctx)
        assertEquals(1, links.size)
        assertEquals(Severity.LOW, links[0].severity)
        assertTrue(links[0].detail.contains("No android:autoVerify"))
    }

    /**
     * A synthetic binary manifest like InstaPay's: every attribute name in the string pool is "" and the resource map gives the framework id of
     * the pool index. <manifest><application testOnly=true><activity name=".Deep" exported=true><intent-filter><data scheme=https host=x.com autoVerify>
     */
    private fun strippedManifest(autoVerify: Boolean = true): ByteArray {
        // pool: 0..4 are attribute names (empty), 5.. are real strings
        val ids = intArrayOf(0x01010003, 0x01010010, 0x010104ee, 0x01010272, 0x01010027)   // name, exported, autoVerify, testOnly, scheme
        val strings = listOf("", "", "", "", "", "manifest", "application", "activity", "intent-filter", "data",
            "http://schemas.android.com/apk/res/android", "android", ".Deep", "https", "com.x", "host", "x.com", "category",
            "android.intent.category.BROWSABLE")
        val pool = pool(strings)
        val resMap = chunk(0x0180, 8, ByteArrayOutputStream().also { o -> for (i in ids) o.write(le(i)) }.toByteArray())
        val out = ByteArrayOutputStream()
        out.write(pool); out.write(resMap)
        out.write(startNs(prefix = 11, uri = 10))
        out.write(startEl(5, emptyList()))
        out.write(startEl(6, listOf(attr(10, 3, boolean = true))))                      // testOnly (pool index 3 -> id 0x01010272)
        out.write(startEl(7, listOf(attr(10, 0, str = 12), attr(10, 1, boolean = true))))   // name, exported
        out.write(startEl(8, if (autoVerify) listOf(attr(10, 2, boolean = true)) else emptyList()))   // autoVerify belongs to <intent-filter> (1.1.0: judged per filter)
        out.write(startEl(17, listOf(attr(10, 0, str = 18)))); out.write(endEl(17))      // <category android:name="...BROWSABLE"/> (name = pool index 0 -> id 0x01010003)
        val data = ArrayList<ByteArray>()
        data.add(attr(10, 4, str = 13))                                                  // scheme
        out.write(startEl(9, data))
        out.write(endEl(9)); out.write(endEl(8)); out.write(endEl(7)); out.write(endEl(6)); out.write(endEl(5))
        out.write(endNs(prefix = 11, uri = 10))
        val body = out.toByteArray()
        return ByteBuffer.allocate(8 + body.size).order(ByteOrder.LITTLE_ENDIAN).putShort(0x0003).putShort(8).putInt(8 + body.size).put(body).array()
    }

    private fun le(v: Int) = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(v).array()
    private fun le16(v: Int) = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(v.toShort()).array()

    /** A chunk: type, header size, total size (8 + body), then the body (which starts with the rest of the header). */
    private fun chunk(type: Int, header: Int, body: ByteArray): ByteArray {
        val o = ByteArrayOutputStream()
        o.write(le16(type)); o.write(le16(header)); o.write(le(8 + body.size)); o.write(body)
        return o.toByteArray()
    }

    /** UTF-16 string pool (flags 0), so the length prefix is a plain 16-bit count. */
    private fun pool(strings: List<String>): ByteArray {
        val data = ByteArrayOutputStream()
        val offs = ArrayList<Int>()
        for (s in strings) {
            offs.add(data.size())
            data.write(le16(s.length))
            for (c in s) data.write(le16(c.code))
            data.write(le16(0))
        }
        while (data.size() % 4 != 0) data.write(0)
        val head = ByteArrayOutputStream()
        head.write(le(strings.size)); head.write(le(0)); head.write(le(0))             // count, style count, flags
        head.write(le(28 + 4 * strings.size)); head.write(le(0))                       // strings start (from chunk start), styles start
        val offBytes = ByteArrayOutputStream().also { o -> for (x in offs) o.write(le(x)) }.toByteArray()
        return chunk(0x0001, 28, head.toByteArray() + offBytes + data.toByteArray())
    }

    private fun startNs(prefix: Int, uri: Int) = chunk(0x0100, 16, le(1) + le(-1) + le(prefix) + le(uri))
    private fun endNs(prefix: Int, uri: Int) = chunk(0x0101, 16, le(1) + le(-1) + le(prefix) + le(uri))
    private fun endEl(name: Int) = chunk(0x0103, 16, le(1) + le(-1) + le(-1) + le(name))

    private fun startEl(name: Int, attrs: List<ByteArray>): ByteArray {
        val head = le(1) + le(-1)                                                     // line, comment
        val ext = le(-1) + le(name) + le16(20) + le16(20) + le16(attrs.size) + le16(0) + le16(0) + le16(0)
        val o = ByteArrayOutputStream()
        for (a in attrs) o.write(a)
        return chunk(0x0102, 16, head + ext + o.toByteArray())
    }

    /** ns, name (pool index; EMPTY string here), raw value, typed value (size 8, res0, type, data). */
    private fun attr(ns: Int, name: Int, str: Int = -1, boolean: Boolean = false): ByteArray {
        val typed = if (boolean) le16(8) + byteArrayOf(0, 0x12) + le(-1) else le16(8) + byteArrayOf(0, 0x03) + le(str)
        return le(ns) + le(name) + le(if (boolean) -1 else str) + typed
    }
}
