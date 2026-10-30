package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.80.0: fixes measured on real-app sets 4 + 5 (same build, unseen apps). */
class SetFourFiveFixes0800Test {

    private fun taint(type: String, ssa: Boolean, src: String = "Data from Intent.getData() reaches File.delete()") =
        SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "Untrusted input is used as a file path",
            src + if (ssa) " ... Found by the SSA data-flow engine ..." else " ... followed inside this class", "r", type, 4, 10, "CWE-22")
            .also { it.ruleId = "taint-flow" }

    @Test fun intentTaintInANonExportedReceiverDropsButAnActivityDoesNot() {
        val recv = taint("Lcom/x/DeleteReceiver;", false)
        val act = taint("Lcom/x/WebViewActivity;", false)
        val prefs = taint("Lcom/x/DeleteReceiver;", false, "Data from SharedPreferences.getString() reaches File.delete()")
        val n = FindingPolish.lowerNonExportedReceivers(listOf(recv, act, prefs), setOf("Lcom/x/DeleteReceiver;"))
        assertEquals(1, n)
        assertEquals(SecurityScanner.Severity.MEDIUM, recv.severity)
        assertEquals(SecurityScanner.Severity.HIGH, act.severity)      // OVAA / Infinity: forwarded by an exported activity
        assertEquals(SecurityScanner.Severity.HIGH, prefs.severity)
    }

    @Test fun nonExportedReceiversAndServicesComeFromTheManifest() {
        val mc = ManifestContext("""
            <manifest package="com.x"><application>
            <receiver android:name=".DeleteReceiver"/>
            <receiver android:name=".Open" android:exported="true"/>
            <service android:name=".Sync" android:exported="false"/>
            <activity android:name=".WebViewActivity"/>
            </application></manifest>
        """.trimIndent())
        assertEquals(setOf("Lcom/x/DeleteReceiver;", "Lcom/x/Sync;"), FindingPolish.nonExportedReceiversAndServices(mc))
    }

    @Test fun theSsaFlowAbsorbsTheInClassFindingOfTheSameClassAndTitle() {
        val d = SecurityScanner.dedupe(listOf(taint("Lcom/x/W;", false), taint("Lcom/x/W;", true)))
        assertEquals(1, d.size)
        assertTrue(d[0].detail.contains("SSA data-flow engine"))
    }

    @Test fun pathLiteralsAreNotSecrets() {
        assertTrue(SecurityScanner.looksLikeName("/android_asset_font/"))
        assertTrue(SecurityScanner.looksLikeName("files/objectbox/data"))
        assertFalse(SecurityScanner.looksLikeName("mJn':4Nbk};AMVFGEWiY!(8&gp1xOv@/"))
    }
}
