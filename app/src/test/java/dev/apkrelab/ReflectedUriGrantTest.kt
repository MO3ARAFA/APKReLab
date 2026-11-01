package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 2.1.0 (real-CVE benchmark C09): an exported activity that reflects its own Intent through setResult() is HIGH when a grantUriPermissions provider exists. */
class ReflectedUriGrantTest {
    private fun manifest(activityExported: Boolean, grantProvider: Boolean) = """<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application>
    <activity android:name="com.x.SettingsActivity" android:exported="$activityExported"/>
    <provider android:name="androidx.core.content.FileProvider" android:authorities="com.x.fp" android:exported="false" android:grantUriPermissions="$grantProvider"/>
  </application></manifest>"""

    private fun card(sev: SecurityScanner.Severity = SecurityScanner.Severity.MEDIUM, detail: String = "setResult() returns the Intent this activity was started with (getIntent()). The app that started it chose that Intent's data Uri") =
        SecurityScanner.Finding(sev, "Intent returned with setResult() may grant URI permissions", detail, "r", "Lcom/x/SettingsActivity;", 1, 0, "CWE-284").also { it.ruleId = "uri-grant-via-result"; it.scope = SecurityScanner.Scope.APP }

    @Test fun anExportedReflectorWithAGrantProviderIsHigh() {
        val f = card()
        assertEquals(1, FindingPolish.raiseReflectedUriGrant(listOf(f), ManifestContext(manifest(true, true))))
        assertEquals(SecurityScanner.Severity.HIGH, f.severity)
        assertTrue(f.adjusted, f.adjusted.startsWith("Raised to HIGH"))
        assertEquals(0, FindingPolish.raiseReflectedUriGrant(listOf(f), ManifestContext(manifest(true, true))))      // idempotent
    }

    // twins
    @Test fun aNotExportedActivityStaysMedium() { val f = card(); assertEquals(0, FindingPolish.raiseReflectedUriGrant(listOf(f), ManifestContext(manifest(false, true)))); assertEquals(SecurityScanner.Severity.MEDIUM, f.severity) }
    @Test fun withoutAGrantProviderItStaysMedium() { val f = card(); assertEquals(0, FindingPolish.raiseReflectedUriGrant(listOf(f), ManifestContext(manifest(true, false)))); assertEquals(SecurityScanner.Severity.MEDIUM, f.severity) }
    @Test fun otherUriGrantCardsAreNotTouched() { val f = card(detail = "onActivityResult() passes the result Intent it received straight to setResult()."); assertEquals(0, FindingPolish.raiseReflectedUriGrant(listOf(f), ManifestContext(manifest(true, true)))); assertEquals(SecurityScanner.Severity.MEDIUM, f.severity) }

    @Test fun mutantSwitchOffKeepsMedium() {
        val was = FindingPolish.RAISE_REFLECTED_GRANT
        FindingPolish.RAISE_REFLECTED_GRANT = false
        try { val f = card(); assertEquals(0, FindingPolish.raiseReflectedUriGrant(listOf(f), ManifestContext(manifest(true, true)))); assertEquals(SecurityScanner.Severity.MEDIUM, f.severity) } finally { FindingPolish.RAISE_REFLECTED_GRANT = was }
    }

    @Test fun theRaisedCardPassesTheSinkConditionOfTheGate() {
        val f = card(); FindingPolish.raiseReflectedUriGrant(listOf(f), ManifestContext(manifest(true, true)))
        f.reach = "YES"; f.chain = "Entry: exported activity com.x.SettingsActivity (no permission)\nPath: com.x.SettingsActivity"
        assertTrue(MustFixGate.check(f).passes)
        // twin: the same card still at MEDIUM-without-raise does not name a high-impact sink
        val g = card(); g.reach = "YES"; g.chain = f.chain
        assertTrue(MustFixGate.check(g).failed.contains("a"))
    }
}
