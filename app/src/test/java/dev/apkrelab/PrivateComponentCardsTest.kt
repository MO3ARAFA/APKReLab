package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 2.0.2: the not-exported-component rule on the cards of every engine (WE Wallet SignUpWebViewActivity). */
class PrivateComponentCardsTest {
    private val signUp = "Lcom/emeint/SignUpWebViewActivity;"
    private val irCard = "Data from Intent.getStringExtra() reaches WebView.loadUrl() in method setDueDate(): the WebView loads a URL chosen by the caller. The value was followed through registers, fields and calls inside this class."

    private fun card(cls: String = signUp, detail: String = irCard, sev: SecurityScanner.Severity = SecurityScanner.Severity.HIGH, reach: String = "YES"): SecurityScanner.Finding =
        SecurityScanner.Finding(sev, "Untrusted input is loaded into a WebView", detail, "r", cls, 3, 10, "CWE-79").also { it.ruleId = "taint-flow"; it.reach = reach; it.chain = "Entry: x\nPath: a -> b" }

    private fun run(f: SecurityScanner.Finding, priv: Set<String> = setOf(signUp), fwd: Set<String> = emptySet(), open: Boolean = false) =
        FindingPolish.lowerUnforwardedPrivateIntentFlows(listOf(f), priv, fwd, open)

    @Test fun anUnforwardedIntentFlowInAPrivateActivityDropsAndItsReachIsApproximate() {
        val f = card()
        assertEquals(1, run(f))
        assertEquals(SecurityScanner.Severity.MEDIUM, f.severity)
        assertEquals("LOW", f.confidence)
        assertEquals("YES~", f.reach)
        assertTrue(f.adjusted, f.adjusted.contains("not forwarded"))
    }

    @Test fun itIsIdempotent() {
        val f = card(); run(f)
        assertEquals(0, run(f))
        assertEquals(SecurityScanner.Severity.MEDIUM, f.severity)
    }

    // twins
    @Test fun aProvenForwardKeepsTheCard() {
        val f = card(); assertEquals(0, run(f, fwd = setOf(signUp)))
        assertEquals(SecurityScanner.Severity.HIGH, f.severity); assertEquals("YES", f.reach)
    }
    @Test fun anExportedActivityIsNotTouched() { val f = card(); assertEquals(0, run(f, priv = setOf("Lcom/emeint/Other;"))); assertEquals(SecurityScanner.Severity.HIGH, f.severity) }
    @Test fun anOpenRedirectorKeepsEverything() { val f = card(); assertEquals(0, run(f, open = true)); assertEquals(SecurityScanner.Severity.HIGH, f.severity) }
    @Test fun aCardOfTheSsaEngineIsLeftToTheEngine() {
        val f = card(detail = "Data from Intent.getStringExtra() reaches WebView.loadUrl() in method m(). Found by the SSA data-flow engine, which follows values.")
        assertEquals(0, run(f)); assertEquals(SecurityScanner.Severity.HIGH, f.severity)
    }
    @Test fun aProviderSourceIsNotAnIntentFlow() { val f = card(detail = "Data from a ContentProvider method parameter reaches x()."); assertEquals(0, run(f)) }
    @Test fun aNestedClassOfAPrivateActivityFollowsItsOuterClass() { val f = card(cls = "Lcom/emeint/SignUpWebViewActivity\$1;"); assertEquals(1, run(f)); assertEquals(SecurityScanner.Severity.MEDIUM, f.severity) }
    @Test fun aMediumCardIsNotLoweredFurther() { val f = card(sev = SecurityScanner.Severity.MEDIUM); assertEquals(0, run(f)) }

    @Test fun mutantSwitchOffKeepsTheCard() {
        val was = FindingPolish.PRIVATE_COMPONENT_CARDS
        FindingPolish.PRIVATE_COMPONENT_CARDS = false
        try { val f = card(); assertEquals(0, run(f)); assertEquals(SecurityScanner.Severity.HIGH, f.severity) } finally { FindingPolish.PRIVATE_COMPONENT_CARDS = was }
    }
}
