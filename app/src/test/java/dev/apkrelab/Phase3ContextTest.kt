package dev.apkrelab

import dev.apkrelab.SecurityScanner.Finding
import dev.apkrelab.SecurityScanner.Severity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Maturity protocol phase 3: the context model (caller checks in code, exported="false" and permission context, callee sanitizer summaries). */
class Phase3ContextTest {

    // ---------- (1) caller checks on the provider path (K-9 SettingsProvider) ----------
    private fun ctx(text: String) = RuleContext("Lcom/x/P;", 0, text, "com.x")
    private val throwing = """
            new-instance p0, Ljava/lang/UnsupportedOperationException;
            const-string p1, "not supported"
            invoke-direct {p0, p1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V
            throw p0"""
    private val checkedOpenFile = """
            invoke-virtual {p0}, Landroid/content/ContentProvider;->getCallingPackage()Ljava/lang/String;
            move-result-object v0
            const/4 v1, 0x0
            return-object v1"""
    private fun provider(query: String = throwing, insert: String = throwing, openFile: String = checkedOpenFile) = """
        .class public final Lcom/x/P;
        .super Landroid/content/ContentProvider;
        .method public final query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
            .locals 2
            QUERY
        .end method
        .method public final insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
            .locals 2
            INSERT
        .end method
        .method public final openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
            .locals 2
            OPENFILE
        .end method
    """.trimIndent().replace("QUERY", query).replace("INSERT", insert).replace("OPENFILE", openFile)

    @Test fun throwingDataMethodsPlusACheckedOpenFileGetTheMarkerAndLowerTheManifestCard() {
        val m = ProviderCodePermissionRule.scan(ctx(provider()))
        assertEquals(1, m.size)
        assertTrue(m[0].detail, m[0].detail.contains("(openFile) checks the calling app") && m[0].detail.contains("query, insert only throw an exception"))
        val marker = m[0].also { it.ruleId = "provider-code-permission" }
        val card = Finding(Severity.HIGH, "Exported provider without a permission: com.x.P", "d", "r", cwe = "CWE-926").also { it.ruleId = "manifest-exported-components" }
        assertEquals(1, FindingPolish.applyProviderCodeChecks(listOf(marker, card)))
        assertEquals(Severity.LOW, card.severity)
    }

    @Test fun twinAMethodThatThrowsOnOneBranchAndReturnsOnAnotherIsOpen() {
        val maybe = throwing.replace("throw p0", "if-eqz p1, :ok\n            throw p0\n            :ok\n            const/4 v0, 0x0\n            return-object v0")
        assertTrue(ProviderCodePermissionRule.scan(ctx(provider(insert = maybe))).isEmpty())
    }

    @Test fun twinAProviderWhoseMethodsAllThrowIsNotCheckedInCode() {
        assertTrue(ProviderCodePermissionRule.scan(ctx(provider(openFile = throwing))).isEmpty())
        // even when a caller check exists elsewhere in the class (getType): no data method checks anything, so there is no marker
        val withCheckElsewhere = provider(openFile = throwing).replace(".end method\n.method public final openFile",
            ".end method\n.method public final getType(Landroid/net/Uri;)Ljava/lang/String;\n    .locals 1\n    invoke-virtual {p0}, Landroid/content/ContentProvider;->getCallingPackage()Ljava/lang/String;\n    move-result-object v0\n    return-object v0\n.end method\n.method public final openFile")
        assertTrue(withCheckElsewhere.contains("getType"))
        assertTrue(ProviderCodePermissionRule.scan(ctx(withCheckElsewhere)).isEmpty())
    }

    @Test fun checkSignaturesIsACallerCheck() {
        val sig = """
            invoke-virtual {p0}, Landroid/content/ContentProvider;->getContext()Landroid/content/Context;
            move-result-object v0
            invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;
            move-result-object v0
            invoke-virtual {v0, v1, v1}, Landroid/content/pm/PackageManager;->checkSignatures(II)I
            const/4 v1, 0x0
            return-object v1"""
        assertEquals(1, ProviderCodePermissionRule.scan(ctx(provider(openFile = sig))).size)
        // twin: the same method without the check is open
        assertTrue(ProviderCodePermissionRule.scan(ctx(provider(openFile = sig.replace("checkSignatures", "hasSystemFeature")))).isEmpty())
    }

    @Test fun mutantThrowingIsNotClosedLosesTheK9Marker() {
        ProviderCodePermissionRule.THROWING_IS_CLOSED = false
        try { assertTrue(ProviderCodePermissionRule.scan(ctx(provider())).isEmpty()) } finally { ProviderCodePermissionRule.THROWING_IS_CLOSED = true }
        assertFalse(ProviderCodePermissionRule.scan(ctx(provider())).isEmpty())
    }

    // ---------- (2) exported="false" and permission context (Nextcloud DiskLruImageCacheFileProvider) ----------
    private val xml = """
        <manifest package="com.x">
          <application>
            <provider android:name=".SigP" android:exported="true" android:permission="android.permission.MANAGE_DOCUMENTS" android:authorities="a"/>
            <provider android:name=".SmsP" android:exported="true" android:permission="android.permission.READ_SMS" android:authorities="b"/>
            <provider android:name=".OpenP" android:exported="true" android:authorities="c"/>
            <provider android:name=".HiddenP" android:exported="false" android:authorities="d"/>
          </application>
        </manifest>
    """.trimIndent()
    private val mc = ManifestContext(xml)
    private val pg = PermissionGuard(mc)
    private fun flow(cls: String, src: String = "a ContentProvider method parameter (other apps can call it when the provider is exported)") =
        Finding(Severity.HIGH, "Untrusted input is used as a file path", "Data from $src reaches FileOutputStream.<init>() in method $cls.openFile().", "Fix.", "Lcom/x/$cls;", 1, 0, "CWE-22")
            .also { it.ruleId = "taint-flow"; it.confidence = "MEDIUM" }

    @Test fun aProviderGuardedByASignaturePermissionLowersItsParameterFlow() {
        val f = flow("SigP")
        assertEquals(1, FindingPolish.lowerGuardedProviderFlows(listOf(f), mc, pg))
        assertEquals(Severity.MEDIUM, f.severity); assertEquals("LOW", f.confidence)
        assertTrue(f.adjusted, f.adjusted.contains("android.permission.MANAGE_DOCUMENTS"))
        assertEquals(0, FindingPolish.lowerGuardedProviderFlows(listOf(f), mc, pg))      // idempotent
    }

    @Test fun aNonExportedProviderLowersItsParameterFlow() {
        val f = flow("HiddenP\$Inner").also { it.detail = it.detail.replace("HiddenP\$Inner", "HiddenP") }
        assertEquals(1, FindingPolish.lowerGuardedProviderFlows(listOf(f), mc, pg))
        assertTrue(f.adjusted.contains("not exported"))
    }

    @Test fun twinsDangerousPermissionOpenProviderAndOtherSourcesStay() {
        val sms = flow("SmsP"); val open = flow("OpenP"); val intent = flow("SigP", src = "Intent.getStringExtra()")
        assertEquals(0, FindingPolish.lowerGuardedProviderFlows(listOf(sms, open, intent), mc, pg))
        assertEquals(Severity.HIGH, sms.severity); assertEquals(Severity.HIGH, open.severity); assertEquals(Severity.HIGH, intent.severity)
    }

    @Test fun mutantProviderContextOffKeepsTheNextcloudCard() {
        FindingPolish.PROVIDER_CONTEXT = false
        try { assertEquals(0, FindingPolish.lowerGuardedProviderFlows(listOf(flow("SigP")), mc, pg)) } finally { FindingPolish.PROVIDER_CONTEXT = true }
    }
}
