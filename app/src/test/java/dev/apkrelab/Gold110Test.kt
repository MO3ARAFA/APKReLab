package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 1.1.0: library prefixes of Flutter-plugin apps, the zip-slip path slice (PathFlow), dynamic receivers, the protection column and the agent's card labels. */
class Gold110Test {

    // ---- library prefixes ----

    @Test fun flutterPluginAndSdkPackagesAreLibraries() {
        for (t in listOf("Lcom/visionflutter/x/A;", "Ldev/fluttercommunity/plus/B;", "Lcom/yalantis/ucrop/UCropActivity;", "Lae/network/nicardmanagementsdk/C;", "Lleakcanary/D;"))
            assertEquals(t, SecurityScanner.Scope.LIB, SecurityScanner.scopeOf(t, "com.axispay.consumer.wallet"))
        // twins: the app's own package, and a neighbour of a listed prefix, stay app code
        assertEquals(SecurityScanner.Scope.APP, SecurityScanner.scopeOf("Lcom/axispay/consumer/wallet/MainActivity;", "com.axispay.consumer.wallet"))
        assertEquals(SecurityScanner.Scope.APP, SecurityScanner.scopeOf("Lcom/yalantis/myapp/A;", "com.yalantis.myapp"))
    }

    // ---- zip slip: the entry name must reach a path ----

    private fun method(body: String) = """
        .class public Lcom/example/Z;
        .super Ljava/lang/Object;
        .method public run(Ljava/io/File;Ljava/io/InputStream;)V
            .locals 8
            new-instance v1, Ljava/util/zip/ZipInputStream;
            invoke-direct {v1, p2}, Ljava/util/zip/ZipInputStream;-><init>(Ljava/io/InputStream;)V
            invoke-virtual {v1}, Ljava/util/zip/ZipInputStream;->getNextEntry()Ljava/util/zip/ZipEntry;
            move-result-object v2
            invoke-virtual {v2}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;
            move-result-object v3
            BODY
            return-void
        .end method
    """.trimIndent().replace("BODY", body)

    private fun zipSlip(body: String) = ZipSlipRule.scan(RuleContext("Lcom/example/Z;", 0, method(body), "com.example"))

    private val extract = "new-instance v4, Ljava/io/File;\n    invoke-direct {v4, p1, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V"

    @Test fun anEntryNameUsedAsTheOutputPathIsHigh() {
        val r = zipSlip(extract)
        assertEquals(1, r.size)
        assertEquals(SecurityScanner.Severity.HIGH, r[0].severity)
        // through a StringBuilder too
        val built = "new-instance v5, Ljava/lang/StringBuilder;\n    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V\n" +
            "    invoke-virtual {v5, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n" +
            "    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n    move-result-object v6\n" +
            "    new-instance v4, Ljava/io/File;\n    invoke-direct {v4, p1, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V"
        assertEquals(1, zipSlip(built).size)
    }

    @Test fun aListedNameIsNotZipSlip() {
        val listed = "new-instance v5, Ljava/util/ArrayList;\n    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V\n" +
            "    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z\n" +
            "    new-instance v4, Ljava/io/File;\n    const-string v6, \"index.txt\"\n    invoke-direct {v4, p1, v6}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V"
        assertTrue(zipSlip(listed).isEmpty())
    }

    @Test fun aZipToZipCopyIsNotZipSlip() {
        val copy = "new-instance v5, Ljava/util/zip/ZipEntry;\n    invoke-direct {v5, v3}, Ljava/util/zip/ZipEntry;-><init>(Ljava/lang/String;)V\n" +
            "    new-instance v4, Ljava/io/FileOutputStream;\n    invoke-direct {v4, p1}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V"
        assertTrue(zipSlip(copy).isEmpty())
    }

    @Test fun aBareFileNameIsNotZipSlipButAnotherSeparatorIs() {
        fun after(sep: String) = "const/16 v5, $sep\n    const/4 v6, 0x0\n    const/4 v7, 0x2\n" +
            "    invoke-static {v3, v5, v6, v7, v6}, Lkotlin/text/StringsKt;->substringAfterLast\$default(Ljava/lang/String;CLjava/lang/String;ILjava/lang/Object;)Ljava/lang/String;\n" +
            "    move-result-object v3\n    " + extract
        assertTrue(zipSlip(after("0x2f")).isEmpty())
        assertEquals(1, zipSlip(after("0x2e")).size)        // twin: '.' keeps the directory part
    }

    @Test fun pathFlowAnswers() {
        val text = method(extract)
        assertEquals(true, PathFlow.reachesPath(text, text.indexOf("ZipEntry;->getName"), "Ljava/util/zip/ZipEntry;->getName("))
        assertEquals(null, PathFlow.reachesPath(text, text.indexOf("ZipEntry;->getName"), "Ljava/util/jar/JarEntry;->getName("))   // no such call: the old rule decides
    }

    // ---- dynamic receivers ----

    private fun registers(perm: String?, flags: Int?, compat: Boolean = false): String {
        val p = if (perm == null) "const/4 v2, 0x0" else "const-string v2, \"$perm\""
        val call = if (compat) "invoke-static {p0, v0, v1, v2, v3, v4}, Landroidx/core/content/ContextCompat;->registerReceiver(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;I)Landroid/content/Intent;"
            else if (flags == null) "invoke-virtual {p0, v0, v1, v2, v3}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;)Landroid/content/Intent;"
            else "invoke-virtual {p0, v0, v1, v2, v3, v4}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;Ljava/lang/String;Landroid/os/Handler;I)Landroid/content/Intent;"
        return """
            .class public Lcom/example/Host;
            .super Landroid/app/Activity;
            .method public onStart()V
                .locals 5
                new-instance v0, Lcom/example/Rx;
                invoke-direct {v0}, Lcom/example/Rx;-><init>()V
                new-instance v1, Landroid/content/IntentFilter;
                invoke-direct {v1}, Landroid/content/IntentFilter;-><init>()V
                $p
                const/4 v3, 0x0
                const/4 v4, ${flags ?: 0}
                $call
                return-void
            .end method
        """.trimIndent()
    }

    private fun protectedAfter(minSdk: Int, vararg classes: String): Set<String> {
        DynamicReceivers.clear()
        for (c in classes) DynamicReceivers.observe(c)
        return DynamicReceivers.protectedReceivers(minSdk) { it == "com.example.permission.SIGNED" }
    }

    @Test fun aSignaturePermissionProtectsADynamicReceiver() {
        assertEquals(setOf("Lcom/example/Rx;"), protectedAfter(26, registers("com.example.permission.SIGNED", null)))
        assertEquals(setOf("Lcom/example/Rx;"), protectedAfter(26, registers("com.example.permission.SIGNED", 0, compat = true)))
        // twins: a normal permission, none at all, and one unprotected registration among protected ones
        assertTrue(protectedAfter(26, registers("com.example.permission.NORMAL", null)).isEmpty())
        assertTrue(protectedAfter(26, registers(null, null)).isEmpty())
        assertTrue(protectedAfter(26, registers("com.example.permission.SIGNED", null), registers(null, null).replace("Host", "Host2")).isEmpty())
    }

    @Test fun notExportedProtectsOnlyFromApi33() {
        assertEquals(setOf("Lcom/example/Rx;"), protectedAfter(33, registers(null, 4)))
        assertTrue(protectedAfter(26, registers(null, 4)).isEmpty())       // older devices ignore the flag
        assertTrue(protectedAfter(33, registers(null, 2)).isEmpty())       // RECEIVER_EXPORTED
    }

    @Test fun lowerTouchesOnlyIntentCardsOfAProtectedReceiver() {
        fun card(type: String, detail: String) = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, "Untrusted input is used as a file path", detail, "r", type, 3, 10, "CWE-22")
            .also { it.ruleId = "taint-flow" }
        val a = card("Lcom/example/Rx;", "Data from Intent.getStringExtra() reaches File.<init>")
        val b = card("Lcom/example/Other;", "Data from Intent.getStringExtra() reaches File.<init>")
        val c = card("Lcom/example/Rx;", "Data from ContentResolver.query() reaches File.<init>")
        val d = card("Lcom/example/Rx;", "Data from Intent.getStringExtra() reaches File.<init>").also { it.sourceMethod = "Lcom/example/Other;->onReceive" }   // the Intent another class received
        assertEquals(1, DynamicReceivers.lower(listOf(a, b, c, d), setOf("Lcom/example/Rx;")))
        assertEquals(SecurityScanner.Severity.HIGH, d.severity)
        assertEquals(SecurityScanner.Severity.LOW, a.severity)
        assertEquals(SecurityScanner.Severity.HIGH, b.severity)
        assertEquals(SecurityScanner.Severity.HIGH, c.severity)
    }

    // ---- attack surface: the protection column ----

    @Test fun theProtectionColumnShowsWhatACallerNeeds() {
        val xml = """
            <manifest package="com.example">
            <permission android:name="com.example.SIGNED" android:protectionLevel="signature"/>
            <permission android:name="com.example.NORMAL"/>
            <application>
            <receiver android:name=".Open" android:exported="true"></receiver>
            <receiver android:name=".Signed" android:exported="true" android:permission="com.example.SIGNED"></receiver>
            <receiver android:name=".Normal" android:exported="true" android:permission="com.example.NORMAL"></receiver>
            <service android:name=".Job" android:exported="true" android:permission="android.permission.BIND_JOB_SERVICE"></service>
            <provider android:name=".P" android:exported="true" android:readPermission="com.example.SIGNED"></provider>
            </application></manifest>
        """.trimIndent()
        val md = ReportBuilder.attackSurface(xml, "com.example")
        fun row(name: String) = md.lines().first { it.startsWith("| `com.example.$name`") }
        assertTrue(row("Open"), row("Open").contains("NONE (open to any app)"))
        assertTrue(row("Signed"), row("Signed").contains("(signature)"))
        assertTrue(row("Normal"), row("Normal").contains("normal: any app can request it"))
        assertTrue(row("Job"), row("Job").contains("signature / system"))
        assertTrue(row("P"), row("P").contains("read: `com.example.SIGNED` (signature); write: NONE (open)"))
        assertTrue(md.contains("1 of 5 exported component(s) need no permission at all"))
    }

    // ---- agent card labels ----

    @Test fun cardLabelsMatchTheReportNumbers() {
        val list = (1..5).map { SecurityScanner.Finding(SecurityScanner.Severity.MEDIUM, "Title $it", "d", "r") }
        assertEquals("#3", GraphTools.cardLabel(2, 3))
        assertEquals("#L1", GraphTools.cardLabel(3, 3))
        assertEquals(2, GraphTools.pick(list, "#2", 3)!!.first)
        assertEquals(4, GraphTools.pick(list, "#L1", 3)!!.first)
        assertEquals(null, GraphTools.pick(list, "#4", 3))          // twin: #4 is not a report card when the report has 3
        assertEquals(null, GraphTools.pick(list, "#L3", 3))
        assertFalse(GraphTools.pick(list, "Title 5", 3) == null)
    }
}
