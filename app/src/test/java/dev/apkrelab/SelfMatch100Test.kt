package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 1.0.0 (self-scan of APKReLab's own APK): three rules matched their own pattern text, held by APKReLab's rule classes as string constants (a JS-bridge "annotation", a
 * "ContentProvider" header, an ALLOW_ALL_HOSTNAME_VERIFIER name). Each twin pair: the text inside a const-string is no finding, the real code still is.
 */
class SelfMatch100Test {
    private fun count(type: String, text: String, rule: String) = SecurityScanner.scanSmali(type, 0, text, "com.x").count { it.ruleId == rule }

    private val jsBody = "    invoke-virtual {p0}, Lcom/x/B;->getSharedPreferences()Landroid/content/SharedPreferences;\n    return-void\n.end method\n"

    @Test fun aJsInterfaceNameInAStringIsNoBridge() {
        val strings = ".class public Lcom/x/B;\n.super Ljava/lang/Object;\n.method public scan()V\n    .locals 2\n    const-string v0, \"Landroid/webkit/JavascriptInterface;\"\n$jsBody"
        assertEquals(0, count("Lcom/x/B;", strings, "webview-js-bridge-method"))
        val real = ".class public Lcom/x/B;\n.super Ljava/lang/Object;\n.method public scan()V\n    .locals 2\n    .annotation runtime Landroid/webkit/JavascriptInterface;\n    .end annotation\n$jsBody"
        assertEquals(1, count("Lcom/x/B;", real, "webview-js-bridge-method"))
    }

    private val queryBody = ".method public query(Landroid/net/Uri;)V\n    .locals 3\n    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n" +
        "    invoke-virtual {v2, v1, v0}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;\n    return-void\n.end method\n"

    @Test fun aProviderHeaderInAStringIsNoProvider() {
        val strings = ".class public Lcom/x/R;\n.super Ljava/lang/Object;\n.method public a()V\n    .locals 2\n    const-string v0, \"\\n.super Landroid/content/ContentProvider;\"\n" +
            "    const-string v1, \"\\n.method public query(\"\n    return-void\n.end method\n.method public b(Landroid/net/Uri;)V\n    .locals 3\n" +
            "    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n" +
            "    invoke-virtual {v2, v1, v0}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;\n    return-void\n.end method\n"
        assertEquals(0, count("Lcom/x/R;", strings, "provider-sql-injection"))
        // a class with a real query() that is not a provider, naming the provider header only in a string
        val notProvider = ".class public Lcom/x/Q;\n.super Ljava/lang/Object;\n.method public a()V\n    .locals 1\n    const-string v0, \".super Landroid/content/ContentProvider;\"\n    return-void\n.end method\n$queryBody"
        assertEquals(0, count("Lcom/x/Q;", notProvider, "provider-sql-injection"))
        assertEquals(1, count("Lcom/x/P;", ".class public Lcom/x/P;\n.super Landroid/content/ContentProvider;\n$queryBody", "provider-sql-injection"))
    }

    @Test fun anAllowAllNameInAStringIsNoVerifier() {
        val strings = ".class public Lcom/x/T;\n.super Ljava/lang/Object;\n.method public a()V\n    .locals 2\n    const-string v0, \"HostnameVerifier\"\n    const-string v1, \"ALLOW_ALL_HOSTNAME_VERIFIER\"\n    return-void\n.end method\n"
        assertEquals(0, count("Lcom/x/T;", strings, "tls-hostname-verifier"))
        val real = ".class public Lcom/x/T;\n.super Ljava/lang/Object;\n.method public a()V\n    .locals 2\n" +
            "    sget-object v0, Lorg/apache/http/conn/ssl/SSLSocketFactory;->ALLOW_ALL_HOSTNAME_VERIFIER:Lorg/apache/http/conn/ssl/X509HostnameVerifier;\n" +
            "    invoke-virtual {v1, v0}, Ljavax/net/ssl/HttpsURLConnection;->setHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V\n    return-void\n.end method\n"
        assertEquals(1, count("Lcom/x/T;", real, "tls-hostname-verifier"))
    }
}
