package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.100.0: Jackson polymorphic typing in the app's own code and a SQLCipher passphrase that is constant or predictable. Every positive has twins. */
class DbAndJacksonRulesTest {
    private fun scan(rule: ScanRule, cls: String, body: String, pkg: String = "com.x"): List<SecurityScanner.Finding> =
        rule.scan(RuleContext("L" + cls.replace('.', '/') + ";", 0, ".class public L" + cls.replace('.', '/') + ";\n.super Ljava/lang/Object;\n" + body, pkg))
    private fun m(code: String) = ".method public run()V\n    .locals 6\n$code\n    return-void\n.end method\n"

    // ---- Jackson
    @Test fun defaultTypingInTheAppsOwnCodeIsReportedAndInJacksonItselfIsNot() {
        val call = m("    new-instance v0, Lcom/fasterxml/jackson/databind/ObjectMapper;\n    invoke-virtual {v0}, Lcom/fasterxml/jackson/databind/ObjectMapper;->enableDefaultTyping()Lcom/fasterxml/jackson/databind/ObjectMapper;")
        val f = scan(JacksonDefaultTypingRule, "com.x.Json", call)
        assertEquals(1, f.size); assertEquals(SecurityScanner.Severity.MEDIUM, f[0].severity); assertTrue(f[0].detail.contains("enableDefaultTyping"))
        assertTrue(scan(JacksonDefaultTypingRule, "com.fasterxml.jackson.databind.ObjectMapper", call).isEmpty())            // the library's own definition (the wallet app's only hit)
    }

    @Test fun activateDefaultTypingNeedsAPermissiveValidatorAndTheAnnotationNeedsClassNames() {
        val laissez = m("    sget-object v1, Lcom/fasterxml/jackson/databind/jsontype/impl/LaissezFaireSubTypeValidator;->instance:Lcom/fasterxml/jackson/databind/jsontype/impl/LaissezFaireSubTypeValidator;\n    invoke-virtual {v0, v1}, Lcom/fasterxml/jackson/databind/ObjectMapper;->activateDefaultTyping(Lcom/fasterxml/jackson/databind/jsontype/PolymorphicTypeValidator;)Lcom/fasterxml/jackson/databind/ObjectMapper;")
        assertEquals(1, scan(JacksonDefaultTypingRule, "com.x.Json", laissez).size)
        val safe = m("    invoke-static {}, Lcom/fasterxml/jackson/databind/jsontype/BasicPolymorphicTypeValidator;->builder()Lcom/fasterxml/jackson/databind/jsontype/BasicPolymorphicTypeValidator\$Builder;\n    invoke-virtual {v0, v1}, Lcom/fasterxml/jackson/databind/ObjectMapper;->activateDefaultTyping(Lcom/fasterxml/jackson/databind/jsontype/PolymorphicTypeValidator;)Lcom/fasterxml/jackson/databind/ObjectMapper;")
        assertTrue(scan(JacksonDefaultTypingRule, "com.x.Json", safe).isEmpty())                                           // twin: an allow-listing validator
        fun anno(id: String) = ".annotation runtime Lcom/fasterxml/jackson/annotation/JsonTypeInfo;\n    use = .enum Lcom/fasterxml/jackson/annotation/JsonTypeInfo\$Id;->$id\n.end annotation\n"
        assertEquals(1, scan(JacksonDefaultTypingRule, "com.x.Model", anno("CLASS")).size)
        assertEquals(1, scan(JacksonDefaultTypingRule, "com.x.Model", anno("MINIMAL_CLASS")).size)
        assertTrue(scan(JacksonDefaultTypingRule, "com.x.Model", anno("NAME")).isEmpty())                                    // twin: logical names, not class names
        assertTrue(scan(JacksonDefaultTypingRule, "com.x.Plain", m("    const-string v0, \"x\"")).isEmpty())
    }

    // ---- SQLCipher
    private fun open(argSetup: String, reg: String = "v2") = m("    new-instance v0, Lcom/x/DbHelper;\n$argSetup\n    invoke-virtual {v0, $reg}, LwithoutAttribute;->getWritableDatabase(Ljava/lang/String;)Lnet/sqlcipher/database/SQLiteDatabase;")

    @Test fun aConstantPassphraseIsHighOnAnyReceiverClass() {                                                                // the wallet app's helper class is renamed: the String overload is what identifies SQLCipher
        val f = scan(SqlCipherPassphraseRule, "com.x.Db", open("    const-string v2, \"s3cretDbKey2024\""))
        assertEquals(1, f.size); assertEquals(SecurityScanner.Severity.HIGH, f[0].severity); assertTrue(f[0].detail.contains("a constant")); assertFalse(f[0].detail.contains("s3cretDbKey2024"))   // never print the value
        val viaBytes = m("    const-string v1, \"s3cretDbKey2024\"\n    invoke-virtual {v1}, Ljava/lang/String;->getBytes()[B\n    move-result-object v1\n    new-instance v0, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;\n    invoke-direct {v0, v1}, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;-><init>([B)V")
        assertEquals(SecurityScanner.Severity.HIGH, scan(SqlCipherPassphraseRule, "com.x.Db", viaBytes).single().severity)       // a constant stays a constant through getBytes
    }

    @Test fun aDeviceIdentifierIsMediumAndAnUnknownSourceIsNotReported() {
        val androidId = open("    invoke-static {v3, v4}, Landroid/provider/Settings\$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2")
        val f = scan(SqlCipherPassphraseRule, "com.x.Db", androidId)
        assertEquals(SecurityScanner.Severity.MEDIUM, f.single().severity); assertTrue(f.single().detail.contains("Settings\$Secure.getString"))
        // twins: from the Keystore / a reflective call / a parameter: unknown is not a finding
        assertTrue(scan(SqlCipherPassphraseRule, "com.x.Db", open("    invoke-virtual {v3}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;\n    move-result-object v2\n    invoke-virtual {v2}, Ljava/lang/String;->toString()Ljava/lang/String;\n    move-result-object v2")).isEmpty())
        assertTrue(scan(SqlCipherPassphraseRule, "com.x.Db", open("    invoke-static {}, Lcom/x/Keys;->dbKey()Ljava/lang/String;\n    move-result-object v2")).isEmpty())
        assertTrue(scan(SqlCipherPassphraseRule, "com.x.Db", open("", "p1")).isEmpty())                                      // a parameter
        // the library's own classes are never reported; the platform's no-argument helper is not SQLCipher
        assertTrue(scan(SqlCipherPassphraseRule, "net.sqlcipher.database.SQLiteOpenHelper", open("    const-string v2, \"abcdef\"")).isEmpty())
        assertTrue(scan(SqlCipherPassphraseRule, "com.x.Db", m("    invoke-virtual {v0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;")).isEmpty())
    }
}
