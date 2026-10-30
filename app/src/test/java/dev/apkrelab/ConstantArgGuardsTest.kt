package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.102.0: deterministic guards for the AES-CMAC zero-block primitive and for shell commands whose arguments are all constants. Each positive has negative twins. */
class ConstantArgGuardsTest {
    private val dec = "Lvs/C;->d(I)Ljava/lang/String;"
    private fun cls(params: String, body: String) = ".class public Lcom/example/Pay;\n.super Ljava/lang/Object;\n.method public run($params)V\n    .locals 6\n$body\n    return-void\n.end method\n"
    private fun ctx(text: String) = RuleContext("Lcom/example/Pay;", 0, text, "com.example")
    private fun ecb(t: String) = CryptoCipherRule.scan(ctx(t))
    private fun shell(t: String) = ShellExecRule.scan(ctx(t))
    private val sev = SecurityScanner.Severity.values().associateBy { it.name }

    // ---------------- AES/ECB/NoPadding on a zero block ----------------
    private fun cmac(algo: String, size: String = "0x10", between: String = "", use: String = "invoke-virtual {v1, v0}, Ljavax/crypto/Cipher;->doFinal([B)[B") = cls("", """
        const-string v2, "$algo"
        invoke-static {v2}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
        move-result-object v1
        const/16 v0, $size
        new-array v0, v0, [B
$between
        $use
        move-result-object v0""")

    @Test fun aesEcbNoPaddingOnAFreshZeroBlockIsLowAndSaysWhy() {
        val f = ecb(cmac("AES/ECB/NoPadding"))
        assertEquals(1, f.size); assertEquals(SecurityScanner.Severity.LOW, f[0].severity)
        assertTrue(f[0].title.contains("CMAC")); assertTrue(f[0].detail.contains("0^128"))
    }

    @Test fun theSameCipherOnAnythingElseStaysHigh() {
        fun high(t: String) { val f = ecb(t); assertEquals(1, f.size); assertEquals(SecurityScanner.Severity.HIGH, f[0].severity) }
        high(cmac("AES/ECB/PKCS5Padding"))                                                                     // padding: a zero block gives 32 bytes, not the CMAC step
        high(cmac("AES/ECB/NoPadding", size = "0x20"))                                                         // two blocks
        high(cmac("AES/ECB/NoPadding", between = "        const/4 v3, 0x1\n        aput-byte v3, v0, v3"))       // the array is written
        high(cmac("AES/ECB/NoPadding", between = "        invoke-static {v0}, Lx/Y;->fill([B)V"))                  // handed to something that may fill it
        high(cls("[B", """
            const-string v2, "AES/ECB/NoPadding"
            invoke-static {v2}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
            move-result-object v1
            invoke-virtual {v1, p1}, Ljavax/crypto/Cipher;->doFinal([B)[B"""))                                  // data from a parameter
        high(cmac("AES/ECB/NoPadding", between = "        :cond_0"))                                             // a label: another path may arrive
        // two doFinal calls, one on data: the guard needs EVERY use to be the zero block
        high(cmac("AES/ECB/NoPadding", use = "invoke-virtual {v1, v0}, Ljavax/crypto/Cipher;->doFinal([B)[B\n        invoke-virtual {v1, p1}, Ljavax/crypto/Cipher;->doFinal([B)[B"))
        high(cmac("AES/ECB/NoPadding", use = "invoke-virtual {v1, v0}, Ljavax/crypto/Cipher;->update([B)[B"))   // update(): streaming use
    }

    // ---------------- shell commands with constant arguments ----------------
    private fun exec1(argSetup: String, reg: String = "v1") = cls("Ljava/lang/String;", """
        invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
        move-result-object v0
$argSetup
        invoke-virtual {v0, $reg}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;""")

    @Test fun constantShellCommandsAreLowInEveryConstantShape() {
        fun low(t: String) { val f = shell(t); assertEquals(1, f.size); assertEquals(SecurityScanner.Severity.LOW, f[0].severity); assertTrue(f[0].detail.contains("no input to inject")) }
        low(exec1("        const-string v1, \"which su\""))                                                    // a literal
        low(exec1("        const/16 v2, 0x2a\n        invoke-static {v2}, $dec\n        move-result-object v1"))                 // the string-table decryptor
        low(cls("", """
            invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
            move-result-object v0
            const/4 v1, 0x3
            new-array v1, v1, [Ljava/lang/String;
            const/4 v2, 0x0
            const-string v3, "su"
            aput-object v3, v1, v2
            const/4 v2, 0x1
            const/16 v4, 0x10
            invoke-static {v4}, $dec
            move-result-object v3
            aput-object v3, v1, v2
            invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;"""))        // String[] of constants and decrypted constants
        low(cls("", """
            new-instance v0, Ljava/lang/ProcessBuilder;
            const/4 v1, 0x1
            new-array v1, v1, [Ljava/lang/String;
            const/4 v2, 0x0
            const-string v3, "getprop"
            aput-object v3, v1, v2
            invoke-direct {v0, v1}, Ljava/lang/ProcessBuilder;-><init>([Ljava/lang/String;)V"""))
    }

    @Test fun anythingNotProvablyConstantStaysMedium() {
        fun med(t: String) { val f = shell(t); assertEquals(1, f.size); assertEquals(SecurityScanner.Severity.MEDIUM, f[0].severity) }
        med(exec1("", reg = "p1"))                                                                                // a parameter
        med(exec1("        const/4 v2, 0x2\n        invoke-static {v2}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;\n        move-result-object v1"))   // a framework (I)String is not a string table
        med(exec1("        invoke-static {p1}, $dec\n        move-result-object v1"))                                // the index is computed / a parameter
        med(exec1("        const-string v1, \"ls\"\n        :goto_0\n        nop", reg = "v1"))                      // a label between the literal and the use is not a proof... (the literal is before the label)
        med(exec1("        iget-object v1, p0, Lcom/example/Pay;->cmd:Ljava/lang/String;"))                         // a field
        med(cls("Ljava/lang/String;", """
            invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
            move-result-object v0
            const/4 v1, 0x2
            new-array v1, v1, [Ljava/lang/String;
            const/4 v2, 0x0
            const-string v3, "sh"
            aput-object v3, v1, v2
            const/4 v2, 0x1
            aput-object p1, v1, v2
            invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;"""))         // one element from a parameter
        // two sites in one class, one constant and one not: the class stays MEDIUM
        med(cls("Ljava/lang/String;", """
            invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
            move-result-object v0
            const-string v1, "id"
            invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
            invoke-virtual {v0, p1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;"""))
    }

    @Test fun theDefensePostureSignalFollowsTheSameDecision() {
        val sig = PostureScanner.signals.first { it.id == "shell-const" }
        assertTrue(sig.test(exec1("        const-string v1, \"which su\"")))
        assertFalse(sig.test(exec1("", reg = "p1")))                                                              // twin: a command from a parameter is not a fixed command
        assertFalse(sig.test(cls("", "        const-string v0, \"plain\"")))                                  // twin: no exec at all
    }
}
