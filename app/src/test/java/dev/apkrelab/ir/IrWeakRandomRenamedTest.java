package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/** 0.108.0: a dictionary renamer (DexGuard, WE Wallet) gives renamed classes and methods security-sounding names; in a root-package class names are not evidence. */
public class IrWeakRandomRenamedTest {
    private static String cls(String type, String method, boolean crypto) {
        return ".class public " + type + "\n.super Ljava/lang/Object;\n"
                + ".method public " + method + "()I\n    .locals 2\n    new-instance v0, Ljava/util/Random;\n    invoke-direct {v0}, Ljava/util/Random;-><init>()V\n"
                + "    invoke-virtual {v0}, Ljava/util/Random;->nextInt()I\n    move-result v1\n"
                + (crypto ? "    const-string v0, \"SHA-256\"\n    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;\n" : "")
                + "    return v1\n.end method\n";
    }

    private static int hits(String type, String method, boolean crypto) {
        String t = cls(type, method, crypto);
        return IrRules.weakRandom(SmaliParser.parse(t), t).size();
    }

    @Test
    public void securityWordsInARenamedClassAreNotEvidence() {
        assertEquals(0, hits("LgetKeyTemplate$values;", "isUnknownTypeSerializer", false));   // class name "Key"
        assertEquals(0, hits("LgetBillTypeName;", "registerEncoder", false));                // method name "code"
        assertEquals(0, hits("LisEnableSecuringAccountPin;", "setExpandedTitleMargin", false));
    }

    @Test
    public void theTwinsStillReport() {
        assertEquals(1, hits("Lcom/x/KeyTemplate;", "values", false));                       // a real (packaged) class name
        assertEquals(1, hits("Lcom/x/Util;", "newSessionToken", false));                     // a real method name
        assertEquals(1, hits("LperformContextItemSelected$4;", "setShowPrivacyPolicyAboutScreen", true));   // renamed, but the class uses MessageDigest
    }
}
