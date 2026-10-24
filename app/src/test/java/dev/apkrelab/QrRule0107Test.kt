package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.107.0: the QR/barcode card needs a real scanner API call; R8's reuse of a library class name for merged app code (K-9 Mail) is not scanning. */
class QrRule0107Test {
    private fun cls(body: String) = ".class public Lcom/x/Scan;\n.super Ljava/lang/Object;\n.method public run(Landroid/content/Context;Landroid/content/Intent;)V\n    .locals 4\n$body    return-void\n.end method\n"
    private val start = "    invoke-virtual {p1, p2}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V\n"
    private fun qr(text: String) = AndroGoatChecks.scan("Lcom/x/Scan;", 0, text, "com.x").filter { it.title.startsWith("QR/barcode") }

    @Test fun eachScannerApiWithASinkIsReported() {
        for (api in listOf("    invoke-virtual {v0}, Lcom/google/zxing/Result;->getText()Ljava/lang/String;\n",
                "    invoke-virtual {v0, v1}, Lcom/google/zxing/MultiFormatReader;->decode(Lcom/google/zxing/BinaryBitmap;)Lcom/google/zxing/Result;\n",
                "    new-instance v0, Lcom/journeyapps/barcodescanner/ScanOptions;\n",
                "    invoke-virtual {v0}, Lcom/google/mlkit/vision/barcode/common/Barcode;->getRawValue()Ljava/lang/String;\n",
                "    iget-object v0, v1, Lcom/google/android/gms/vision/barcode/Barcode;->rawValue:Ljava/lang/String;\n")) {
            val f = qr(cls(api + start))
            assertEquals(api, 1, f.size); assertEquals(SecurityScanner.Severity.MEDIUM, f[0].severity)
        }
    }

    @Test fun aMergedAppClassThatKeptALibraryNameIsNotAScanner() {
        val merged = "    iget-object v0, v1, Lcom/fsck/k9/controller/MessagingController;->archiveOperations:Lcom/google/zxing/BinaryBitmap;\n" +
            "    invoke-virtual {v0, v2}, Lcom/google/zxing/BinaryBitmap;->archiveMessages(Ljava/util/List;)V\n"
        assertTrue(qr(cls(merged + start)).isEmpty())
        assertTrue(qr(cls("    invoke-virtual {v0}, Lcom/google/zxing/Result;->getText()Ljava/lang/String;\n")).none { it.severity == SecurityScanner.Severity.MEDIUM })   // twin: a scanner, no sink
    }
}
