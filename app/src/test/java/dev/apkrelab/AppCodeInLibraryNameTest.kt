package dev.apkrelab

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 3.0.0 (C12, Wikipedia: R8 put SingleWebViewActivity.newIntent$default into okio/ByteString$Companion): a library-named class that holds app code is analysed as app code. */
class AppCodeInLibraryNameTest {
    private val merged = """
        .class public final Lokio/ByteString${'$'}Companion;
        .method public static newIntent(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;
            sget v0, Lorg/wikipedia/activity/SingleWebViewActivity;->${'$'}r8${'$'}clinit:I
            const-class v1, Lorg/wikipedia/activity/SingleWebViewActivity;
            invoke-static {p1}, Lorg/wikipedia/util/UriUtil;->x(Ljava/lang/String;)V
        .end method
    """.trimIndent()

    @Test fun aLibraryNamedClassWhoseInstructionsNameTheAppIsAppCode() {
        assertTrue(SecurityScanner.appCodeInLibraryName("Lokio/ByteString\$Companion;", merged, "org.wikipedia"))
    }

    @Test fun twins() {
        val strings = "const-string v0, \"Lorg/wikipedia/a;\"\nconst-string v1, \"Lorg/wikipedia/b;\"\nconst-string v2, \"Lorg/wikipedia/c;\"\n"
        assertFalse(SecurityScanner.appCodeInLibraryName("Lokio/Buffer;", strings, "org.wikipedia"))                      // strings only
        assertFalse(SecurityScanner.appCodeInLibraryName("Lorg/wikipedia/Main;", merged, "org.wikipedia"))                 // already app
        assertFalse(SecurityScanner.appCodeInLibraryName("Lokio/Buffer;", "invoke-static {}, Lokio/Util;->x()V\n", "org.wikipedia"))   // a plain library class
        SecurityScanner.APP_CODE_IN_LIB_NAMES = false
        try { assertFalse(SecurityScanner.appCodeInLibraryName("Lokio/ByteString\$Companion;", merged, "org.wikipedia")) } finally { SecurityScanner.APP_CODE_IN_LIB_NAMES = true }   // mutation
    }
}
