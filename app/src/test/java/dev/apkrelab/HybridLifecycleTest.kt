package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 2.0.2: the Hybrid inspection is filled by the resource scan (APK load) and must not be cleared when a code scan starts. MainActivity cannot run on the JVM, so this
 * is a source-level guard for the one line that went wrong in 2.0.0 / 2.0.1, plus the behaviour of the two clear functions.
 */
class HybridLifecycleTest {
    private fun main(): String = listOf(File("src/main/java/dev/apkrelab/MainActivity.kt"), File("app/src/main/java/dev/apkrelab/MainActivity.kt")).first { it.exists() }.readText()

    @Test fun mainActivityClearsTheInspectionWhenAnApkIsLoadedAndNeverWhenAScanStarts() {
        val src = main()
        assertFalse("the code scan must not call HybridInspector.clear()", src.contains("HybridInspector.clear()"))
        val load = src.indexOf("NativeBridge.clearApk()")
        assertTrue(load > 0)
        val near = src.substring(load, minOf(src.length, load + 900))
        assertTrue("clearApk() sits next to NativeBridge.clearApk() and before scanResourcesAsync()", near.contains("HybridInspector.clearApk()") && near.indexOf("HybridInspector.clearApk()") < near.indexOf("scanResourcesAsync()"))
    }

    @Test fun clearApkDropsTheResult() {
        HybridInspector.current = HybridInspector.HybridResult(emptyList())
        assertNotNull(HybridInspector.current)
        HybridInspector.clearApk()
        assertEquals(null, HybridInspector.current)
    }
}
