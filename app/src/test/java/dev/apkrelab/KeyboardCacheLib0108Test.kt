package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Test

/** 0.108.0: the keyboard-cache check skips the layouts of well-known libraries (Material's time / date pickers were reported in WE Wallet). */
class KeyboardCacheLib0108Test {
    private val xml = "<LinearLayout><EditText android:id=\"@+id/password\" /></LinearLayout>"
    private fun kc(path: String) = AndroGoatChecks.scanResourceXml(path, xml).count { it.title.startsWith("Keyboard cache") }

    @Test fun libraryLayoutsAreSkippedAndTheAppsAreNot() {
        assertEquals(0, kc("res/layout/material_time_input.xml"))
        assertEquals(0, kc("res/layout/mtrl_picker_text_input_date.xml"))
        assertEquals(1, kc("res/layout/fragment_login.xml"))                 // twin: the app's own screen
        assertEquals(1, kc("res/layout/my_material_login.xml"))              // twin: only a PREFIX names a library
    }
}
