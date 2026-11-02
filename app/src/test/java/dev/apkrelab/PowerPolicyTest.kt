package dev.apkrelab

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 2.1.3: the background index pauses only on a critically low battery, not because Battery Saver is on. */
class PowerPolicyTest {
    @Test fun criticallyLowBatteryPauses() {
        assertTrue(PowerPolicy.indexShouldPause(5, charging = false, powerSave = false))
        assertTrue(PowerPolicy.indexShouldPause(2, charging = false, powerSave = true))
    }

    @Test fun batterySaverAtANormalLevelDoesNotPause() {                       // the JustMarkets device report
        assertFalse(PowerPolicy.indexShouldPause(40, charging = false, powerSave = true))
        assertFalse(PowerPolicy.indexShouldPause(6, charging = false, powerSave = true))
    }

    @Test fun chargingOrUnknownLevelNeverPauses() {
        assertFalse(PowerPolicy.indexShouldPause(3, charging = true, powerSave = true))
        assertFalse(PowerPolicy.indexShouldPause(-1, charging = false, powerSave = true))
    }
}
