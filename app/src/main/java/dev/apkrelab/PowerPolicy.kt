package dev.apkrelab

/**
 * 2.1.3: when the background class index waits for the battery. Before (0.37.6) it paused below 20% OR whenever Battery Saver was on; on a phone that keeps
 * Battery Saver on all the time (JustMarkets device report: "Index paused at 2/59667 (low battery or battery saver)") the index never ran.
 * Now: it pauses only when the battery is critically low (at most 5%) and the phone is not charging. Battery Saver alone does not pause it.
 */
object PowerPolicy {
    const val CRITICAL_PCT = 5

    /** [levelPct] = battery percentage (negative = unknown); [powerSave] is accepted but no longer decides. */
    @Suppress("UNUSED_PARAMETER")
    fun indexShouldPause(levelPct: Int, charging: Boolean, powerSave: Boolean): Boolean =
        !charging && levelPct in 0..CRITICAL_PCT
}
