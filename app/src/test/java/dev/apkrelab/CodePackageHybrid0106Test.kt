package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * 0.106.0: hybrid apps (Flutter, React Native, Expo) keep a handful of Java classes in their own package and big readable plugin packages next to them. Axis Pay's code package
 * came out as a Flutter plugin's (com.visionflutter): its own MainActivity was "origin unknown" in the posture table. Found the same in 5 apps of the F-Droid corpus.
 */
class CodePackageHybrid0106Test {
    private fun many(prefix: String, n: Int) = (1..n).map { "L$prefix/C$it;" }

    @Test fun aPluginPackageWithNoComponentDoesNotBeatTheAppsOwnFewClasses() {
        val types = many("com/visionflutter/plugin", 60) + listOf("Lcom/axispay/consumer/wallet/MainActivity;", "Lcom/axispay/consumer/wallet/MainApplication;") + many("a", 10)
        val comps = listOf("Lcom/axispay/consumer/wallet/MainActivity;", "Lcom/axispay/consumer/wallet/CardDetailsActivity;", "Lae/network/x/A;", "Lae/network/x/B;", "Ldev/fluttercommunity/C;")
        assertEquals("com.axispay.consumer.wallet", SecurityScanner.codePackage(types, "com.axispay.consumer.wallet", comps))
        // 1.1.0: com/visionflutter/ is a library prefix now, so even without component evidence the app's own package wins
        assertEquals("com.axispay.consumer.wallet", SecurityScanner.codePackage(types, "com.axispay.consumer.wallet"))
        // twin: without component evidence the old rule still applies to a package NOT in the library list (a big readable package with 4x the manifest prefix's classes wins)
        val other = many("com/someplugin/plugin", 60) + types.drop(60)
        assertEquals("com.someplugin", SecurityScanner.codePackage(other, "com.axispay.consumer.wallet"))
    }

    @Test fun theLauncherActivityKeepsTheAppsPackageAgainstPluginComponents() {
        val types = many("expo/modules/core", 80) + listOf("Lcom/paperless/mobile/MainActivity;", "Lcom/paperless/mobile/MainApplication;")
        val comps = listOf("Lcom/paperless/mobile/MainActivity;") + (1..5).map { "Lexpo/modules/p$it/Provider;" }
        val launcher = listOf("Lcom/paperless/mobile/MainActivity;")
        assertEquals("com.paperless.mobile", SecurityScanner.codePackage(types, "com.paperless.mobile", comps, launcher))
        assertEquals("expo.modules", SecurityScanner.codePackage(types, "com.paperless.mobile", comps))                      // twin: no launcher known, the components vote
        // twin: a white-label app whose launcher lives in its real code package keeps that package
        val wl = many("com/emeint/android", 80) + listOf("Lcom/TE/WEWallet/R;")
        val wlComps = (1..10).map { "Lcom/emeint/android/A$it;" }
        assertEquals("com.emeint", SecurityScanner.codePackage(wl, "com.TE.WEWallet", wlComps, listOf("Lcom/emeint/android/A1;")))
    }
}
