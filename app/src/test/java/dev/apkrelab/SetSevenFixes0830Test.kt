package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.83.0: library code repackaged into the app's own package, and two more known libraries (real-app set 7: Shizuku, FairEmail). */
class SetSevenFixes0830Test {

    private fun cls(name: String, body: String) = ".class public Lrikka/shizuku/$name;\n.super Ljava/lang/Object;\n.method public a()V\n    .locals 1\n$body\n    return-void\n.end method\n"

    private val fragMsg = "    const-string v0, \"Unable to instantiate fragment \"\n"

    @Test fun shortRenamedClassWithALibraryMarkerAndNoReadableAppReferencesIsALibrary() {
        assertTrue(SecurityScanner.isRepackagedLibrary("Lrikka/shizuku/Kc;", cls("Kc", fragMsg), "moe.shizuku.privileged.api"))
        assertEquals(SecurityScanner.Scope.LIB, SecurityScanner.scopeOfText("Lrikka/shizuku/Kc;", "moe.shizuku.privileged.api", cls("Kc", fragMsg)))
    }

    @Test fun readableNamesAndAppCodeThatMentionsAnAndroidxClassStayApp() {
        // a readable class name is the app's own, whatever strings it holds
        assertFalse(SecurityScanner.isRepackagedLibrary("Lcom/x/app/SyncWorker;", cls("SyncWorker", fragMsg), "com.x.app"))
        // short renamed app code with >= 3 references to readable classes of the app's package: app code
        val refs = (1..3).joinToString("") { "    new-instance v$it, Lcom/x/app/ui/LoginScreen$it;\n" }
        assertFalse(SecurityScanner.isRepackagedLibrary("Lcom/x/app/mu;", ".class public Lcom/x/app/mu;\n" + "    const-string v0, \"androidx.work.WorkerParameters\"\n" + refs, "com.x.app"))
        // short renamed class without any marker: unknown, stays as it was
        assertFalse(SecurityScanner.isRepackagedLibrary("Lrikka/shizuku/Kc;", cls("Kc", "    const-string v0, \"hello\"\n"), "moe.shizuku.privileged.api"))
    }

    @Test fun shortcutBadgerAndAppAuthAreLibraries() {
        for (t in listOf("Lme/leolin/shortcutbadger/impl/VivoHomeBadger;", "Lnet/openid/appauth/AuthState;"))
            assertEquals(t, SecurityScanner.Scope.LIB, SecurityScanner.scopeOf(t, "eu.faircode.email"))
    }

    @Test fun marketingAndAnalyticsSdksOfFintechAppsAreLibraries() {
        for (t in listOf("Lcom/braze/ui/BrazeWebViewActivity;", "Lcom/moengage/pushbase/activities/PushClickDialogTracker;", "Lcom/moe/pushlibrary/activities/MoEActivity;",
            "Lcom/dynatrace/android/agent/JavascriptAgentInterface;", "Lco/ab180/airbridge/internal/lifecycle/AirbridgeLifecycleProvider;"))
            assertEquals(t, SecurityScanner.Scope.LIB, SecurityScanner.scopeOf(t, "com.axispay.consumer"))
    }
}

