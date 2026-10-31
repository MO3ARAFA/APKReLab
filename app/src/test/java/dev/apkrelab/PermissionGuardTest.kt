package dev.apkrelab

import dev.apkrelab.PermissionGuard.Access
import dev.apkrelab.PermissionGuard.Guard
import org.junit.Assert.assertEquals
import org.junit.Test

/** 0.69.0: manifest permission parsing and guard strength (no device needed: system permissions come from an injected resolver). */
class PermissionGuardTest {

    private val xml = """
        <manifest package="com.example.app">
          <permission android:name="com.example.SIG" android:protectionLevel="signature"/>
          <permission android:name="com.example.NRM" android:protectionLevel="normal"/>
          <permission android:name="com.example.PRIV" android:protectionLevel="signature|privileged"/>
          <application>
            <service android:name=".SigService" android:exported="true" android:permission="com.example.SIG"/>
            <service android:name="WeakService" android:exported="true" android:permission="com.example.NRM"/>
            <service android:name="com.example.app.OpenService" android:exported="true"/>
            <provider android:name=".P" android:exported="true"
                android:readPermission="com.example.SIG"/>
            <provider android:name=".P2" android:exported="true" android:permission="com.example.SIG"
                android:writePermission="com.example.NRM"/>
            <activity android:name=".Real" android:exported="false" android:permission="com.example.SIG"/>
            <activity-alias android:name=".Alias" android:targetActivity=".Real" android:exported="true"/>
            <service android:name=".SysService" android:exported="true" android:permission="android.permission.BIND_JOB_SERVICE"/>
          </application>
        </manifest>
    """.trimIndent()

    private val ctx = ManifestContext(xml)
    private val g = PermissionGuard(ctx) { if (it == "android.permission.BIND_JOB_SERVICE") 2 else null }

    @Test fun namesResolveToSmaliTypes() {
        assertEquals("Lcom/example/app/SigService;", ctx.smaliType(".SigService"))
        assertEquals("Lcom/example/app/WeakService;", ctx.smaliType("WeakService"))
        assertEquals("Lcom/example/app/OpenService;", ctx.smaliType("com.example.app.OpenService"))
    }

    @Test fun serviceGuards() {
        assertEquals(Guard.SIGNATURE, g.guardFor("Lcom/example/app/SigService;"))
        assertEquals(Guard.WEAK, g.guardFor("Lcom/example/app/WeakService;"))
        assertEquals(Guard.NONE, g.guardFor("Lcom/example/app/OpenService;"))
        assertEquals(Guard.NONE, g.guardFor("Lcom/example/app/Unknown;"))
    }

    @Test fun systemPermissionUsesResolver() {
        assertEquals(Guard.SIGNATURE, g.guardFor("Lcom/example/app/SysService;"))
        // phase 2: a platform BIND_* service permission is a guard even unresolved (ReportBuilder.defaultLevel); an unknown permission still never downgrades
        assertEquals(Guard.SIGNATURE, PermissionGuard(ctx).guardFor("Lcom/example/app/SysService;"))
        assertEquals(Guard.WEAK, PermissionGuard(ctx).strengthOf("com.other.UNKNOWN"))
    }

    @Test fun providerReadAndWriteAreIndependent() {
        assertEquals(Guard.SIGNATURE, g.guardFor("Lcom/example/app/P;", Access.READ))
        assertEquals(Guard.NONE, g.guardFor("Lcom/example/app/P;", Access.WRITE))
        assertEquals(Guard.NONE, g.guardFor("Lcom/example/app/P;", Access.ANY))     // the weaker of the two
        assertEquals(Guard.SIGNATURE, g.guardFor("Lcom/example/app/P2;", Access.READ))
        assertEquals(Guard.WEAK, g.guardFor("Lcom/example/app/P2;", Access.WRITE))
    }

    @Test fun exportedAliasWithoutPermissionDefeatsGuardedTarget() {
        assertEquals(Guard.NONE, g.guardFor("Lcom/example/app/Real;"))
    }

    @Test fun protectionLevelText() {
        assertEquals(true, PermissionGuard.isSignatureLevel("signature|privileged"))
        assertEquals(true, PermissionGuard.isSignatureLevel("0x12"))
        assertEquals(false, PermissionGuard.isSignatureLevel("dangerous"))
        assertEquals(false, PermissionGuard.isSignatureLevel("0x1"))
    }
}
