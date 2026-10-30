package dev.apkrelab

import android.content.Context
import android.content.pm.PackageManager

/**
 * 0.69.0 (P2 groundwork): does a component's declared permission actually keep other apps out?
 *
 * A guard is SIGNATURE when only apps signed with the same key (or the system) can hold the permission: protectionLevel
 * signature / privileged / signatureOrSystem / internal / knownSigner. normal and dangerous permissions are WEAK: any app can
 * request them, so they slow an attacker down but do not stop one. No permission at all is NONE.
 *
 * Nothing here decides severity yet: it only answers "how strong is the guard", so the scan driver (0.69.1 / 0.69.2) can use it
 * to downgrade a finding or to leave a component out of the attacker-reachable entry set.
 */
class PermissionGuard(
    private val manifest: ManifestContext,
    /** Base protection level (0 normal, 1 dangerous, 2 signature, 3 signatureOrSystem, 4 internal) of a permission this manifest does not declare; null = unknown here. */
    private val systemLevel: (String) -> Int? = { null }
) {
    enum class Guard { NONE, WEAK, SIGNATURE }

    /** Which operation a provider sink performs; non-provider components ignore it. ANY = the weaker of read and write. */
    enum class Access { READ, WRITE, ANY }

    /** Guard strength of one permission name (null / empty = NONE). */
    fun strengthOf(permission: String?): Guard {
        if (permission.isNullOrEmpty()) return Guard.NONE
        manifest.declaredPerms[permission]?.let { return if (isSignatureLevel(it)) Guard.SIGNATURE else Guard.WEAK }
        val base = systemLevel(permission) ?: return Guard.WEAK   // declared by an app we cannot see: unknown -> do not downgrade on it
        return if (base >= 2) Guard.SIGNATURE else Guard.WEAK
    }

    /**
     * Guard of the component class [smaliType] ("Lcom/x/Foo;"). Several manifest entries can run the same class (an activity-alias
     * next to its target): the weakest EXPORTED entry decides, because any open entry point defeats the others. Unknown class -> NONE.
     */
    fun guardFor(smaliType: String, access: Access = Access.ANY): Guard {
        val entries = manifest.components.filter { manifest.smaliTypeOf(it) == smaliType }
        if (entries.isEmpty()) return Guard.NONE
        val relevant = entries.filter { it.exported }.ifEmpty { entries }
        return relevant.map { guardOf(it, access) }.minByOrNull { it.ordinal } ?: Guard.NONE
    }

    private fun guardOf(c: ManifestComponent, access: Access): Guard {
        if (c.tag != "provider") return strengthOf(c.permission)
        // android:readPermission / writePermission override android:permission for their own operation
        val read = strengthOf(c.readPermission ?: c.permission)
        val write = strengthOf(c.writePermission ?: c.permission)
        return when (access) {
            Access.READ -> read
            Access.WRITE -> write
            Access.ANY -> if (read.ordinal <= write.ordinal) read else write
        }
    }

    companion object {
        /** protectionLevel text from the decoded manifest: names joined with '|', or a raw number ("2", "0x12") when the enum was not resolved. */
        internal fun isSignatureLevel(level: String): Boolean {
            val t = level.trim()
            val n = if (t.startsWith("0x", true)) t.substring(2).toIntOrNull(16) else t.toIntOrNull()
            if (n != null) return (n and 0xF) >= 2
            return t.split('|').any {
                when (it.trim().lowercase()) {
                    "signature", "signatureorsystem", "system", "privileged", "internal", "knownsigner" -> true
                    else -> false
                }
            }
        }

        /** On-device resolver: asks the PackageManager for the base protection level of a permission declared outside this APK. */
        fun systemResolver(ctx: Context): (String) -> Int? {
            val pm = ctx.packageManager
            return { name ->
                try {
                    pm.getPermissionInfo(name, 0).protectionLevel and 0xF   // PROTECTION_MASK_BASE
                } catch (_: PackageManager.NameNotFoundException) {
                    null
                } catch (_: Throwable) {
                    null
                }
            }
        }
    }
}
