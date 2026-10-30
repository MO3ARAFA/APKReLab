package dev.apkrelab

import dev.apkrelab.ir.Insn
import dev.apkrelab.ir.SmaliParser
import dev.apkrelab.ir.SsaForm
import java.util.concurrent.ConcurrentHashMap

/**
 * 1.1.0: receivers registered at run time (Context.registerReceiver / ContextCompat.registerReceiver) and what keeps other apps from sending them an Intent.
 *
 * A dynamic receiver is not in the manifest, so the attack surface rules never saw how it is protected; its onReceive Intent was treated as input from any app.
 * Two protections are recognised, from the call site's own arguments on the method's SSA form:
 *  - a broadcastPermission argument (a constant string) that the manifest declares with a signature level, or a platform signature permission: only the same
 *    signer or the system can send it, on every Android version;
 *  - the RECEIVER_NOT_EXPORTED flag (4), which Android applies from API 33 on: protective only when the app's minSdk is 33 or more.
 * The receiver's class comes from the argument's static type (a new-instance, a field of that exact type, a cast). A class registered at least once without
 * either protection is never counted as protected.
 */
object DynamicReceivers {
    private const val NOT_EXPORTED = 4
    private val registered = ConcurrentHashMap<String, MutableList<Pair<String?, Int?>>>()   // receiver class -> (permission, flags) of each registration

    fun clear() = registered.clear()

    /** Called with the text of every class of the full scan; thread-safe. Only classes that call registerReceiver are parsed. */
    fun observe(text: String) {
        if (!text.contains("registerReceiver(")) return
        val c = try { SmaliParser.parse(text) } catch (_: Throwable) { return }
        val fieldConst = constantFields(c)
        for (m in c.methods) {
            if (m.insns.none { it.kind == Insn.Kind.INVOKE && it.ref.contains("->registerReceiver(") }) continue
            val ssa = try { SsaForm.build(m) } catch (_: Throwable) { continue }
            for (insn in m.insns) {
                if (insn.kind != Insn.Kind.INVOKE || !insn.ref.contains("->registerReceiver(")) continue
                val desc = insn.ref.substringAfter("registerReceiver")
                val compat = insn.invokeKind() == "static"                 // ContextCompat.registerReceiver(context, receiver, filter, ...)
                val us = ssa.usesOf(insn)
                val ri = 1                                               // instance call: u[0] = the context, u[1] = the receiver; static (ContextCompat): the same order
                val recvType = staticType(ssa, us.getOrNull(ri)) ?: continue
                val params = paramTypes(desc)
                // the argument registers after the receiver: find a String (the permission) and the last int (the flags) by the declared parameter types
                var permission: String? = null; var flags: Int? = null
                var reg = if (compat) 0 else 1                            // register index of the first declared parameter
                for (p in params) {
                    val v = us.getOrNull(reg)
                    if (p == "Ljava/lang/String;") permission = constString(v) ?: v?.def?.takeIf { it.kind == Insn.Kind.FIELD_GET }?.let { fieldConst[it.ref] }
                    if (p == "I") flags = constInt(v)
                    reg += if (p == "J" || p == "D") 2 else 1
                }
                registered.getOrPut(recvType) { java.util.Collections.synchronizedList(ArrayList()) }.add(permission to flags)
            }
        }
    }

    /** Receiver classes whose EVERY registration is protected (see the class comment). [isSignature] = the manifest / platform level of a permission name. */
    fun protectedReceivers(minSdk: Int, isSignature: (String) -> Boolean): Set<String> {
        val out = HashSet<String>()
        for ((t, regs) in registered) {
            val all = synchronized(regs) { regs.toList() }
            if (all.isNotEmpty() && all.all { (perm, flags) -> (perm != null && isSignature(perm)) || (minSdk >= 33 && flags != null && (flags and NOT_EXPORTED) != 0) }) out.add(t)
        }
        return out
    }

    /** Lowers taint cards whose source is the Intent a protected receiver class received. Returns how many. */
    fun lower(list: List<SecurityScanner.Finding>, protectedTypes: Set<String>): Int {
        var n = 0
        val received = Regex("^Data from Intent\\.get[A-Za-z]*\\(")
        for (f in list) {
            val t = f.classType ?: continue
            if (t !in protectedTypes || !f.ruleId.startsWith("taint") || !received.containsMatchIn(f.detail) || f.severity.rank > 2) continue
            if (f.sourceMethod.isNotEmpty() && !f.sourceMethod.startsWith(t)) continue
            f.severity = SecurityScanner.Severity.LOW
            f.confidence = "LOW"
            f.adjusted = (if (f.adjusted.isNotEmpty()) f.adjusted + " " else "") + "Lowered to LOW: this receiver is registered at run time only with a signature-level broadcast permission " +
                "(or RECEIVER_NOT_EXPORTED with minSdk 33+), so no other app can send it this Intent; only the app itself and the system can."
            n++
        }
        return n
    }

    /** String fields of this class that every write in the class sets to one and the same constant (a Kotlin `private val x = "..."`). */
    private fun constantFields(c: dev.apkrelab.ir.ClassIr): Map<String, String> {
        val values = HashMap<String, String?>()
        for (m in c.methods) {
            if (m.insns.none { it.kind == Insn.Kind.FIELD_PUT && it.ref.endsWith(":Ljava/lang/String;") }) continue
            val ssa = try { SsaForm.build(m) } catch (_: Throwable) { continue }
            for (insn in m.insns) {
                if (insn.kind != Insn.Kind.FIELD_PUT || !insn.ref.endsWith(":Ljava/lang/String;")) continue
                val v = constString(ssa.usesOf(insn).firstOrNull())
                values[insn.ref] = if (!values.containsKey(insn.ref)) v else if (values[insn.ref] == v) v else null
            }
        }
        val out = HashMap<String, String>()
        for ((k, v) in values) if (v != null) out[k] = v
        return out
    }

    private fun staticType(ssa: SsaForm, v0: SsaForm.Value?): String? {
        var v = v0
        for (i in 0 until 8) {
            val d = v?.def ?: return null
            when (d.kind) {
                Insn.Kind.NEW_INSTANCE -> return d.ref
                // a cast to the base type says nothing (Kotlin casts an anonymous receiver held in a field back to BroadcastReceiver): the operand's type does
                Insn.Kind.CHECK_CAST -> if (d.ref.trim() == "Landroid/content/BroadcastReceiver;") v = ssa.usesOf(d).firstOrNull() else return d.ref
                Insn.Kind.FIELD_GET -> return d.ref.substringAfterLast(':').takeIf { it != "Landroid/content/BroadcastReceiver;" }
                Insn.Kind.MOVE -> v = ssa.usesOf(d).firstOrNull()
                else -> return null
            }
        }
        return null
    }

    private fun constString(v: SsaForm.Value?): String? {
        val d = v?.def ?: return null
        return if (d.kind == Insn.Kind.CONST && d.op.startsWith("const-string")) d.ref.trim().removeSurrounding("\"") else null
    }

    private fun constInt(v: SsaForm.Value?): Int? {
        val d = v?.def ?: return null
        if (d.kind != Insn.Kind.CONST || d.op.startsWith("const-string") || d.op.startsWith("const-class")) return null
        return try { java.lang.Long.decode(d.ref.trim()).toInt() } catch (_: Throwable) { null }
    }

    private fun paramTypes(desc: String): List<String> {
        val out = ArrayList<String>()
        var i = desc.indexOf('(') + 1; val e = desc.indexOf(')')
        while (i in 1 until e) {
            val s = i
            while (desc[i] == '[') i++
            if (desc[i] == 'L') i = desc.indexOf(';', i)
            i++
            out.add(desc.substring(s, i))
        }
        return out
    }
}
