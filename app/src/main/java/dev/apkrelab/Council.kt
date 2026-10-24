package dev.apkrelab

import android.content.SharedPreferences

/**
 * verdict: edits -> APPROVE | FIX | REJECT ; findings -> CONFIRM | DOWNGRADE.
 * summary: short plain-English text for the user. fixed: replacement for the edit's "modified" snippet (only when verdict == FIX).
 * roles: e.g. "analyst Gemini/x | critic OpenRouter/y | judge Groq/z".
 */
class CouncilResult(val verdict: String, val summary: String, val fixed: String, val roles: String)

/**
 * 0.29.0: multi-model council for the HARD tasks only (agent edits, confirmed security findings).
 * Three roles, each a different model whenever the user has enough models/providers:
 *   analyst = the model that produced the proposal/verdict (already done by the caller),
 *   critic  = tries to find what is wrong with it,
 *   judge   = reads proposal + critique and decides.
 * Two extra AI calls per review. The council never applies anything: the user still taps Apply.
 */
object Council {
    fun enabled(p: SharedPreferences): Boolean = p.getBoolean("council", true)

    private const val ROLE_NOTE = "Answer with ONE JSON object only (no prose, no markdown fences). Write free-text fields in plain English, short; keep identifiers, registers and code in English."

    /** Keeps the start of the method (.method / .locals lines) plus a window around the edit when the method is long. */
    private fun excerptAround(method: String, editStart: Int, editEnd: Int, max: Int = 7000): String {
        if (method.length <= max) return method
        val head = method.take(500)
        val from = (editStart - 2500).coerceAtLeast(500)
        val to = (editEnd + 2500).coerceAtMost(method.length)
        if (from >= to) return method.take(max)
        return head + "\n    # ... (method shortened) ...\n" + method.substring(from, to)
    }

    fun methodExcerpt(method: String, editStart: Int, editEnd: Int): String = excerptAround(method, editStart, editEnd)

    /** Critic, then judge. Returns null if the council could not run (all providers failed or answers unusable): the caller then continues without it. */
    fun reviewEdit(
        p: SharedPreferences, userGoal: String, cname: String,
        methodBefore: String, methodAfter: String, modified: String,
        explanation: String, risk: String, analyst: String, progress: (String) -> Unit
    ): CouncilResult? {
        val proposal = "Class: $cname\nUser goal: ${userGoal.take(600)}\nAnalyst explanation: ${explanation.take(600)}\nAnalyst risk note: ${risk.take(300)}\n\n" +
            "METHOD BEFORE the edit:\n$methodBefore\n\nMETHOD AFTER the edit:\n$methodAfter\n"
        val criticPrompt = "You are the CRITIC in a code-review council for an EDUCATIONAL smali-editing tool (the user edits apps they own or may analyze). " +
            "Another model proposed the smali edit below. Your job is to find what is WRONG with it. Check, in this order:\n" +
            "1. Smali validity: every register used exists (.locals/.registers vs v#/p# used), types match the invoke/field signatures, move-result follows invoke, labels used are defined, no broken try/catch ranges, no changed .class line.\n" +
            "2. Does the edit really do what the user goal asks? Is it the SMALLEST change that does it?\n" +
            "3. Side effects: crashes, changed return types/values elsewhere, infinite loops, skipped cleanup, behaviour broken for other callers.\n" +
            "4. Out of scope: anything that bypasses licensing, DRM, payment or security protections is a BLOCKER.\n" +
            "Be concrete and skeptical; do not praise. If you find nothing wrong, say so.\n" +
            "Return: {\"verdict\":\"OK|PROBLEMS\",\"problems\":[{\"severity\":\"BLOCKER|MINOR\",\"what\":\"\"}],\"better_modified\":\"\"}\n" +
            "\"better_modified\" = a corrected replacement for the edited snippet ONLY if you are sure of a fix, otherwise empty.\n$ROLE_NOTE\n\n$proposal"
        progress("⚖️ Council: critic is reviewing the edit...")
        val critic = Team.callAvoiding(p, criticPrompt, setOf(analyst)) { _ -> }
        val criticJson = Agent.firstJsonObject(critic.text) ?: return null
        val criticLabel = critic.label
        // Fast path: clean review with no problems at all -> no need to spend a third call.
        val criticOk = criticJson.optString("verdict").uppercase().contains("OK") &&
            (criticJson.optJSONArray("problems")?.length() ?: 0) == 0
        if (criticOk) {
            return CouncilResult("APPROVE", "The critic (" + criticLabel + ") reviewed the edit and found no issues.", "", "analyst $analyst | critic $criticLabel")
        }
        val judgePrompt = "You are the JUDGE in a code-review council for an EDUCATIONAL smali-editing tool. An analyst proposed an edit; a critic reviewed it. " +
            "Decide independently using the code, not just the critic's opinion (critics can be wrong or nit-picky):\n" +
            "- APPROVE: the edit is valid and does what the user wants (minor nits are fine).\n" +
            "- FIX: the edit has a real problem you can correct. Put the corrected replacement of the edited snippet in \"fixed_modified\" (same scope as the original edit; full text, not a diff).\n" +
            "- REJECT: the edit is broken, unsafe, out of scope, or cannot be fixed with a small change.\n" +
            "Return: {\"verdict\":\"APPROVE|FIX|REJECT\",\"summary\":\"one or two short sentences for the user\",\"fixed_modified\":\"\"}\n$ROLE_NOTE\n\n" +
            proposal + "\nEDITED SNIPPET (analyst's \"modified\"):\n" + modified.take(3000) +
            "\n\nCRITIC (" + criticLabel + ") said:\n" + criticJson.toString().take(2500)
        progress("⚖️ Council: judge is deciding...")
        val judge = try {
            Team.callAvoiding(p, judgePrompt, setOf(analyst, criticLabel)) { _ -> }
        } catch (_: Throwable) { null }
        val jo = judge?.let { Agent.firstJsonObject(it.text) }
        if (judge == null || jo == null) {
            // Judge unavailable: fall back to the critic alone, conservatively (any BLOCKER -> REJECT, otherwise approve with the notes).
            val probs = criticJson.optJSONArray("problems")
            var blocker = false
            val sb = StringBuilder()
            if (probs != null) for (i in 0 until probs.length()) {
                val o = probs.optJSONObject(i) ?: continue
                if (o.optString("severity").uppercase().contains("BLOCKER")) blocker = true
                sb.append(o.optString("what")).append(' ')
            }
            return CouncilResult(if (blocker) "REJECT" else "APPROVE", "Judge unavailable; critic’s (" + criticLabel + ") opinion: " + sb.toString().trim().take(300),
                "", "analyst $analyst | critic $criticLabel | judge unavailable")
        }
        val v = jo.optString("verdict").uppercase().let { when { it.contains("REJECT") -> "REJECT"; it.contains("FIX") -> "FIX"; else -> "APPROVE" } }
        val fixed = if (v == "FIX") jo.optString("fixed_modified") else ""
        val verdict = if (v == "FIX" && fixed.isBlank()) "REJECT" else v
        return CouncilResult(verdict, jo.optString("summary").trim().ifEmpty { "(no summary)" }, fixed,
            "analyst $analyst | critic $criticLabel | judge ${judge.label}")
    }

    /** Second opinion on a finding the first AI marked TRUE_POSITIVE. DOWNGRADE means "the council disagrees: needs human review". Null = council could not run. */
    fun checkFinding(
        p: SharedPreferences, title: String, cwe: String, detail: String, location: String,
        reach: String, code: String, analystReason: String, analyst: String, progress: (String) -> Unit
    ): CouncilResult? {
        val case = "Finding: $title $cwe\nWhy flagged: ${detail.take(900)}\nClass: $location\n$reach\n\nCode (enclosing method, and for a data-flow finding the method where the value is read):\n$code\n\n" +
            "FIRST ANALYST said TRUE_POSITIVE because: ${analystReason.take(500)}"
        val criticPrompt = "You are the CRITIC in a security-triage council for an EDUCATIONAL static-analysis tool (smali from an app the user owns or may analyze). " +
            "A first model marked this finding TRUE_POSITIVE. Argue against it as hard as the code honestly allows: is it library/boilerplate code? is the dangerous input NOT attacker-controlled? " +
            "is the dangerous call unused or guarded? is it only theoretical? If the weakness really is intrinsic (always-true hostname verifier, hardcoded key, cleartext traffic) or attacker input demonstrably reaches it, say the analyst is right.\n" +
            "Return: {\"analyst_is_right\":true,\"reason\":\"\"}\n$ROLE_NOTE\n\n$case"
        progress("⚖️ Council: critic is reviewing the finding...")
        val critic = Team.callAvoiding(p, criticPrompt, setOf(analyst)) { _ -> }
        val co = Agent.firstJsonObject(critic.text) ?: return null
        val agrees = co.optBoolean("analyst_is_right", true)
        val criticLabel = critic.label
        if (agrees) {
            return CouncilResult("CONFIRM", "The critic (" + criticLabel + ") agreed: " + co.optString("reason").trim().take(200), "", "analyst $analyst | critic $criticLabel")
        }
        val judgePrompt = "You are the JUDGE in a security-triage council. A first model said TRUE_POSITIVE, a critic disagreed. Decide from the code, not from authority. " +
            "CONFIRM only if the weakness is intrinsic or attacker-controlled input demonstrably reaches it; otherwise DOWNGRADE (needs human review).\n" +
            "Return: {\"verdict\":\"CONFIRM|DOWNGRADE\",\"summary\":\"one or two short sentences\"}\n$ROLE_NOTE\n\n$case\n\nCRITIC (" + criticLabel + ") said:\n" + co.toString().take(1500)
        progress("⚖️ Council: judge is deciding...")
        val judge = try {
            Team.callAvoiding(p, judgePrompt, setOf(analyst, criticLabel)) { _ -> }
        } catch (_: Throwable) { null }
        val jo = judge?.let { Agent.firstJsonObject(it.text) }
        if (judge == null || jo == null) {
            // No judge: a critic that disagrees is enough to ask for a human look, but not to dismiss the finding.
            return CouncilResult("DOWNGRADE", "The critic (" + criticLabel + ") objected: " + co.optString("reason").trim().take(200) + " (judge unavailable)", "", "analyst $analyst | critic $criticLabel | judge unavailable")
        }
        val verdict = if (jo.optString("verdict").uppercase().contains("CONFIRM")) "CONFIRM" else "DOWNGRADE"
        return CouncilResult(verdict, jo.optString("summary").trim().take(260), "", "analyst $analyst | critic $criticLabel | judge ${judge.label}")
    }
}
