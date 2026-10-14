package dev.apkrelab

/**
 * "Harden with AI" prompt builder (defensive-only).
 *
 * Builds the prompt for hardening ONE scanner finding in the open class. The reply is the JSON
 * shape of MainActivity's Suggestion and goes through the same verbatim-match + diff dialog +
 * Apply + Council review as every other AI edit. No exploit code or payloads are ever requested.
 * (0.48.3: the unused data model and buildPrompt() of 0.29.0 were removed; nothing referenced them.)
 */
object VulnHunter {

    // ---------------------------------------------------------------------
    // Remediation ("Harden with AI") — reuses the app's existing propose_edit
    // pipeline (verbatim-match locate -> diff dialog -> Apply -> Council review)
    // instead of a separate code generator, so every applied patch goes through
    // the same human-in-the-loop safety check as every other AI edit in the app.
    // The returned JSON schema matches MainActivity's Suggestion exactly:
    // {"original":"","modified":"","explanation":"","risk":""}
    // ---------------------------------------------------------------------

    /**
     * Builds the prompt for hardening ONE existing scanner finding (SecurityScanner.Finding) in the
     * currently open class. Defensive-only: validation, sanitization, safe defaults. No exploit code,
     * no payloads, no attack-oriented content, by construction of the prompt.
     */
    fun buildHardenPrompt(
        findingTitle: String,
        findingSeverity: String,
        findingCwe: String,
        findingDetail: String,
        findingRecommendation: String,
        smaliClassCode: String
    ): String {
        return "You are a mobile application security engineer proposing a DEFENSIVE smali patch for an " +
            "Android app the user owns or is allowed to analyze. A static scanner flagged this finding in " +
            "the class below; your job is to propose the smallest smali change that closes the gap.\n\n" +
            "Finding: $findingTitle [$findingSeverity]${if (findingCwe.isNotBlank()) " $findingCwe" else ""}\n" +
            "Why flagged: ${findingDetail.take(500)}\n" +
            "Suggested direction: ${findingRecommendation.take(300)}\n\n" +
            "Rules:\n" +
            "- The change must be purely defensive: input validation, allowlisting, safe defaults, a " +
            "secure API in place of a dangerous one, or similar hardening. Never produce attack code, " +
            "payloads, obfuscation, or anything that weakens a check.\n" +
            "- Change only a few lines. Never touch the .class / .super lines.\n" +
            "- Keep register usage valid: do not reference registers beyond the method's .locals/.registers; " +
            "if the hardening genuinely needs a new local, raise .locals by the right amount in the same edit.\n" +
            "- \"original\" must be copied VERBATIM from the code below (same indentation) and appear EXACTLY " +
            "ONCE; include enough lines (e.g. the enclosing .method line) to make it unique. \"modified\" is " +
            "its replacement.\n" +
            "- If the finding looks like a false positive on closer reading of this code, return an empty " +
            "\"original\" and say why in \"explanation\".\n" +
            "- \"risk\" is one short sentence: what could this patch break (compatibility, behavior change)?\n" +
            "- Return JSON only, no prose, no markdown fences: {\"original\":\"\",\"modified\":\"\",\"explanation\":\"\",\"risk\":\"\"}\n" +
            "- Write \"explanation\" and \"risk\" in plain English; keep code in English.\n\n" +
            "Code:\n" + smaliClassCode.take(80_000)
    }
}
