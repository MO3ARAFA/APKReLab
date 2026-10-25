package dev.apkrelab

import org.json.JSONArray
import org.json.JSONObject

/**
 * 0.51.0: SARIF 2.1.0 export of the scan findings (GitHub code scanning, VS Code SARIF viewer, DefectDojo, ...).
 * One run, one rule per distinct rule id, one result per finding. An AI "false positive" verdict is kept as a SARIF suppression
 * (kind "external") instead of dropping the finding, because the verdict is not stable between runs.
 */
object SarifExport {

    private fun level(f: SecurityScanner.Finding): String = when {
        f.severity.rank <= 1 -> "error"
        f.severity.rank == 2 -> "warning"
        else -> "note"
    }

    /** Stable rule id: the scanner's rule id, else a slug of the title (resource / legacy findings have no rule id). */
    internal fun ruleIdOf(f: SecurityScanner.Finding): String {
        if (f.ruleId.isNotEmpty()) return f.ruleId
        val slug = f.title.lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-').take(60)
        return "apkrelab-" + (if (slug.isEmpty()) "finding" else slug)
    }

    /** Smali class "Lcom/x/Y;" -> "com/x/Y.smali" (the path inside the decoded APK); manifest / resource findings keep their file name. */
    internal fun uriOf(f: SecurityScanner.Finding): String {
        val t = f.classType
        if (t != null) return "smali/" + t.removePrefix("L").removeSuffix(";") + ".smali"
        return if (f.file.isNotEmpty()) f.file else "AndroidManifest.xml"
    }

    /** GitHub code scanning reads `security-severity` (0.1 - 10.0) from the rule: critical > 9, high 7 - 8.9, medium 4 - 6.9, low below 4. */
    internal fun securitySeverity(sev: SecurityScanner.Severity): String = when (sev.rank) { 0 -> "9.5"; 1 -> "8.0"; 2 -> "5.5"; 3 -> "3.0"; else -> "1.0" }

    /** A key that survives a re-scan of the same app (GitHub / DefectDojo track an alert with it): rule, place and the title without the numbers a scan changes. */
    internal fun fingerprint(f: SecurityScanner.Finding, occurrence: Int = 0): String {
        // the start of the detail tells two findings of one rule in one class apart (the first characters of the value, the field name); digits are masked: a count changes between scans
        val key = ruleIdOf(f) + "|" + uriOf(f) + "|" + f.title.lowercase().replace(Regex("[0-9]+"), "#") + "|" + f.detail.take(90).lowercase().replace(Regex("[0-9]+"), "#") + (if (occurrence > 0) "|#" + occurrence else "")
        return java.security.MessageDigest.getInstance("SHA-256").digest(key.toByteArray()).joinToString("") { "%02x".format(it) }.take(32)
    }

    fun build(appPkg: String, toolVersion: String, findings: List<SecurityScanner.Finding>, verdict: Verdict.Lines? = null): String {
        val rules = JSONArray()
        val ruleIndex = HashMap<String, Int>()
        val results = JSONArray()
        val occurrences = HashMap<String, Int>()      // the n-th finding with the same key (two identical findings of one rule in one class) gets its own fingerprint
        for (f in findings) {
            val rid = ruleIdOf(f)
            if (rid !in ruleIndex) {
                ruleIndex[rid] = rules.length()
                val r = JSONObject()
                r.put("id", rid)
                r.put("name", f.title)
                r.put("shortDescription", JSONObject().put("text", f.title))
                r.put("fullDescription", JSONObject().put("text", f.detail.replace("\n", " ").take(400)))
                r.put("help", JSONObject().put("text", f.recommendation))
                if (f.cwe.startsWith("CWE-")) f.cwe.removePrefix("CWE-").toIntOrNull()?.let { r.put("helpUri", "https://cwe.mitre.org/data/definitions/$it.html") }
                r.put("defaultConfiguration", JSONObject().put("level", level(f)))
                val tags = JSONArray()
                if (f.cwe.isNotEmpty()) tags.put("external/cwe/" + f.cwe.lowercase())
                for (c in Masvs.controlsFor(f)) tags.put("external/masvs/" + c.lowercase())         // 0.92.0
                tags.put("security")
                r.put("properties", JSONObject().put("tags", tags).put("security-severity", securitySeverity(f.severity)).put("precision", FindingPolish.confidenceOf(f).lowercase().let { if (it == "high") "high" else if (it == "medium") "medium" else "low" }))
                rules.put(r)
            }
            val res = JSONObject()
            res.put("ruleId", rid)
            res.put("ruleIndex", ruleIndex[rid])
            res.put("level", level(f))
            val score = FindingScore.of(f)
            res.put("rank", score.value.toDouble())      // 0.69.3: SARIF 3.27.25 rank, 0.0..100.0, "priority within the run"
            res.put("message", JSONObject().put("text", f.title + ": " + f.detail.replace("\n", " ").take(1500)))
            // region.startLine: GitHub code scanning needs a line; a smali class / manifest finding has none, so 1 (the file) is used
            val loc = JSONObject().put("physicalLocation", JSONObject().put("artifactLocation", JSONObject().put("uri", uriOf(f))).put("region", JSONObject().put("startLine", 1)))
            f.classType?.let { loc.put("logicalLocations", JSONArray().put(JSONObject().put("fullyQualifiedName", it.removePrefix("L").removeSuffix(";").replace('/', '.')).put("kind", "type"))) }
            res.put("locations", JSONArray().put(loc))
            val base = fingerprint(f); val n = occurrences.getOrDefault(base, 0); occurrences[base] = n + 1
            res.put("partialFingerprints", JSONObject().put("apkrelab/v1", if (n == 0) base else fingerprint(f, n)))
            val props = JSONObject()
            props.put("severity", f.severity.label)
            props.put("confidence", FindingPolish.confidenceOf(f))
            props.put("priorityBand", score.band)
            props.put("priorityWhy", score.why)
            FindingScore.confidence(f).let { c -> props.put("confidenceScore", c.value); props.put("confidenceFactors", c.factors); props.put("confidenceWhy", c.why) }   // 1.2.0
            FixTemplates.match(f, appPkg)?.let { props.put("suggestedFix", it.sentence) }   // 1.2.0
            props.put("scope", f.scope.tag)
            if (f.cwe.isNotEmpty()) props.put("cwe", f.cwe)
            Masvs.controlsFor(f).takeIf { it.isNotEmpty() }?.let { props.put("masvs", JSONArray(it)) }
            if (f.reach.isNotEmpty()) props.put("reachFromExportedComponent", f.reach)
            if (f.verdict.isNotEmpty()) props.put("aiVerdict", f.verdict)
            if (f.count > 1) props.put("occurrences", f.count)
            res.put("properties", props)
            if (f.verdict == "FP") {
                val sup = JSONObject().put("kind", "external").put("status", "underReview")
                sup.put("justification", ("AI triage said false positive (not stable between runs): " + f.verdictNote.replace("\n", " ")).take(500))
                res.put("suppressions", JSONArray().put(sup))
            }
            results.put(res)
        }
        val driver = JSONObject()
        driver.put("name", "APK ReLab")
        driver.put("version", toolVersion)
        driver.put("rules", rules)
        val run = JSONObject()
        run.put("tool", JSONObject().put("driver", driver))
        run.put("results", results)
        val runProps = JSONObject().put("package", appPkg)
        if (verdict != null) { val v = JSONObject(); for ((k, x) in Verdict.properties(verdict)) v.put(k, x); runProps.put("verdict", v) }   // 1.2.0
        run.put("properties", runProps)
        run.put("automationDetails", JSONObject().put("id", "apkrelab/" + appPkg + "/"))
        run.put("invocations", JSONArray().put(JSONObject().put("executionSuccessful", true)))
        val root = JSONObject()
        root.put("\$schema", "https://json.schemastore.org/sarif-2.1.0.json")
        root.put("version", "2.1.0")
        root.put("runs", JSONArray().put(run))
        return root.toString(1)
    }
}
