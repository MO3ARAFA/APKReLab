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

    fun build(appPkg: String, toolVersion: String, findings: List<SecurityScanner.Finding>): String {
        val rules = JSONArray()
        val seen = HashSet<String>()
        val results = JSONArray()
        for (f in findings) {
            val rid = ruleIdOf(f)
            if (seen.add(rid)) {
                val r = JSONObject()
                r.put("id", rid)
                r.put("name", f.title)
                r.put("shortDescription", JSONObject().put("text", f.title))
                r.put("help", JSONObject().put("text", f.recommendation))
                val tags = JSONArray()
                if (f.cwe.isNotEmpty()) tags.put("external/cwe/" + f.cwe.lowercase())
                tags.put("security")
                r.put("properties", JSONObject().put("tags", tags))
                rules.put(r)
            }
            val res = JSONObject()
            res.put("ruleId", rid)
            res.put("level", level(f))
            val score = FindingScore.of(f)
            res.put("rank", score.value.toDouble())      // 0.69.3: SARIF 3.27.25 rank, 0.0..100.0, "priority within the run"
            res.put("message", JSONObject().put("text", f.title + ": " + f.detail.replace("\n", " ").take(1500)))
            val loc = JSONObject().put("physicalLocation", JSONObject().put("artifactLocation", JSONObject().put("uri", uriOf(f))))
            res.put("locations", JSONArray().put(loc))
            val props = JSONObject()
            props.put("severity", f.severity.label)
            props.put("confidence", FindingPolish.confidenceOf(f))
            props.put("priorityBand", score.band)
            props.put("priorityWhy", score.why)
            props.put("scope", f.scope.tag)
            if (f.cwe.isNotEmpty()) props.put("cwe", f.cwe)
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
        driver.put("informationUri", "https://github.com/")
        driver.put("rules", rules)
        val run = JSONObject()
        run.put("tool", JSONObject().put("driver", driver))
        run.put("results", results)
        run.put("properties", JSONObject().put("package", appPkg))
        val root = JSONObject()
        root.put("\$schema", "https://json.schemastore.org/sarif-2.1.0.json")
        root.put("version", "2.1.0")
        root.put("runs", JSONArray().put(run))
        return root.toString(1)
    }
}
