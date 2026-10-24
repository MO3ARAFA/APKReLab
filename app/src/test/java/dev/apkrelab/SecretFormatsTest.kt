package dev.apkrelab

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * 0.89.0: the vendor token formats against the LITERAL true / false positives that gitleaks keeps for its own rules (tools/secrets/gen_secret_formats.py extracts them;
 * the samples built with random generators are not in the file).
 */
class SecretFormatsTest {
    private fun file(rel: String) = listOf(File("src/$rel"), File("app/src/$rel")).first { it.exists() }

    private fun load(): Int = SecretFormats.load(file("main/assets/secret_formats.json").readText())

    @Test fun nearlyEveryRuleCompilesInJava() {
        val n = load()
        assertTrue("rules loaded: $n", n >= 200)
        assertTrue("did not compile: " + SecretFormats.failedToCompile, SecretFormats.failedToCompile.size <= 3)
    }

    @Test fun literalSamplesOfTheRuleSetAreDetectedAndTheLiteralFalsePositivesAreNot() {
        load()
        val s = JSONObject(file("test/resources/secret_samples.json").readText())
        var tp = 0; var tpMiss = 0; var fp = 0; var fpHit = 0
        val miss = ArrayList<String>(); val fpl = ArrayList<String>()
        for (rid in s.keys().asSequence().map { it as String }.toList()) {
            val o = s.getJSONObject(rid)
            val tps = o.getJSONArray("tps"); val fps = o.getJSONArray("fps")
            for (i in 0 until tps.length()) {
                val kind = tps.getJSONArray(i).getString(0); val text = tps.getJSONArray(i).getString(1)
                tp++
                // "gen": gitleaks wraps (identifier, value) in a handful of source shapes; the sample counts when ANY of them is detected
                val tries = if (kind == "gen") text.split('\u0000').let { (i, v) -> listOf("${i}_api_token = \"$v\"", "${i}Token = \"$v\"", "${i}Token=$v", "${i}_token: $v", "\"${i}_token\": \"$v\"", "String ${i}Token = \"$v\";") } else listOf(text)
                if (tries.none { t -> SecretFormats.scan(t).any { it.ruleId == rid } }) { tpMiss++; if (miss.size < 40) miss.add("$rid [$kind] " + text.take(70).replace('\u0000', '|')) }
            }
            for (i in 0 until fps.length()) {
                fp++
                if (SecretFormats.scan(fps.getString(i)).any { it.ruleId == rid }) { fpHit++; if (fpl.size < 40) fpl.add("$rid " + fps.getString(i).take(70)) }
            }
        }
        println("SECRETFORMATS tp=$tp missed=$tpMiss | fp=$fp wrongly-hit=$fpHit")
        miss.forEach { println("  MISS $it") }; fpl.forEach { println("  FPHIT $it") }
        assertTrue("true positives missed: $tpMiss of $tp", tpMiss * 100 <= tp * 8)         // at most 8% (context-only samples, see the printed list)
        assertTrue("false positives hit: $fpHit of $fp", fpHit * 100 <= fp * 3)
    }
}
