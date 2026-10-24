import dev.apkrelab.*
import java.io.File

fun main(args: Array<String>) {
    val pkg = args[1]
    val rules: List<ScanRule> = listOf(BroadcastUnprotectedSendRule, SqliteUnencryptedRule, WebviewPluginStateRule)
    var legacy = 0
    val counts = HashMap<String, Int>()
    File(args[0]).walkTopDown().filter { it.isFile && it.name.endsWith(".smali") }.forEach { f ->
        val text = f.readText()
        val m = Regex("^\\.class[^\\n]* (L[^;]+;)", RegexOption.MULTILINE).find(text) ?: return@forEach
        val ctx = RuleContext(m.groupValues[1], 0, text, pkg)
        if (ctx.scope != SecurityScanner.Scope.LIB && (text.contains("->sendBroadcast") || text.contains("->sendStickyBroadcast")))
            for (x in BroadcastUnprotectedSendRule.legacy(ctx)) { legacy++; println("  legacy  ${m.groupValues[1]} [${x.severity}]") }
        for (r in rules) for (x in r.scan(ctx)) {
            counts.merge(x.ruleId, 1, Int::plus)
            if (x.severity != SecurityScanner.Severity.INFO) println("${x.ruleId}  ${m.groupValues[1]}  [${x.severity}/${x.confidence}] ${x.detail.take(230)}")
        }
    }
    println("COUNTS $counts legacyBroadcast=$legacy")
    if (args.size > 2) {
        val r = ResourceScanner.scanApk(File(args[2]))
        r.findings.filter { it.ruleId == "tapjacking-sensitive-layout" }.forEach { println("TAPJ [${it.severity}/${it.confidence}] ${it.file} :: ${it.detail.take(260)}") }
        println("RES " + r.stats.take(200))
    }
}
