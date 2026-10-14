import dev.apkrelab.*
import java.io.File
import java.util.zip.ZipFile

/** Sandbox approximation of the device Smart scan: code rules per class, manifest rules, resource rules, SSA taint flows -> Markdown report. No AI triage, no reach labels. */
fun main(args: Array<String>) {
    val decDir = File(args[0]); val apk = File(args[1]); val outMd = File(args[2])
    val manifest = ZipFile(apk).use { z -> Axml.decode(z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes()) } ?: error("manifest")
    val mc = ManifestContext(manifest)
    val pkg = Regex("package=\"([^\"]+)\"").find(manifest)?.groupValues?.get(1) ?: ""
    val all = ArrayList<SecurityScanner.Finding>()
    all.addAll(SecurityScanner.scanManifest(manifest))
    val texts = ArrayList<Pair<String, String>>()
    decDir.walkTopDown().filter { it.isFile && it.name.endsWith(".smali") }.forEach { f ->
        val text = f.readText()
        val type = Regex("^\\.class[^\\n]* (L[^;]+;)", RegexOption.MULTILINE).find(text)?.groupValues?.get(1) ?: return@forEach
        texts.add(type to text)
    }
    for ((i, p) in texts.withIndex()) all.addAll(SecurityScanner.scanSmali(p.first, i, p.second, pkg))
    all.addAll(ResourceScanner.scanApk(apk).findings)
    // SSA taint flows
    val entries = mc.exportedComponents.map { mc.smaliTypeOf(it) }
    // big apps: "nossa" skips the whole-app SSA here (the device groups it with ScopePlanner; measure it with MeasureBig instead)
    val items = if (args.size > 3 && args[3] == "nossa") emptyList() else
        dev.apkrelab.ir.SsaBridge.newFlows(texts.filter { (args.size > 3 && args[3] == "withlibs") || SecurityScanner.scopeOf(it.first, pkg) != SecurityScanner.Scope.LIB }.map { dev.apkrelab.ir.SmaliParser.parse(it.second) }, entries, ArrayList<dev.apkrelab.ir.TaintIr.Old>())
    val idx = texts.withIndex().associate { it.value.first to it.index }
    for (item in items) {
        val sev = SecurityScanner.Severity.values().firstOrNull { it.label == item.sev } ?: SecurityScanner.Severity.HIGH
        val f = SecurityScanner.Finding(sev, item.title, item.detail, item.fix, item.classType, idx[item.classType] ?: -1, item.at, item.cwe)
        f.ruleId = "taint-flow"; f.confidence = item.confidence
        f.scope = SecurityScanner.scopeOf(item.classType, pkg)
        val itText = texts.firstOrNull { it.first == item.classType }?.second ?: ""
        all.addAll(FindingPolish.apply(listOf(f), item.classType,
            f.scope == SecurityScanner.Scope.OBF && SecurityScanner.isAppBoundObf(itText, pkg)))   // 0.82.0, like MainActivity
    }
    val final = SecurityScanner.dedupe(all)
    FindingPolish.lowerNonExportedReceivers(final, FindingPolish.nonExportedReceiversAndServices(mc))   // 0.80.0, like MainActivity.reachPass
    FindingPolish.lowerSeparateProcessDialogs(final, FindingPolish.separateProcessActivities(mc))        // 0.81.0
    FindingPolish.applyProviderCodeChecks(final)
    FindingPolish.applyNetworkEvidence(final)
    outMd.writeText("# APK ReLab report: $pkg\n\n(sandbox scan, no AI triage)\n\n## Security scan\n\n" + ReportBuilder.securitySection(final) + "\n")
    println("pkg=$pkg exported=${entries.size} findings=${final.size} ssaItems=${items.size}")
    final.filter { it.severity != SecurityScanner.Severity.INFO }.sortedBy { it.severity.rank }.forEach {
        println("  [${it.severity}] ${it.ruleId} | ${it.title} | ${it.classType ?: it.file}")
    }
    println("INFO: " + final.filter { it.severity == SecurityScanner.Severity.INFO }.joinToString("; ") { it.ruleId + ":" + it.title })
}
