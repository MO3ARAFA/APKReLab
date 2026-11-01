import dev.apkrelab.*
import java.io.File
import java.util.zip.ZipFile

/** Sandbox approximation of the device Smart scan: code rules per class, manifest rules, resource rules, SSA taint flows -> Markdown report. No AI triage, no reach labels. */
fun main(args: Array<String>) {
    val decDir = File(args[0]); val apk = File(args[1]); val outMd = File(args[2])
    // recall kit: -Dmanifest=<file> scans with an edited (text) manifest instead of the APK's, so injected components can be declared
    val manifest = System.getProperty("manifest")?.let { File(it).readText() }
        ?: ZipFile(apk).use { z -> Axml.decode(z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes()) } ?: error("manifest")
    val mc = ManifestContext(manifest)
    // 0.89.0: the vendor token formats (the app loads assets/secret_formats.json at start)
    java.io.File(System.getProperty("secretformats") ?: "app/src/main/assets/secret_formats.json").let { if (it.exists()) SecretFormats.load(it.readText()) }
    val manifestPkg = Regex("package=\"([^\"]+)\"").find(manifest)?.groupValues?.get(1) ?: ""
    val all = ArrayList<SecurityScanner.Finding>()
    all.addAll(SecurityScanner.scanManifest(manifest))
    val texts = ArrayList<Pair<String, String>>()
    decDir.walkTopDown().filter { it.isFile && it.name.endsWith(".smali") }.forEach { f ->
        val text = f.readText()
        val type = Regex("^\\.class[^\\n]* (L[^;]+;)", RegexOption.MULTILINE).find(text)?.groupValues?.get(1) ?: return@forEach
        texts.add(type to text)
    }
    // 0.86.2: like the device (MainActivity: SecurityScanner.codePackage(...)): the code package, not the manifest package. Quillpad's code is in
    // org.qosp.notes while the manifest says io.github.quillpad; with the manifest package an app-bound renamed class looked like a library.
    val pkg = SecurityScanner.codePackage(texts.map { it.first }, manifestPkg, mc.componentTypes(manifestPkg), mc.launcherTypes(manifestPkg))   // 0.92.1 + 0.106.0: components and launcher are evidence, like in the app
    PostureScanner.clear(); SecurityScanner.clearKeyTracking()   // 0.94.0
    for ((i, p) in texts.withIndex()) { all.addAll(SecurityScanner.scanSmali(p.first, i, p.second, pkg)); PostureScanner.observe(p.first, p.second, pkg) }   // 0.91.0
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
        f.reach = if (item.reachable) (if (item.viaHub) "YES~" else "YES") else "NO"   // 0.83.0: like the device (reach labels from the call graph)
        f.scope = SecurityScanner.scopeOfText(item.classType, pkg, texts.getOrNull(idx[item.classType] ?: -1)?.second ?: "")   // 0.83.0
        val itText = texts.firstOrNull { it.first == item.classType }?.second ?: ""
        all.addAll(FindingPolish.apply(listOf(f), item.classType,
            f.scope == SecurityScanner.Scope.OBF && SecurityScanner.isAppBoundObf(itText, pkg)))   // 0.82.0, like MainActivity
    }
    val final = ArrayList(SecurityScanner.dedupe(all))
    FindingPolish.lowerUnreachedHelpers(final, mc.components.map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.toSet(), emptySet())   // 0.77.0 pass of MainActivity.reachPass (no guarded-entry types here)
    FindingPolish.lowerNonExportedReceivers(final, FindingPolish.nonExportedReceiversAndServices(mc))   // 0.80.0, like MainActivity.reachPass
    FindingPolish.lowerSeparateProcessDialogs(final, FindingPolish.separateProcessActivities(mc))        // 0.81.0
    FindingPolish.applyProviderCodeChecks(final)
    FindingPolish.applyNetworkEvidence(final)
    FindingPolish.restoreInstalledTls(final)   // 0.85.0
    FindingPolish.raiseUsedSecretFields(final)   // 0.86.1
    val superMap = texts.associate { (t, x) -> t to Regex("^\\.super (L[^;]+;)", RegexOption.MULTILINE).find(x)?.groupValues?.get(1) }
    FindingPolish.lowerNonExportedProviders(final, FindingPolish.nonExportedProviders(mc) { t -> superMap[t]?.takeIf { it in superMap } })   // 0.84.0
    FindingPolish.lowerCallerVerified(final)   // 0.94.0
    final.addAll(FindingPolish.resolvePendingKeys().filter { k -> final.none { it.classType == k.classType && it.title == k.title } })   // 0.94.0
    final.addAll(PostureScanner.findings())   // 0.91.0
    // 0.93.1: -Dtriage=<file> writes, per CRITICAL / HIGH / MEDIUM code finding, everything the app's AI triage puts in its prompt (MainActivity.triageWithAi), as JSON lines,
    // so that the triage can be replayed outside the app and compared with hand verdicts. Reach text only exists for findings the harness traced (taint flows).
    System.getProperty("triage")?.let { path ->
        val idxOf = HashMap<String, Int>(); for ((i, p) in texts.withIndex()) idxOf[p.first] = i
        val sb = StringBuilder()
        for (f in final) {
            if (f.clsIndex < 0 || f.severity.rank > 2) continue
            val text = texts.getOrNull(f.clsIndex)?.second ?: continue
            var ex = SecurityScanner.excerpt(text, f.at, 3500)
            if (f.sourceMethod.isNotEmpty()) {
                val srcType = f.sourceMethod.substringBefore("->")
                val srcText = idxOf[srcType]?.let { texts[it].second } ?: ""
                val srcCode = SecurityScanner.methodExcerpt(srcText, f.sourceMethod, 1800)
                if (srcCode.isNotEmpty() || f.dataPath.isNotEmpty())
                    ex += "\n\nData path (source -> sink): " + f.dataPath.ifEmpty { "(see above)" } +
                        (if (srcCode.isNotEmpty()) "\n\nCode of the method where the untrusted value is first held (" + f.sourceMethod.substringAfter("->") + "):\n" + srcCode else "")
            }
            val o = org.json.JSONObject()
            o.put("app", pkg).put("title", f.title).put("severity", f.severity.label).put("cwe", f.cwe).put("rule", f.ruleId).put("scope", f.scope.tag)
            o.put("detail", f.detail.take(if (f.sourceMethod.isNotEmpty()) 900 else 400)).put("location", f.location).put("reach", f.reach).put("chain", f.chain).put("code", ex)
            sb.append(o.toString()).append('\n')
        }
        java.io.File(path).writeText(sb.toString())
    }
    System.getProperty("sarif")?.let { java.io.File(it).writeText(SarifExport.build(pkg, "sandbox", final)) }   // 0.92.0: -Dsarif=<file> writes the SARIF export of this scan
    outMd.writeText("# APK ReLab report: $pkg\n\n(sandbox scan, no AI triage)\n\n## Security scan\n\n" + ReportBuilder.securitySection(final) + "\n" + PostureScanner.section() + AttackScenarios.section(final, mc, manifestPkg) + Masvs.section(final))
    println("pkg=$pkg exported=${entries.size} findings=${final.size} ssaItems=${items.size}")
    final.filter { it.severity != SecurityScanner.Severity.INFO }.sortedBy { it.severity.rank }.forEach {
        println("  [${it.severity}] ${it.ruleId} | ${it.title} | ${it.classType ?: it.file}")
    }
    println("INFO: " + final.filter { it.severity == SecurityScanner.Severity.INFO }.joinToString("; ") { it.ruleId + ":" + it.title })
}
