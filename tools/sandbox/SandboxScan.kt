import dev.apkrelab.*
import java.io.File
import java.util.zip.ZipFile
import dev.apkrelab.ir.TaintIr

/** Sandbox approximation of the device Smart scan: code rules per class, manifest rules, resource rules, SSA taint flows -> Markdown report. No AI triage, no reach labels. */
fun main(args: Array<String>) {
    val decDir = File(args[0]); val apk = File(args[1]); val outMd = File(args[2])
    val t0 = System.nanoTime()
    val manifest = ZipFile(apk).use { z -> Axml.decode(z.getInputStream(z.getEntry("AndroidManifest.xml")).readBytes()) } ?: error("manifest")
    val mc = ManifestContext(manifest)
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
    val pkg = SecurityScanner.codePackage(texts.map { it.first }, manifestPkg, mc.componentTypes(manifestPkg), mc.launcherTypes(manifestPkg))   // 0.106.0: like the app
    TaintIr.clearForwarded(); DynamicReceivers.clear(); HybridInspector.clearApk(); NativeBridge.clear(); NativeBridge.clearApk(); PostureScanner.clear()
    for ((i, p) in texts.withIndex()) {
        all.addAll(SecurityScanner.scanSmali(p.first, i, p.second, pkg))
        DynamicReceivers.observe(p.second)                       // 1.1.0: like the app's scan loop
        NativeBridge.observe(p.first, p.second)                  // 1.2.0: for the verdict's NOT SEEN line, like the app
        PostureScanner.observe(p.first, p.second, pkg)
    }
    ZipFile(apk).use { z -> NativeBridge.useLibs(NativeScanner.readLibs(z).first) }   // the base APK only (the sandbox imports no split)
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
        f.reach = if (item.reachable) (if (item.viaHub) "YES~" else "YES") else "NO"; if (item.reachable) f.chain = "Entry: " + item.entry + "\nPath: " + item.path   // 1.2.0 QA: reach labels from the call graph, like SandboxScanReach and the device (rule cards stay untraced here)
        f.scope = SecurityScanner.scopeOfText(item.classType, pkg, texts.getOrNull(idx[item.classType] ?: -1)?.second ?: "")   // 0.83.0
        val itText = texts.firstOrNull { it.first == item.classType }?.second ?: ""
        all.addAll(FindingPolish.apply(listOf(f), item.classType,
            f.scope == SecurityScanner.Scope.OBF && SecurityScanner.isAppBoundObf(itText, pkg)))   // 0.82.0, like MainActivity
    }
    val final = SecurityScanner.dedupe(all)
    FindingPolish.lowerNonExportedReceivers(final, FindingPolish.nonExportedReceiversAndServices(mc))   // 0.80.0, like MainActivity.reachPass
    FindingPolish.lowerSeparateProcessDialogs(final, FindingPolish.separateProcessActivities(mc))        // 0.81.0
    FindingPolish.lowerGuardedProviderFlows(final, mc, PermissionGuard(mc))                              // phase 3, like MainActivity (no device resolver)
    FindingPolish.raiseReflectedUriGrant(final, mc)                                                      // 2.1.0, like MainActivity
    // 2.1.0: MIRROR of the device's reach pass for the simplest case only (the sandbox does not trace rule cards): a rule card inside an EXPORTED component's own class is reached by that entry
    val entryTypes = mc.exportedComponents.map { mc.smaliTypeOf(it) }.filter { it.isNotEmpty() }.toSet()
    for (f in final) {
        val t = f.classType ?: continue
        val outer = if (t.contains('$')) t.substringBefore('$') + ";" else t
        if (f.reach.isEmpty() && f.clsIndex >= 0 && FindingPolish.wantsReach(f) && outer in entryTypes) {
            f.reach = "YES"; f.chain = "Entry: exported activity " + outer.removePrefix("L").removeSuffix(";").replace('/', '.') + " (no permission)\nPath: " + outer.removePrefix("L").removeSuffix(";").replace('/', '.')
        }
    }
    FindingPolish.lowerUnforwardedPrivateIntentFlows(final, FindingPolish.privateActivitiesAndServices(mc), TaintIr.forwardedComponents(), TaintIr.openRedirectorSeen())   // 2.0.2, like MainActivity
    // 1.1.0, like MainActivity: receivers registered only with a signature permission (or NOT_EXPORTED and minSdk 33+); no device here, so platform levels come from ReportBuilder.defaultLevel
    val minSdk = Regex("minSdkVersion\\s*=\\s*\"?(\\d+)").find(manifest)?.groupValues?.get(1)?.toIntOrNull() ?: 1
    DynamicReceivers.lower(final, DynamicReceivers.protectedReceivers(minSdk) { p -> mc.declaredPerms[p]?.let { PermissionGuard.isSignatureLevel(it) } ?: ((ReportBuilder.defaultLevel(p) ?: 0) >= 2) })
    FindingPolish.applyProviderCodeChecks(final)
    FindingPolish.applyNetworkEvidence(final)
    // 1.2.0: the verdict as the app builds it (no device: no strings overlay, no splits, no reach pass so MUST FIX stays empty here; the whole app in one SSA run)
    val cards = ReportBuilder.reportable(final).take(400)
    val vt0 = System.nanoTime()
    val verdict = Verdict.build(cards, try { AttackScenarios.build(final, mc, pkg) } catch (_: Throwable) { emptyList() },
        Verdict.Coverage(deepScan = true, classesScanned = texts.size, nativeMethods = NativeBridge.bindings().size, nativeLibs = NativeBridge.libs.size,
            decryptorCalls = PostureScanner.decryptorCallCount(), hybridKinds = HybridInspector.current?.kinds ?: emptyList()), pkg, final, guard = PermissionGuard(mc))   // phase 2: MUST FIX gate (no device resolver: BIND_* / platform levels from ReportBuilder.defaultLevel)
    val vtEnd = System.nanoTime()
    outMd.writeText("# APK ReLab report: $pkg\n\n(sandbox scan, no AI triage)\n\n" + Verdict.markdown(verdict) + "## Security scan\n\n" + ReportBuilder.securitySection(final, 400, pkg) + HybridInspector.markdown(HybridInspector.current) + "\n")
    println("pkg=$pkg exported=${entries.size} findings=${final.size} ssaItems=${items.size} classes=${texts.size} scanMs=${(System.nanoTime() - t0) / 1_000_000} verdictMs=${(vtEnd - vt0) / 1_000_000.0}")
    final.filter { it.severity != SecurityScanner.Severity.INFO }.sortedBy { it.severity.rank }.forEach {
        println("  [${it.severity}] ${it.ruleId} | ${it.title} | ${it.classType ?: it.file}")
    }
    println("INFO: " + final.filter { it.severity == SecurityScanner.Severity.INFO }.joinToString("; ") { it.ruleId + ":" + it.title })
}
