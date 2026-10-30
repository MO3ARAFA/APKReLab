import dev.apkrelab.ir.*;
import java.io.*; import java.nio.charset.StandardCharsets; import java.nio.file.*; import java.util.*; import java.util.regex.*; import java.util.stream.*;

public class Measure {
  static final boolean RESCUE = Boolean.getBoolean("rescue");
  static boolean refsApp(String text, String pkg) {
    String[] sp = pkg.split("\\."); String pref = (sp.length >= 2 ? sp[0] + "/" + sp[1] : sp[0]) + "/";
    int i = 0;
    while ((i = text.indexOf("L" + pref, i)) >= 0) {
      int e = text.indexOf(';', i);
      if (e > 0) { String t = text.substring(i + 1, e); if (!Scope.isOverride("L" + t + ";")) return true; }
      i += 2;
    }
    return false;
  }
  public static void main(String[] a) throws Exception {
    Path dec = Paths.get(a[0]); Path mfp = a.length > 1 ? Paths.get(a[1]) : dec.resolve("AndroidManifest.xml");
    String mf = new String(Files.readAllBytes(mfp), StandardCharsets.UTF_8);
    Matcher pm = Pattern.compile("<manifest[^>]*\\spackage=\"([^\"]+)\"").matcher(mf);
    String pkg = pm.find() ? pm.group(1) : "";
    // components
    Set<String> comps = new LinkedHashSet<>();
    Matcher cm = Pattern.compile("<(application|activity|activity-alias|service|receiver|provider)\\s[^>]*?android:name=\"([^\"]+)\"").matcher(mf);
    while (cm.find()) { String n = cm.group(2); if (n.startsWith(".")) n = pkg + n; else if (!n.contains(".")) n = pkg + "." + n; comps.add("L" + n.replace('.', '/') + ";"); }
    List<Path> files;
    try (Stream<Path> s = Files.walk(dec)) { files = s.filter(p -> p.toString().endsWith(".smali") && dec.relativize(p).toString().startsWith("smali")).collect(Collectors.toList()); }
    long t0 = System.currentTimeMillis();
    List<ClassIr> app = new ArrayList<>(); int total = 0, skipped = 0, fail = 0, rescued = 0; List<String> rescuedNames = new ArrayList<>();
    for (Path p : files) {
      total++;
      String text = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
      Matcher tm = Pattern.compile("^\\.class[^\\n]*?(L[^;\\s]+;)", Pattern.MULTILINE).matcher(text);
      if (!tm.find()) { fail++; continue; }
      if (Scope.isLib(tm.group(1), pkg)) {
        if (RESCUE && !Scope.isOverride(tm.group(1)) && refsApp(text, pkg)) { rescued++; rescuedNames.add(tm.group(1)); }
        else { skipped++; continue; }
      }
      try { app.add(SmaliParser.parse(text)); } catch (Throwable t) { fail++; }
    }
    long t1 = System.currentTimeMillis();
    CallGraph g = CallGraph.build(app, comps, CallGraph.Mode.RTA, null);
    long t2 = System.currentTimeMillis();
    TaintIr.Result r = TaintIr.analyze(g, false, null);
    long t3 = System.currentTimeMillis();
    TreeSet<String> lines = new TreeSet<>();
    for (TaintIr.Flow f : r.flows) lines.add("[" + f.sink.sev + "] " + f.sink.title + " | " + f.source + (f.via != null ? " via " + f.via : "") + " | " + f.sink.method + " | reach=" + (f.reachable ? "Y" : "N"));
    System.out.println("APP pkg=" + pkg + " comps=" + comps.size() + " files=" + total + " libSkipped=" + skipped + " parsedApp=" + app.size() + " parseFail=" + fail);
    System.out.println("RESCUED " + rescued + (rescued > 0 ? " e.g. " + rescuedNames.subList(0, Math.min(3, rescuedNames.size())) : ""));
    System.out.println("TIME parse=" + (t1 - t0) + "ms graph=" + (t2 - t1) + "ms taint=" + (t3 - t2) + "ms");
    System.out.println("FLOWS " + lines.size() + " (raw " + r.flows.size() + ")");
    for (String l : lines) System.out.println("  " + l);
    if (Boolean.getBoolean("chain")) for (TaintIr.Flow f : r.flows) System.out.println("CHAIN " + f.sink.api + " in " + f.sink.method + "\n   src=" + f.source + " via=" + f.via + "\n   chain=" + f.chain + "\n   entry=" + f.entryPath);
    System.out.println("STATS " + r.stats.line());
  }
}
