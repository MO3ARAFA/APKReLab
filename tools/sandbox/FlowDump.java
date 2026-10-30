import dev.apkrelab.ir.*;
import java.nio.file.*; import java.nio.charset.StandardCharsets; import java.util.*; import java.util.regex.*; import java.util.stream.*;
/** Dumps every TaintIr flow (source, via, chain, sink) of the non-library classes, entries = exported components. Sandbox measurement only. */
public class FlowDump { public static void main(String[] a) throws Exception {
  Path dec = Paths.get(a[0]); String mf = new String(Files.readAllBytes(Paths.get(a[1])), StandardCharsets.UTF_8);
  Matcher pm = Pattern.compile("<manifest[^>]*\\spackage=\"([^\"]+)\"").matcher(mf); String pkg = pm.find() ? pm.group(1) : "";
  Set<String> comps = new LinkedHashSet<>();
  Matcher cm = Pattern.compile("<(activity-alias|activity|service|receiver|provider)(?![\\w-])([^>]*?)(?:/>|>([\\s\\S]*?)</\\1>)").matcher(mf);
  while (cm.find()) { String h = cm.group(2), b = cm.group(3) == null ? "" : cm.group(3);
    Matcher nm = Pattern.compile("android:" + (cm.group(1).equals("activity-alias") ? "targetActivity" : "name") + "\\s*=\\s*\"([^\"]+)\"").matcher(h); if (!nm.find()) continue;
    Matcher em = Pattern.compile("android:exported\\s*=\\s*\"(true|false)\"").matcher(h); boolean ex = em.find() ? em.group(1).equals("true") : b.contains("<intent-filter");
    if (!ex) continue; String n = nm.group(1); if (n.startsWith(".")) n = pkg + n; else if (!n.contains(".")) n = pkg + "." + n; comps.add("L" + n.replace('.', '/') + ";"); }
  List<ClassIr> cs = new ArrayList<>();
  try (Stream<Path> s = Files.walk(dec)) { for (Path p : (Iterable<Path>) s.filter(p -> p.toString().endsWith(".smali"))::iterator) {
    String t = new String(Files.readAllBytes(p), StandardCharsets.UTF_8); Matcher tm = Pattern.compile("^\\.class[^\\n]*?(L[^;\\s]+;)", Pattern.MULTILINE).matcher(t);
    if (!tm.find() || Scope.isLib(tm.group(1), pkg)) continue; cs.add(SmaliParser.parse(t)); } }
  CallGraph g = CallGraph.build(cs, new ArrayList<>(comps), CallGraph.Mode.RTA, null);
  TaintIr.Result r = TaintIr.analyze(g, false, null);
  System.out.println("APP " + pkg + " classes=" + cs.size() + " flows=" + r.flows.size());
  for (TaintIr.Flow f : r.flows) System.out.println("FLOW | " + f.sink.title + " | src=" + f.source + " | via=" + f.via + " | weak=" + f.weak + " internal=" + f.internal + " | sink=" + f.sink.method + " | chain=" + f.chain);
}}
