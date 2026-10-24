import dev.apkrelab.ir.*;
import java.nio.charset.StandardCharsets; import java.nio.file.*; import java.util.*; import java.util.regex.*; import java.util.stream.*;

/** Same pipeline as MainActivity.ssaFindings for big apps: ScopePlanner.groups + SsaGroups.run (non-library classes only). */
public class MeasureBig {
  public static void main(String[] a) throws Exception {
    Path dec = Paths.get(a[0]); Path mfp = Paths.get(a[1]);
    int threads = a.length > 2 ? Integer.parseInt(a[2]) : 2;
    String mf = new String(Files.readAllBytes(mfp), StandardCharsets.UTF_8);
    Matcher pm = Pattern.compile("<manifest[^>]*\\spackage=\"([^\"]+)\"").matcher(mf);
    String pkg = pm.find() ? pm.group(1) : "";
    Set<String> comps = new LinkedHashSet<>();
    // 0.68.5: entries = exported components only, the same rule as SecurityScanner.exportedComponents (android:exported, else "has an intent-filter")
    Matcher cm = Pattern.compile("<(activity-alias|activity|service|receiver|provider)(?![\\w-])([^>]*?)(?:/>|>([\\s\\S]*?)</\\1>)").matcher(mf);
    while (cm.find()) {
      String header = cm.group(2), body = cm.group(3) == null ? "" : cm.group(3);
      Matcher nm = Pattern.compile("android:" + (cm.group(1).equals("activity-alias") ? "targetActivity" : "name") + "\\s*=\\s*\"([^\"]+)\"").matcher(header);
      if (!nm.find()) continue;
      Matcher em = Pattern.compile("android:exported\\s*=\\s*\"(true|false)\"").matcher(header);
      boolean exported = em.find() ? em.group(1).equals("true") : body.contains("<intent-filter");
      if (!exported) continue;
      String n = nm.group(1); if (n.startsWith(".")) n = pkg + n; else if (!n.contains(".")) n = pkg + "." + n; comps.add("L" + n.replace('.', '/') + ";");
    }
    // 0.69.1: -Dguard.file=<file written by GuardList> = exported components behind a signature-level permission (one smali type per line); absent = 0.69.0 behaviour
    final List<String> guarded = new ArrayList<>();
    if (System.getProperty("guard.file") != null) guarded.addAll(Files.readAllLines(Paths.get(System.getProperty("guard.file"))));
    List<Path> files;
    try (Stream<Path> s = Files.walk(dec)) { files = s.filter(p -> p.toString().endsWith(".smali") && dec.relativize(p).toString().startsWith("smali")).collect(Collectors.toList()); }
    final List<Path> app = new ArrayList<>(); final List<String> types = new ArrayList<>();
    Pattern tp = Pattern.compile("^\\.class[^\\n]*?(L[^;\\s]+;)", Pattern.MULTILINE);
    for (Path p : files) {
      String head;
      try (var in = Files.newBufferedReader(p, StandardCharsets.UTF_8)) { head = in.readLine(); }
      if (head == null) continue;
      Matcher tm = tp.matcher(head);
      if (!tm.find()) continue;
      if (!Boolean.getBoolean("all") && Scope.isLib(tm.group(1), pkg)) continue;   // -Dall=true: library classes count as app code (a bigger synthetic workload for timing / memory; the flows then mean nothing)
      app.add(p); types.add(tm.group(1));
    }
    System.out.println("APP pkg=" + pkg + " comps=" + comps.size() + " guarded=" + guarded.size() + " files=" + files.size() + " nonLib=" + app.size());
    long t0 = System.currentTimeMillis();
    final ScopePlanner.Groups gr;
    // -Ddigest=<file> (0.105.0): planner digests kept between runs, as the app does; READS counts the class texts read by the plan + the cache keys
    final java.util.concurrent.atomic.AtomicLong reads = new java.util.concurrent.atomic.AtomicLong();
    final String dgf = System.getProperty("digest");
    final DigestStore dstore = dgf == null ? null : DigestStore.load(new java.io.File(dgf));
    final int dloaded = dstore == null ? 0 : dstore.size();
    ScopePlanner.Source src = new ScopePlanner.Source() {
      public int count() { return app.size(); }
      public String type(int i) { return types.get(i); }
      public String text(int i) { reads.incrementAndGet(); try { return new String(Files.readAllBytes(app.get(i)), StandardCharsets.UTF_8); } catch (Exception e) { return ""; } }
      public CallSkeleton.Digest digest(int i) {
        if (dstore == null) return CallSkeleton.digest(text(i));
        CallSkeleton.Digest d = dstore.get(types.get(i));
        if (d == null) { d = CallSkeleton.digest(text(i)); dstore.put(types.get(i), d); }
        return d;
      }
    };
    List<List<Integer>> groupIdx = new ArrayList<>();
    String planNote;
    if (app.size() > 6000) {
      gr = ScopePlanner.groups(src, comps, Integer.getInteger("max", 3000), false, false, false);
      for (int[] g : gr.groups) { List<Integer> l = new ArrayList<>(); for (int x : g) l.add(x); groupIdx.add(l); }
      planNote = gr.groups.size() + " groups, marked " + gr.marked + ", capped " + gr.cappedGroups + ", biggest closure " + gr.maxClosure + " (" + gr.maxClosureTiers + "), hubs " + gr.hubs + ", markedHubs " + gr.markedHubs;
    } else {
      List<Integer> all = new ArrayList<>(); for (int i = 0; i < app.size(); i++) all.add(i); groupIdx.add(all); planNote = "1 group (whole app)";
    }
    { Map<Integer, Integer> mult = new HashMap<>(); long slots = 0; for (List<Integer> g : groupIdx) for (int x : g) { slots++; mult.merge(x, 1, Integer::sum); }
      int[] hist = new int[6]; for (int v : mult.values()) hist[Math.min(5, v - 1)]++;
      System.out.println("OVERLAP slots " + slots + " unique " + mult.size() + " (in 1/2/3/4/5/6+ groups: " + Arrays.toString(hist) + ")"); }
    long t1 = System.currentTimeMillis();
    SsaGroups.Host host = new SsaGroups.Host() {
      public String text(int i) throws Exception { return new String(Files.readAllBytes(app.get(i)), StandardCharsets.UTF_8); }
      public String type(int i) { return types.get(i); }
      public boolean cancelled() { return false; }
      // -Dcache=<dir>: finished groups are kept there (0.104.0); -Dengine=<id> names the engine in the key
      public GroupCache groupCache() { return System.getProperty("cache") == null ? null : new GroupCache.Disk(new java.io.File(System.getProperty("cache")), 1000); }
      public String engineId() { return System.getProperty("engine", "sandbox"); }
      public long textHash(int i) throws Exception { CallSkeleton.Digest d = dstore == null ? null : dstore.get(types.get(i)); if (d != null) return d.textHash; reads.incrementAndGet(); return SsaGroups.fnvOf(text(i)); }
      public void progress(int d, int t) { if (t > 1 && (d % 5 == 0 || d == t)) System.err.println("group " + d + "/" + t + " " + (System.currentTimeMillis() - t1) / 1000 + "s"); }
      public void groupFailed() { System.out.println("GROUP FAILED"); }
      public Collection<String> guardedEntries() { return guarded; }
    };
    SsaGroups.Result res = SsaGroups.run(groupIdx, comps, null, host, 200, threads);
    long t2 = System.currentTimeMillis();
    System.out.println("PLAN " + planNote + " (" + (t1 - t0) + " ms)");
    if (dstore != null) { boolean w = dstore.changed() && dstore.save(new java.io.File(dgf)); System.out.println("DIGEST loaded " + dloaded + ", now " + dstore.size() + (w ? ", written" : "")); }
    System.out.println("READS " + reads.get() + " class texts read by the plan + cache keys");
    System.out.println("RETRIED " + res.groupsRetried + " of " + res.groupsTotal + " stopped=" + res.stopped);
    System.out.println("TIME groups=" + (t2 - t1) / 1000 + "s threads=" + res.threads + " cpu: parse " + res.parseMs / 1000 + "s + analysis " + res.analyseMs / 1000 + "s, groups from cache " + res.groupsCached + " of " + res.groupsTotal);
    TreeSet<String> lines = new TreeSet<>();
    for (SsaGroups.Picked p : res.picked) {
      SsaBridge.Item it = p.item;
      String d = it.detail == null ? "" : it.detail.replace('\n', ' ');
      lines.add("[" + it.sev + "/" + it.confidence + "] " + it.title + " | " + it.classType + "->" + it.method.substring(it.method.indexOf("->") >= 0 ? it.method.indexOf("->") + 2 : 0) + " | reach=" + (it.reachable ? "Y" : "N") + " | " + d.substring(0, Math.min(Integer.getInteger("detail.max", 150), d.length())));
    }
    System.out.println("FLOWS " + lines.size() + " (picked " + res.picked.size() + ")");
    for (String l : lines) System.out.println("  " + l);
    System.out.println("STATS " + res.stats.line());
    int topN = Integer.getInteger("owners", 0);
    if (topN > 0) { List<Map.Entry<String, Long>> es = new ArrayList<>(res.stats.owners.entrySet()); es.sort((x, y) -> Long.compare(y.getValue(), x.getValue()));
      for (int i = 0; i < es.size() && i < topN; i++) System.out.println("OWNERS " + es.get(i).getValue() + " " + es.get(i).getKey()); }
  }
}
