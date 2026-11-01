package dev.apkrelab.ir;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * 0.104.0: the result of one analysed group (its flows and its measurement) kept on disk, so that scanning the SAME app again (a new scanner build with the same engine, a second Deep
 * scan, an edit of one class in the editor) re-runs only the groups whose classes changed.
 *
 * A group's result depends on nothing but its class texts, the entry / guarded component lists, the earlier rule findings it is de-duplicated against and the engine itself; that is
 * exactly what {@link SsaGroups} puts in the key (see {@link SsaGroups#groupKey}). The engine part is the caller's {@code engineId} (the app's version code): an engine change MUST
 * come with a new one, or old results would be served.
 *
 * Only a group that finished normally is stored (never a cancelled, out-of-memory or failed one: an empty list from a failure would be read back as "no flows"). Any problem with a file
 * (missing, truncated, another format) is a miss: the group is analysed again.
 */
public interface GroupCache {
    final class Entry {
        public final List<SsaBridge.Item> items;
        public final TaintIr.Stats stats;

        Entry(List<SsaBridge.Item> items, TaintIr.Stats stats) {
            this.items = items;
            this.stats = stats;
        }
    }

    /** The stored result for [key], or null (a miss, or anything unreadable). */
    Entry load(String key);

    /** Stores a finished group's result. Never throws. */
    void store(String key, List<SsaBridge.Item> items, TaintIr.Stats stats);

    /** One file per group under [dir]: a small binary record, written to a temporary name and renamed (a reader never sees half a file); the oldest files go when there are more than [maxFiles]. */
    final class Disk implements GroupCache {
        private static final int MAGIC = 0x53474331;       // "SGC1"
        private static final int FORMAT = 2;      // 2.0.2: Item.viaHub, Stats.forwarded, Stats.openRedirector (a format-1 file is a miss)
        private static final int MAX_STRING = 60000;       // writeUTF limit is 65535 bytes
        private final File dir;
        private final int maxFiles;

        public Disk(File dir, int maxFiles) {
            this.dir = dir;
            this.maxFiles = maxFiles;
        }

        private File file(String key) {
            return new File(dir, key + ".grp");
        }

        @Override
        public Entry load(String key) {
            File f = file(key);
            if (!f.isFile()) return null;
            try (DataInputStream in = new DataInputStream(new java.io.BufferedInputStream(new java.io.FileInputStream(f)))) {
                if (in.readInt() != MAGIC || in.readInt() != FORMAT) return null;
                int n = in.readInt();
                if (n < 0 || n > 100000) return null;
                List<SsaBridge.Item> items = new ArrayList<>(n);
                for (int i = 0; i < n; i++) {
                    String classType = in.readUTF(), method = in.readUTF();
                    int at = in.readInt();
                    String title = in.readUTF(), cwe = in.readUTF(), sev = in.readUTF(), confidence = in.readUTF(), fix = in.readUTF(), detail = in.readUTF();
                    boolean reachable = in.readBoolean();
                    String entry = in.readUTF(), path = in.readUTF();
                    int count = in.readInt();
                    String sourceMethod = in.readUTF(), dataPath = in.readUTF();
                    SsaBridge.Item item = new SsaBridge.Item(classType, method, at, title, cwe, sev, confidence, fix, detail, reachable, entry, path, count, sourceMethod, dataPath);
                    item.viaHub = in.readBoolean();
                    items.add(item);
                }
                TaintIr.Stats st = new TaintIr.Stats();
                st.analyses = in.readInt();
                for (int i = 0; i < 2; i++) st.outOfScope[i] = in.readLong();
                for (int i = 0; i < 2; i++) st.unresolved[i] = in.readLong();
                for (int i = 0; i < 2; i++) st.library[i] = in.readLong();
                st.capRefs = in.readLong();
                st.capRounds = in.readLong();
                st.capRequeue = in.readLong();
                st.capApprox = in.readLong();
                int no = in.readInt();
                if (no < 0 || no > 200000) return null;
                for (int i = 0; i < no; i++) st.owners.put(in.readUTF(), in.readLong());
                int ns = in.readInt();
                if (ns < 0 || ns > 1000) return null;
                for (int i = 0; i < ns; i++) st.slowest.add(new TaintIr.Stats.Slow(in.readUTF(), in.readLong(), in.readInt(), in.readInt(), in.readInt()));
                st.openRedirector = in.readBoolean();
                int nf = in.readInt();
                if (nf < 0 || nf > 100000) return null;
                for (int i = 0; i < nf; i++) st.forwarded.add(in.readUTF());
                if (in.readInt() != MAGIC) return null;                 // the end marker: a truncated file is a miss
                if (in.read() != -1) return null;
                f.setLastModified(System.currentTimeMillis());
                return new Entry(items, st);
            } catch (Throwable t) {
                return null;
            }
        }

        @Override
        public void store(String key, List<SsaBridge.Item> items, TaintIr.Stats st) {
            File tmp = null;
            try {
                dir.mkdirs();
                tmp = new File(dir, key + ".tmp" + Thread.currentThread().getId());
                try (DataOutputStream out = new DataOutputStream(new java.io.BufferedOutputStream(new java.io.FileOutputStream(tmp)))) {
                    out.writeInt(MAGIC);
                    out.writeInt(FORMAT);
                    out.writeInt(items.size());
                    for (SsaBridge.Item it : items) {
                        utf(out, it.classType); utf(out, it.method);
                        out.writeInt(it.at);
                        utf(out, it.title); utf(out, it.cwe); utf(out, it.sev); utf(out, it.confidence); utf(out, it.fix); utf(out, it.detail);
                        out.writeBoolean(it.reachable);
                        utf(out, it.entry); utf(out, it.path);
                        out.writeInt(it.count);
                        utf(out, it.sourceMethod); utf(out, it.dataPath);
                        out.writeBoolean(it.viaHub);
                    }
                    out.writeInt(st.analyses);
                    for (int i = 0; i < 2; i++) out.writeLong(st.outOfScope[i]);
                    for (int i = 0; i < 2; i++) out.writeLong(st.unresolved[i]);
                    for (int i = 0; i < 2; i++) out.writeLong(st.library[i]);
                    out.writeLong(st.capRefs);
                    out.writeLong(st.capRounds);
                    out.writeLong(st.capRequeue);
                    out.writeLong(st.capApprox);
                    out.writeInt(st.owners.size());
                    for (Map.Entry<String, Long> e : st.owners.entrySet()) {
                        utf(out, e.getKey());
                        out.writeLong(e.getValue());
                    }
                    out.writeInt(st.slowest.size());
                    for (TaintIr.Stats.Slow s : st.slowest) {
                        utf(out, s.key);
                        out.writeLong(s.nanos);
                        out.writeInt(s.runs);
                        out.writeInt(s.insns);
                        out.writeInt(s.rounds);
                    }
                    out.writeBoolean(st.openRedirector);
                    java.util.List<String> fw; synchronized (st.forwarded) { fw = new ArrayList<>(st.forwarded); }
                    out.writeInt(fw.size());
                    for (String x : fw) utf(out, x);
                    out.writeInt(MAGIC);
                }
                File f = file(key);
                if (!tmp.renameTo(f)) {
                    f.delete();
                    if (!tmp.renameTo(f)) tmp.delete();
                }
                trim();
            } catch (Throwable t) {
                if (tmp != null) tmp.delete();     // too long a string, disk full ...: the group is simply not cached
            }
        }

        private static void utf(DataOutputStream out, String s) throws IOException {
            if (s == null) s = "";
            if (s.length() > MAX_STRING) throw new IOException("string too long to cache");
            out.writeUTF(s);
        }

        private void trim() {
            File[] fs = dir.listFiles((d, n) -> n.endsWith(".grp"));
            if (fs == null || fs.length <= maxFiles) return;
            Arrays.sort(fs, Comparator.comparingLong(File::lastModified));
            for (int i = 0; i < fs.length - maxFiles; i++) fs[i].delete();
        }
    }
}
