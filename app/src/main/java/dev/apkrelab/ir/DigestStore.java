package dev.apkrelab.ir;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 0.105.0: the planner digests of one app's classes ({@link CallSkeleton.Digest}), kept on disk between scans so that a re-scan of the same classes reads no class text for the
 * plan nor for the group cache keys. The caller names the file after everything a digest depends on besides the text itself (the engine, the app's code, the strings overlay) and
 * keeps only classes whose text comes from that code unchanged (an edited class is never stored: it is read and digested every time).
 *
 * Any problem with the file (missing, truncated, another format) means an empty store: every class is read as before. Thread-safe.
 */
public final class DigestStore {
    private static final int MAGIC = 0x53444731;     // "SDG1"
    private static final int MAX_STRING = 60000;
    private final Map<String, CallSkeleton.Digest> map = new ConcurrentHashMap<>();
    private volatile boolean changed;

    public CallSkeleton.Digest get(String type) {
        return map.get(type);
    }

    public void put(String type, CallSkeleton.Digest d) {
        if (map.put(type, d) == null) changed = true;
    }

    public int size() {
        return map.size();
    }

    /** True when classes were added since the store was loaded (only then is it worth writing). */
    public boolean changed() {
        return changed;
    }

    public static DigestStore load(File f) {
        DigestStore st = new DigestStore();
        if (f == null || !f.isFile()) return st;
        try (DataInputStream in = new DataInputStream(new java.io.BufferedInputStream(new java.io.FileInputStream(f), 1 << 16))) {
            if (in.readInt() != MAGIC) return st;
            int n = in.readInt();
            if (n < 0 || n > 2_000_000) return st;
            Map<String, CallSkeleton.Digest> tmp = new java.util.HashMap<>(n * 2);
            for (int i = 0; i < n; i++) {
                String type = in.readUTF();
                int bits = in.readInt();
                long hash = in.readLong();
                String[] par = strings(in), refs = strings(in);
                if (par == null || refs == null) return st;
                tmp.put(type, new CallSkeleton.Digest(bits, par, refs, hash));
            }
            if (in.readInt() != MAGIC || in.read() != -1) return st;          // truncated or trailing bytes: nothing is trusted
            st.map.putAll(tmp);
        } catch (Throwable t) {
            st.map.clear();
        }
        return st;
    }

    private static String[] strings(DataInputStream in) throws java.io.IOException {
        int k = in.readInt();
        if (k < 0 || k > 100000) return null;
        String[] a = new String[k];
        for (int i = 0; i < k; i++) a[i] = Canon.of(in.readUTF());
        return a;
    }

    /** Writes the store (to a temporary name, then renamed). Never throws; returns false when nothing was written. */
    public boolean save(File f) {
        File tmp = new File(f.getPath() + ".tmp" + Thread.currentThread().getId());
        try {
            File dir = f.getParentFile();
            if (dir != null) dir.mkdirs();
            try (DataOutputStream out = new DataOutputStream(new java.io.BufferedOutputStream(new java.io.FileOutputStream(tmp), 1 << 16))) {
                Map<String, CallSkeleton.Digest> snap = new java.util.HashMap<>(map);
                out.writeInt(MAGIC);
                out.writeInt(snap.size());
                for (Map.Entry<String, CallSkeleton.Digest> e : snap.entrySet()) {
                    CallSkeleton.Digest d = e.getValue();
                    utf(out, e.getKey());
                    out.writeInt(d.bits);
                    out.writeLong(d.textHash);
                    out.writeInt(d.parents.length);
                    for (String s : d.parents) utf(out, s);
                    out.writeInt(d.refs.length);
                    for (String s : d.refs) utf(out, s);
                }
                out.writeInt(MAGIC);
            }
            if (!tmp.renameTo(f)) {
                f.delete();
                if (!tmp.renameTo(f)) {
                    tmp.delete();
                    return false;
                }
            }
            changed = false;
            return true;
        } catch (Throwable t) {
            tmp.delete();
            return false;
        }
    }

    private static void utf(DataOutputStream out, String s) throws java.io.IOException {
        if (s.length() > MAX_STRING) throw new java.io.IOException("string too long");
        out.writeUTF(s);
    }
}
