package dev.apkrelab;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 0.17.0: renames the application package inside a BINARY AndroidManifest.xml (AXML), no external library.
 *
 * Only the attributes that must change are repointed to NEW strings appended at the end of the string pool
 * (existing string indexes never move, so the resource map and every other reference stay valid).
 *
 * What changes (old = value of the manifest's package attribute, new = the requested package):
 *  - manifest package
 *  - relative component class names (".Foo" / "Foo") are first expanded to the OLD package, so the code still resolves
 *  - permission / permission-tree / permission-group / uses-permission names that start with old + "."
 *  - android:permission, android:permissionGroup values that start with old + "."
 *  - provider authorities that equal old or start with old + "."  (others are reported as warnings)
 *  - intent-filter category equal to old (push-message receivers)
 *  - android:process / android:taskAffinity that start with old, instrumentation targetPackage equal to old
 * Class names of activities / services / receivers / providers / application are NOT renamed (the code stays where it is).
 */
public final class ManifestPatcher {

    public static final class Result {
        public final byte[] data;
        public final String oldPackage;
        public final int patched;
        public final List<String> notes;

        Result(byte[] data, String oldPackage, int patched, List<String> notes) {
            this.data = data;
            this.oldPackage = oldPackage;
            this.patched = patched;
            this.notes = notes;
        }
    }

    private static final int RES_XML = 0x0003;
    private static final int STRING_POOL = 0x0001;
    private static final int START_ELEMENT = 0x0102;
    private static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";
    private static final int TYPE_STRING = 0x03;
    private static final int NONE = -1;

    private final byte[] src;
    private final ByteBuffer b;
    private final String newPkg;

    // string pool
    private int poolPos, poolSize, strCount, flags, stringsStart;
    private boolean utf8;

    private final List<String> added = new ArrayList<>();
    private final Map<String, Integer> addedIndex = new HashMap<>();
    private final List<int[]> edits = new ArrayList<>(); // {attrAbsPos, newStringIndex}
    private final List<String> notes = new ArrayList<>();
    private final Map<Integer, String> cache = new HashMap<>();

    private ManifestPatcher(byte[] data, String newPkg) {
        this.src = data;
        this.b = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        this.newPkg = newPkg;
    }

    public static Result renamePackage(byte[] axml, String newPackage) throws IOException {
        return new ManifestPatcher(axml, newPackage).run();
    }

    /** One boolean attribute change (0.38.0): element = manifest tag, component = android:name of the component (or "" = every such element). */
    public static final class BoolEdit {
        public final String element, attr, component;
        public final boolean value;

        public BoolEdit(String element, String attr, String component, boolean value) {
            this.element = element;
            this.attr = attr;
            this.component = component == null ? "" : component;
            this.value = value;
        }
    }

    private static final int TYPE_BOOLEAN = 0x12;

    /**
     * 0.38.0: flips EXISTING boolean attributes (android:debuggable, allowBackup, usesCleartextTraffic, exported ...) in place:
     * no size change, no new strings. An attribute that is not in the manifest cannot be added (reported in notes).
     */
    public static Result setBooleans(byte[] axml, List<BoolEdit> list) throws IOException {
        return new ManifestPatcher(axml.clone(), null).runBooleans(list);
    }

    private Result runBooleans(List<BoolEdit> list) throws IOException {
        if (src.length < 8 || u16(0) != RES_XML) throw new IOException("Not a binary XML file");
        poolPos = 8;
        if (src.length < poolPos + 28 || u16(poolPos) != STRING_POOL) throw new IOException("String pool is not the first chunk");
        poolSize = u32(poolPos + 4);
        strCount = u32(poolPos + 8);
        flags = u32(poolPos + 16);
        stringsStart = u32(poolPos + 20);
        utf8 = (flags & 0x100) != 0;
        if (poolPos + poolSize > src.length) throw new IOException("Truncated string pool");

        boolean[] found = new boolean[list.size()];
        int changed = 0;
        String pkg = "";
        boolean first = true;
        int pos = poolPos + poolSize;
        int end = Math.min(src.length, u32(4));
        while (pos + 8 <= end) {
            int type = u16(pos);
            int size = u32(pos + 4);
            if (size < 8 || pos + size > src.length) throw new IOException("Corrupt chunk at " + pos);
            if (type == START_ELEMENT) {
                String name = str(u32(pos + 20));
                if (first) {
                    String p = readPackage(pos);
                    if (p != null) pkg = p;
                    first = false;
                }
                for (int k = 0; k < list.size(); k++) {
                    BoolEdit e = list.get(k);
                    if (!e.element.equals(name)) continue;
                    if (!e.component.isEmpty()) {
                        String cn = componentName(pos);
                        if (cn == null || !fullClass(pkg, cn).equals(fullClass(pkg, e.component))) continue;
                    }
                    int base = attrBase(pos), sz = attrSize(pos), n = attrCount(pos);
                    for (int i = 0; i < n; i++) {
                        int a = base + i * sz;
                        int nsIdx = u32(a);
                        if (nsIdx == NONE || !ANDROID_NS.equals(str(nsIdx))) continue;
                        if (!e.attr.equals(str(u32(a + 4)))) continue;
                        if ((b.get(a + 15) & 0xFF) == TYPE_BOOLEAN) {
                            int nv = e.value ? -1 : 0;
                            if (b.getInt(a + 16) != nv) { b.putInt(a + 16, nv); changed++; }
                            found[k] = true;
                        } else {
                            notes.add("android:" + e.attr + " on <" + name + "> is not a plain boolean - skipped");
                            found[k] = true;
                        }
                    }
                }
            }
            pos += size;
        }
        for (int k = 0; k < list.size(); k++) {
            if (!found[k]) {
                BoolEdit e = list.get(k);
                notes.add("android:" + e.attr + " is not present on <" + e.element + ">" + (e.component.isEmpty() ? "" : " " + e.component) + " - cannot be added");
            }
        }
        return new Result(src, pkg, changed, notes);
    }

    private String componentName(int pos) throws IOException {
        int base = attrBase(pos), sz = attrSize(pos), n = attrCount(pos);
        for (int i = 0; i < n; i++) {
            int a = base + i * sz;
            int nsIdx = u32(a);
            if (nsIdx != NONE && ANDROID_NS.equals(str(nsIdx)) && "name".equals(str(u32(a + 4)))) return attrValue(a);
        }
        return null;
    }

    // ------------------------------------------------------------------ main

    private Result run() throws IOException {
        if (src.length < 8 || u16(0) != RES_XML) throw new IOException("Not a binary XML file");
        poolPos = 8;
        if (src.length < poolPos + 28 || u16(poolPos) != STRING_POOL) throw new IOException("String pool is not the first chunk");
        if (u16(poolPos + 2) != 28) throw new IOException("Unexpected string pool header size");
        poolSize = u32(poolPos + 4);
        strCount = u32(poolPos + 8);
        int styleCount = u32(poolPos + 12);
        flags = u32(poolPos + 16);
        stringsStart = u32(poolPos + 20);
        utf8 = (flags & 0x100) != 0;
        if (styleCount != 0) throw new IOException("String pool with styles is not supported");
        if (stringsStart != 28 + 4 * strCount) throw new IOException("Unexpected string pool layout");
        if (poolPos + poolSize > src.length) throw new IOException("Truncated string pool");

        String oldPkg = null;
        int pos = poolPos + poolSize;
        int end = Math.min(src.length, u32(4));
        boolean first = true;
        while (pos + 8 <= end) {
            int type = u16(pos);
            int size = u32(pos + 4);
            if (size < 8 || pos + size > src.length) throw new IOException("Corrupt chunk at " + pos);
            if (type == START_ELEMENT) {
                String name = str(u32(pos + 20));
                if (first) {
                    if (!"manifest".equals(name)) throw new IOException("First element is not <manifest>");
                    oldPkg = readPackage(pos);
                    if (oldPkg == null || oldPkg.isEmpty()) throw new IOException("Manifest has no package attribute");
                    first = false;
                }
                element(pos, name, oldPkg);
            }
            pos += size;
        }
        if (oldPkg == null) throw new IOException("No <manifest> element found");
        return new Result(build(), oldPkg, edits.size(), notes);
    }

    // ------------------------------------------------------------------ element handling

    private int attrBase(int pos) { return pos + 16 + u16(pos + 24); }
    private int attrSize(int pos) { return u16(pos + 26); }
    private int attrCount(int pos) { return u16(pos + 28); }

    private String readPackage(int pos) throws IOException {
        int base = attrBase(pos), sz = attrSize(pos), n = attrCount(pos);
        for (int i = 0; i < n; i++) {
            int a = base + i * sz;
            if (u32(a) == NONE && "package".equals(str(u32(a + 4)))) return attrValue(a);
        }
        return null;
    }

    private static boolean isComponent(String el) {
        return el.equals("application") || el.equals("activity") || el.equals("activity-alias") ||
                el.equals("service") || el.equals("receiver") || el.equals("provider");
    }

    private void element(int pos, String el, String old) throws IOException {
        int base = attrBase(pos), sz = attrSize(pos), n = attrCount(pos);
        if (sz < 20) throw new IOException("Unexpected attribute size");
        for (int i = 0; i < n; i++) {
            int a = base + i * sz;
            int nsIdx = u32(a);
            String attr = str(u32(a + 4));
            boolean android = nsIdx != NONE && ANDROID_NS.equals(str(nsIdx));
            String val = attrValue(a);
            if (val == null) continue; // not a plain string (reference, number, ...)

            if (el.equals("manifest")) {
                if (nsIdx == NONE && attr.equals("package")) set(a, newPkg);
                else if (android && attr.equals("sharedUserId")) notes.add("warning: sharedUserId \"" + val + "\" is kept (cannot be renamed)");
                continue;
            }
            if (!android) continue;

            // 1) relative class names -> full names of the OLD package
            if (isComponent(el) || el.equals("instrumentation")) {
                if (attr.equals("name") || attr.equals("backupAgent") || attr.equals("manageSpaceActivity") ||
                        attr.equals("appComponentFactory") || attr.equals("targetActivity") ||
                        attr.equals("parentActivityName") || attr.equals("zygotePreloadName")) {
                    String full = fullClass(old, val);
                    if (!full.equals(val)) set(a, full);
                    continue;
                }
            }

            // 2) names that carry the package
            switch (attr) {
                case "name":
                    if (el.equals("permission") || el.equals("permission-tree") || el.equals("permission-group") ||
                            el.equals("uses-permission") || el.equals("uses-permission-sdk-23") ||
                            el.equals("uses-permission-sdk-m")) {
                        replace(a, val, old);
                    } else if (el.equals("category")) {
                        if (val.equals(old)) set(a, newPkg);
                    }
                    break;
                case "permission":
                case "permissionGroup":
                    replace(a, val, old);
                    break;
                case "process":
                case "taskAffinity":
                    if (!val.startsWith(":")) replace(a, val, old);
                    break;
                case "targetPackage":
                    if (el.equals("instrumentation") && val.equals(old)) set(a, newPkg);
                    break;
                case "authorities":
                    if (el.equals("provider")) authorities(a, val, old);
                    break;
                default:
                    break;
            }
        }
    }

    private static String fullClass(String pkg, String name) {
        if (name.startsWith(".")) return pkg + name;
        if (name.indexOf('.') < 0) return pkg + "." + name;
        return name;
    }

    private String swap(String v, String old) {
        if (v.equals(old)) return newPkg;
        if (v.startsWith(old + ".")) return newPkg + v.substring(old.length());
        return v;
    }

    private void replace(int a, String val, String old) throws IOException {
        String nv = swap(val, old);
        if (!nv.equals(val)) set(a, nv);
    }

    private void authorities(int a, String val, String old) throws IOException {
        String[] parts = val.split(";");
        StringBuilder sb = new StringBuilder();
        boolean changed = false;
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            String q = swap(p, old);
            if (!q.equals(p)) changed = true;
            else notes.add("warning: provider authority \"" + p + "\" does not contain the package - it may conflict with the original app");
            if (i > 0) sb.append(';');
            sb.append(q);
        }
        if (changed) set(a, sb.toString());
    }

    // ------------------------------------------------------------------ attribute / string access

    /** String value of the attribute, or null when it is not a plain string. */
    private String attrValue(int a) throws IOException {
        int raw = u32(a + 8);
        int dataType = b.get(a + 15) & 0xFF;
        if (dataType == TYPE_STRING) return str(u32(a + 16));
        if (raw != NONE && dataType == 0) return str(raw);
        return null;
    }

    private void set(int attrPos, String value) {
        int idx;
        Integer have = addedIndex.get(value);
        if (have != null) idx = have;
        else {
            idx = strCount + added.size();
            added.add(value);
            addedIndex.put(value, idx);
        }
        edits.add(new int[]{attrPos, idx});
    }

    private String str(int idx) throws IOException {
        if (idx == NONE) return "";
        if (idx < 0 || idx >= strCount) throw new IOException("String index out of range: " + idx);
        String c = cache.get(idx);
        if (c != null) return c;
        int off = u32(poolPos + 28 + 4 * idx);
        int p = poolPos + stringsStart + off;
        String s;
        if (utf8) {
            int cl = b.get(p) & 0xFF;
            p++;
            if ((cl & 0x80) != 0) { cl = ((cl & 0x7F) << 8) | (b.get(p) & 0xFF); p++; }
            int bl = b.get(p) & 0xFF;
            p++;
            if ((bl & 0x80) != 0) { bl = ((bl & 0x7F) << 8) | (b.get(p) & 0xFF); p++; }
            s = new String(src, p, bl, StandardCharsets.UTF_8);
        } else {
            int len = u16(p);
            p += 2;
            if ((len & 0x8000) != 0) { len = ((len & 0x7FFF) << 16) | u16(p); p += 2; }
            s = new String(src, p, len * 2, StandardCharsets.UTF_16LE);
        }
        cache.put(idx, s);
        return s;
    }

    private byte[] encode(String s) throws IOException {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        if (utf8) {
            byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
            if (s.length() > 0x7FFF || bytes.length > 0x7FFF) throw new IOException("String too long");
            varLen8(o, s.length());
            varLen8(o, bytes.length);
            o.write(bytes);
            o.write(0);
        } else {
            if (s.length() > 0x7FFF) throw new IOException("String too long");
            o.write(s.length() & 0xFF);
            o.write((s.length() >> 8) & 0xFF);
            o.write(s.getBytes(StandardCharsets.UTF_16LE));
            o.write(0);
            o.write(0);
        }
        return o.toByteArray();
    }

    private static void varLen8(ByteArrayOutputStream o, int n) {
        if (n > 0x7F) { o.write(((n >> 8) & 0x7F) | 0x80); o.write(n & 0xFF); }
        else o.write(n);
    }

    // ------------------------------------------------------------------ output

    private byte[] build() throws IOException {
        if (edits.isEmpty()) throw new IOException("Nothing to change (package attribute not found?)");
        int k = added.size();

        // copy of the whole file with the attribute edits applied (in place, same sizes)
        byte[] work = src.clone();
        ByteBuffer w = ByteBuffer.wrap(work).order(ByteOrder.LITTLE_ENDIAN);
        for (int[] e : edits) {
            int a = e[0];
            if (w.getInt(a + 8) != NONE) w.putInt(a + 8, e[1]);
            if ((work[a + 15] & 0xFF) == TYPE_STRING) w.putInt(a + 16, e[1]);
        }

        // new string pool
        int oldDataStart = poolPos + stringsStart;
        int oldDataLen = poolSize - stringsStart;
        List<byte[]> enc = new ArrayList<>();
        int extra = 0;
        for (String s : added) { byte[] e = encode(s); enc.add(e); extra += e.length; }
        int dataLen = oldDataLen + extra;
        int padded = (dataLen + 3) & ~3;
        int newStringsStart = 28 + 4 * (strCount + k);
        int newPoolSize = newStringsStart + padded;

        ByteBuffer pool = ByteBuffer.allocate(newPoolSize).order(ByteOrder.LITTLE_ENDIAN);
        pool.putShort((short) STRING_POOL);
        pool.putShort((short) 28);
        pool.putInt(newPoolSize);
        pool.putInt(strCount + k);
        pool.putInt(0);
        pool.putInt(flags & ~0x1); // not sorted any more
        pool.putInt(newStringsStart);
        pool.putInt(0);
        for (int i = 0; i < strCount; i++) pool.putInt(u32(poolPos + 28 + 4 * i));
        int off = oldDataLen;
        for (byte[] e : enc) { pool.putInt(off); off += e.length; }
        pool.put(src, oldDataStart, oldDataLen);
        for (byte[] e : enc) pool.put(e);

        int restStart = poolPos + poolSize;
        int total = Math.min(src.length, u32(4));
        int restLen = total - restStart;
        ByteBuffer out = ByteBuffer.allocate(8 + newPoolSize + restLen).order(ByteOrder.LITTLE_ENDIAN);
        out.put(work, 0, 8);
        out.put(pool.array());
        out.put(work, restStart, restLen);
        out.putInt(4, out.capacity());
        return out.array();
    }

    private int u16(int p) { return b.getShort(p) & 0xFFFF; }
    private int u32(int p) { return b.getInt(p); }
}
