package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

/** 0.105.0: the planner digest of a class and the store that keeps it between scans: a skeleton built from stored digests is the skeleton built from the texts. */
public class IrDigestTest {
    private static String cls(String type, String sup, String impl, String... body) {
        StringBuilder sb = new StringBuilder(".class public " + type + "\n.super " + sup + "\n");
        if (impl != null) sb.append(".implements ").append(impl).append('\n');
        sb.append(".method public static go(Landroid/content/Context;)V\n    .locals 5\n");
        for (String l : body) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static final String PREFS = "invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";
    private static final String EXTRA = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String LOAD = "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";

    private final List<String> types = new ArrayList<>(), texts = new ArrayList<>();

    private void app() {
        types.clear(); texts.clear();
        add("Lt/A;", cls("Lt/A;", "Landroid/app/Activity;", null, "invoke-static {v0}, Lt/B;->go(Landroid/content/Context;)V", "const-class v1, Lt/C;"));
        add("Lt/B;", cls("Lt/B;", "Lt/Base;", "Lt/I;", EXTRA, "move-result-object v2", "invoke-static {v0}, Lt/Impl;->go(Landroid/content/Context;)V"));
        add("Lt/Base;", cls("Lt/Base;", "Ljava/lang/Object;", null, LOAD));
        add("Lt/I;", cls("Lt/I;", "Ljava/lang/Object;", null));
        add("Lt/Impl;", cls("Lt/Impl;", "Ljava/lang/Object;", "Lt/I;", PREFS, "move-result-object v2", LOAD));
        add("Lt/C;", cls("Lt/C;", "Landroid/content/ContentProvider;", null));
        add("Lt/P;", cls("Lt/P;", "Landroid/content/ContentProvider;", null));          // a provider: a source by its super type alone
        for (int i = 0; i < 20; i++) add("Lt/F" + i + ";", cls("Lt/F" + i + ";", "Ljava/lang/Object;", null, "invoke-static {v0}, Lt/F" + ((i + 1) % 20) + ";->go(Landroid/content/Context;)V"));
    }

    private void add(String t, String text) {
        types.add(t);
        texts.add(text);
    }

    private ScopePlanner.Source fromText() {
        return new ScopePlanner.Source() {
            public int count() { return types.size(); }
            public String type(int i) { return types.get(i); }
            public String text(int i) { return texts.get(i); }
        };
    }

    private ScopePlanner.Source fromStore(final DigestStore st) {
        return new ScopePlanner.Source() {
            public int count() { return types.size(); }
            public String type(int i) { return types.get(i); }
            public String text(int i) { throw new IllegalStateException("a stored digest must not read the text"); }
            public CallSkeleton.Digest digest(int i) { return st.get(types.get(i)); }
        };
    }

    private static String shape(CallSkeleton sk) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < sk.n; i++) sb.append(sk.types[i]).append(' ').append(sk.flags[i]).append(Arrays.toString(sk.calleesOf(i))).append(Arrays.toString(sk.callersOf(i))).append('\n');
        return sb.append(sk.entry).toString();
    }

    @Test
    public void aSkeletonFromStoredDigestsIsTheSkeletonFromTheTexts() throws Exception {
        app();
        DigestStore st = new DigestStore();
        for (int i = 0; i < types.size(); i++) st.put(types.get(i), CallSkeleton.digest(texts.get(i)));
        File f = File.createTempFile("digest", ".dg");
        f.deleteOnExit();
        assertTrue(st.save(f));
        DigestStore back = DigestStore.load(f);
        assertEquals(types.size(), back.size());
        List<String> entries = Arrays.asList("Lt/A;");
        for (boolean prefs : new boolean[]{true, false}) {
            String want = shape(CallSkeleton.build(fromText(), entries, prefs));
            assertEquals(want, shape(CallSkeleton.build(fromStore(back), entries, prefs)));
        }
        // the weak (SharedPreferences) source counts only when asked: the stored bits must keep that difference
        assertTrue(!shape(CallSkeleton.build(fromText(), entries, true)).equals(shape(CallSkeleton.build(fromText(), entries, false))));
        for (int i = 0; i < types.size(); i++) assertEquals(SsaGroups.fnvOf(texts.get(i)), back.get(types.get(i)).textHash);   // the group cache key's hash
        assertEquals(ScopePlanner.groups(fromText(), entries, 6).groups.size(), ScopePlanner.groups(fromStore(back), entries, 6).groups.size());
    }

    @Test
    public void aDamagedStoreIsAnEmptyStore() throws Exception {
        app();
        DigestStore st = new DigestStore();
        for (int i = 0; i < types.size(); i++) st.put(types.get(i), CallSkeleton.digest(texts.get(i)));
        File f = File.createTempFile("digest", ".dg");
        f.deleteOnExit();
        st.save(f);
        byte[] b = Files.readAllBytes(f.toPath());
        Files.write(f.toPath(), Arrays.copyOf(b, b.length - 3));
        assertEquals(0, DigestStore.load(f).size());                         // truncated
        Files.write(f.toPath(), Arrays.copyOf(b, b.length + 1));
        assertEquals(0, DigestStore.load(f).size());                         // trailing bytes
        byte[] m = b.clone(); m[0] ^= 1;
        Files.write(f.toPath(), m);
        assertEquals(0, DigestStore.load(f).size());                         // another format
        assertEquals(0, DigestStore.load(new File(f.getPath() + ".missing")).size());
        Files.write(f.toPath(), b);
        assertEquals(types.size(), DigestStore.load(f).size());               // twin: the intact file loads
        DigestStore again = DigestStore.load(f);
        assertTrue(!again.changed());
        again.put("Lt/New;", CallSkeleton.digest(""));
        assertTrue(again.changed());
        assertEquals(0, again.get("Lt/New;").refs.length);
    }
}
