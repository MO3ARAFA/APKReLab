package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Collections;
import java.util.List;

import org.junit.Test;

/** 0.58.0 (P1 step 4, part 1): {@link CallSkeleton} and the entry slice of {@link ScopePlanner}. Tiny hand-written smali, no APK. */
public class IrSkeletonTest {

    private static final String GET = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String LOAD = "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";
    private static final String[] FLOW = {"new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2",
            "new-instance v3, Landroid/webkit/WebView;", LOAD};

    /** A class with one method; {@code header} lines (.super / .implements) are given by the caller. */
    private static String cls(String type, String sup, String[] impls, String modifiers, String sig, int locals, String... lines) {
        StringBuilder sb = new StringBuilder(".class public " + type + "\n.super " + sup + "\n");
        if (impls != null) for (String i : impls) sb.append(".implements ").append(i).append('\n');
        sb.append("\n.method public ").append(modifiers).append(sig).append("\n    .locals ").append(locals).append('\n');
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static String plain(String type) {
        return cls(type, "Ljava/lang/Object;", null, "static ", "go()V", 0);
    }

    private static String calls(String type, String callee) {
        return cls(type, "Ljava/lang/Object;", null, "static ", "go()V", 0, "invoke-static {}, " + callee + "->go()V");
    }

    private static String marked(String type) {
        return cls(type, "Ljava/lang/Object;", null, "static ", "go()V", 4, FLOW);
    }

    private static ScopePlanner.Source src(final List<String> types, final List<String> texts) {
        return new ScopePlanner.Source() {
            public int count() { return types.size(); }
            public String type(int i) { return types.get(i); }
            public String text(int i) { return texts.get(i); }
        };
    }

    private static List<String> names(ScopePlanner.Plan p, List<String> types) {
        List<String> out = new ArrayList<>();
        for (int i : p.selected) out.add(types.get(i));
        return out;
    }

    @Test
    public void aChainOfFiveHopsFromTheEntryIsKeptWholeAndAnUnreachableCallerIsNot() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        String[] chain = {"Lt/A;", "Lt/H1;", "Lt/H2;", "Lt/H3;", "Lt/H4;"};
        for (int i = 0; i < chain.length; i++) {
            types.add(chain[i]);
            texts.add(calls(chain[i], i + 1 < chain.length ? chain[i + 1] : "Lt/Sink;"));
        }
        types.add("Lt/Sink;");
        texts.add(marked("Lt/Sink;"));
        // a 4-hop caller chain that NO entry reaches: depth 1 and 2 are kept (old tiers), hops 3 and 4 are not
        String[] dead = {"Lt/D4;", "Lt/D3;", "Lt/D2;", "Lt/D1;"};
        for (int i = 0; i < dead.length; i++) {
            types.add(dead[i]);
            texts.add(calls(dead[i], i + 1 < dead.length ? dead[i + 1] : "Lt/Sink;"));
        }
        for (int i = 0; i < 200; i++) {
            types.add("Lt/Fill" + i + ";");
            texts.add(plain("Lt/Fill" + i + ";"));
        }
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.singletonList("Lt/A;"), 50);
        List<String> got = names(p, types);
        for (String c : chain) assertTrue(c + " is on the entry path", got.contains(c));
        assertTrue(got.contains("Lt/Sink;"));
        assertTrue(got.contains("Lt/D1;"));
        assertTrue(got.contains("Lt/D2;"));
        assertFalse(got.contains("Lt/D3;"));
        assertFalse(got.contains("Lt/D4;"));
        assertEquals(6, p.slice);
        assertFalse(p.capped);
    }

    @Test
    public void theFlowBehindAFiveHopEntryPathIsReachableNow() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/A;");
        texts.add(cls("Lt/A;", "Landroid/app/Activity;", null, "", "onCreate(Landroid/os/Bundle;)V", 0, "invoke-static {}, Lt/H1;->go()V"));
        String[] hops = {"Lt/H1;", "Lt/H2;", "Lt/H3;", "Lt/H4;"};
        for (int i = 0; i < hops.length; i++) {
            types.add(hops[i]);
            texts.add(calls(hops[i], i + 1 < hops.length ? hops[i + 1] : "Lt/Sink;"));
        }
        types.add("Lt/Sink;");
        texts.add(marked("Lt/Sink;"));
        for (int i = 0; i < 300; i++) {
            types.add("Lt/Fill" + i + ";");
            texts.add(plain("Lt/Fill" + i + ";"));
        }
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.singletonList("Lt/A;"), 20);
        assertEquals(6, p.selected.length);
        List<ClassIr> cs = new ArrayList<>();
        for (int i : p.selected) cs.add(SmaliParser.parse(texts.get(i)));
        List<SsaBridge.Item> items = SsaBridge.newFlows(cs, Collections.singletonList("Lt/A;"), new ArrayList<TaintIr.Old>());
        assertEquals(1, items.size());
        assertEquals("Lt/Sink;", items.get(0).classType);
        assertTrue("the entry path must be complete", items.get(0).reachable);
    }

    @Test
    public void anInterfaceCallReachesTheImplementationThatHoldsTheSink() {
        List<String> types = Arrays.asList("Lt/A;", "Lt/Iface;", "Lt/Impl;", "Lt/Other;");
        List<String> texts = Arrays.asList(
                calls("Lt/A;", "Lt/Iface;"),
                cls("Lt/Iface;", "Ljava/lang/Object;", null, "abstract ", "go()V", 0),
                cls("Lt/Impl;", "Ljava/lang/Object;", new String[]{"Lt/Iface;"}, "static ", "go()V", 4, FLOW),
                plain("Lt/Other;"));
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.singletonList("Lt/A;"), 10);
        List<String> got = names(p, types);
        assertTrue(got.contains("Lt/Impl;"));
        assertTrue(got.contains("Lt/Iface;"));
        assertFalse(got.contains("Lt/Other;"));
        assertEquals(2, p.slice);   // A, Impl (Iface comes in as a supertype of Impl)
    }

    @Test
    public void aCallOnASubclassReachesTheInheritedMethodInItsBase() {
        List<String> types = Arrays.asList("Lt/A;", "Lt/Sub;", "Lt/Base;");
        List<String> texts = Arrays.asList(
                calls("Lt/A;", "Lt/Sub;"),
                cls("Lt/Sub;", "Lt/Base;", null, "static ", "other()V", 0),
                marked("Lt/Base;").replace(".super Ljava/lang/Object;", ".super Ljava/lang/Object;"));
        ScopePlanner.Plan p = ScopePlanner.plan(src(types, texts), Collections.singletonList("Lt/A;"), 10);
        List<String> got = names(p, types);
        assertTrue(got.contains("Lt/Base;"));
        assertEquals(3, p.slice);
    }

    @Test
    public void aConstClassIntentTargetIsAnEdge() {
        List<String> types = Arrays.asList("Lt/A;", "Lt/Target;", "Lt/Other;");
        List<String> texts = Arrays.asList(
                cls("Lt/A;", "Landroid/app/Activity;", null, "", "onCreate(Landroid/os/Bundle;)V", 1, "const-class v0, Lt/Target;"),
                marked("Lt/Target;"),
                plain("Lt/Other;"));
        CallSkeleton sk = CallSkeleton.build(src(types, texts), Collections.singletonList("Lt/A;"));
        assertTrue(Arrays.equals(new int[]{1}, sk.calleesOf(0)));
        assertTrue(Arrays.equals(new int[]{0}, sk.callersOf(1)));
        BitSet fwd = sk.forward(sk.entry);
        assertTrue(fwd.get(1));
        assertFalse(fwd.get(2));
    }

    @Test
    public void aBaseClassWithTooManyDescendantsIsNotExpandedButKeepsItsOwnEdges() {
        List<String> types = new ArrayList<>(), texts = new ArrayList<>();
        types.add("Lt/A;");
        texts.add(calls("Lt/A;", "Lt/Base;"));
        types.add("Lt/Base;");
        texts.add(plain("Lt/Base;"));
        int kids = CallSkeleton.MAX_DESCENDANTS + 5;
        for (int i = 0; i < kids; i++) {
            types.add("Lt/Kid" + i + ";");
            texts.add(cls("Lt/Kid" + i + ";", "Lt/Base;", null, "static ", "go()V", 0));
        }
        CallSkeleton sk = CallSkeleton.build(src(types, texts), Collections.singletonList("Lt/A;"));
        assertEquals(1, sk.calleesOf(0).length);        // only Base itself, the 69 kids are not linked from the call site
        assertTrue(Arrays.equals(new int[]{1}, sk.calleesOf(2)));   // a kid still depends on its base
    }

    @Test
    public void edgesAreSmallIntArraysAndStatsAreCounted() {
        List<String> types = Arrays.asList("Lt/A;", "Lt/B;", "Lt/C;");
        List<String> texts = Arrays.asList(calls("Lt/A;", "Lt/B;"), calls("Lt/B;", "Lt/C;"), marked("Lt/C;"));
        CallSkeleton sk = CallSkeleton.build(src(types, texts), Collections.singletonList("Lt/A;"));
        assertEquals(2, sk.edges);
        assertEquals(3, sk.n);
        assertTrue(sk.stats().startsWith("3 classes, 2 edges, 1 marked, 1 entries"));
        assertEquals(Arrays.asList("Lt/A;", "Lt/B;", "Lt/C;"), sk.typesOf(sk.backward(sk.marked())));
    }

    @Test
    public void cancelReturnsNullFromTheSkeleton() {
        final List<String> types = Arrays.asList("Lt/A;", "Lt/B;");
        ScopePlanner.Source s = new ScopePlanner.Source() {
            public int count() { return 2; }
            public String type(int i) { return types.get(i); }
            public String text(int i) { return plain(types.get(i)); }
            public boolean cancelled() { return true; }
        };
        assertNull(CallSkeleton.build(s, Collections.<String>emptyList()));
    }
}
