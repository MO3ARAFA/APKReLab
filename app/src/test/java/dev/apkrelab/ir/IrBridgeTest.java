package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.56.0 (P1 step 2): tests for {@link SsaBridge} on tiny hand-written smali. No APK, no device. */
public class IrBridgeTest {

    private static final String OBJ = "Ljava/lang/Object;";
    private static final String GET = "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;";
    private static final String LOAD = "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";
    private static final String ON_CREATE = "Lt/A;->onCreate(Landroid/os/Bundle;)V";
    private static final String T_WEB = "Untrusted input is loaded into a WebView";
    private static final String T_SQL = "Untrusted input reaches an SQL statement";

    private static String mm(int locals, String sig, String... lines) {
        StringBuilder sb = new StringBuilder(".method public " + sig + "\n    .locals " + locals + "\n");
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static String mr(int locals, String sig, String... lines) {
        StringBuilder sb = new StringBuilder(".method public " + sig + "\n    .locals " + locals + "\n");
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append(".end method\n").toString();
    }

    private static String cls(String type, String sup, String... methods) {
        StringBuilder sb = new StringBuilder(".class public " + type + "\n.super " + sup + "\n\n");
        for (String x : methods) sb.append(x).append('\n');
        return sb.toString();
    }

    private static String act(String... methods) {
        return cls("Lt/A;", "Landroid/app/Activity;", methods);
    }

    private static final String[] SRC = {
            "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"", GET, "move-result-object v2"};

    private static String[] cat(String[] a, String... b) {
        String[] r = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    private static List<SsaBridge.Item> run(List<TaintIr.Old> old, String... texts) {
        List<ClassIr> cs = new ArrayList<>();
        for (String t : texts) cs.add(SmaliParser.parse(t));
        return SsaBridge.newFlows(cs, Arrays.asList("Lt/A;", "Lt/P;"), old);
    }

    private static String directWebFlow() {
        return act(mm(4, "onCreate(Landroid/os/Bundle;)V", cat(SRC, "new-instance v3, Landroid/webkit/WebView;", LOAD)));
    }

    @Test
    public void aFlowTheOldEngineMissedIsReturnedWithEverythingTheScannerNeeds() {
        String text = directWebFlow();
        List<SsaBridge.Item> items = run(new ArrayList<TaintIr.Old>(), text);
        assertEquals(1, items.size());
        SsaBridge.Item it = items.get(0);
        assertEquals("Lt/A;", it.classType);
        assertEquals(ON_CREATE, it.method);
        assertEquals(T_WEB, it.title);
        assertEquals("CWE-79", it.cwe);
        assertEquals("HIGH", it.sev);
        assertEquals("HIGH", it.confidence);   // real source, no validation call, reachable
        assertTrue(it.reachable);
        assertEquals("A.onCreate(Landroid/os/Bundle;)V", it.entry);
        assertTrue(it.detail.startsWith("Data from Intent.getStringExtra() reaches "));
        assertTrue(it.fix.length() > 20);
        // the offset points at the start of the sink instruction line (Finding.at jumps to it)
        assertTrue(text.substring(it.at).startsWith(LOAD));
    }

    @Test
    public void aFlowTheOldEngineAlreadyHasIsNotReturned() {
        List<TaintIr.Old> old = new ArrayList<>();
        old.add(new TaintIr.Old(ON_CREATE, T_WEB));
        assertEquals(0, run(old, directWebFlow()).size());
    }

    @Test
    public void sameMethodWithAnotherTitleIsStillNew() {
        List<TaintIr.Old> old = new ArrayList<>();
        old.add(new TaintIr.Old(ON_CREATE, T_SQL));
        assertEquals(1, run(old, directWebFlow()).size());
    }

    @Test
    public void severalFlowsOfOneKindInOneMethodBecomeOneItemWithACount() {
        String text = act(mm(4, "onCreate(Landroid/os/Bundle;)V", cat(SRC, "new-instance v3, Landroid/webkit/WebView;", LOAD,
                "invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadData(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V")));
        List<SsaBridge.Item> items = run(new ArrayList<TaintIr.Old>(), text);
        assertEquals(1, items.size());
        assertEquals(2, items.get(0).count);
        assertTrue(items.get(0).detail.contains("2 flows of this kind"));
    }

    /**
     * The scanner merges findings with the same title inside one class into ONE card that keeps only the first method (scanSmali), so the
     * old list says "this class has an SQL finding" and nothing finer. A second SQL sink in that class is part of the card, not new.
     */
    @Test
    public void aSecondSinkOfTheSameTitleInAClassTheOldCardCoversIsNotNew() {
        String prov = cls("Lt/P;", "Landroid/content/ContentProvider;",
                mr(4, "delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I",
                        "new-instance v0, Landroid/database/sqlite/SQLiteDatabase;", "const-string v1, \"t\"",
                        "invoke-virtual {v0, v1, p2, p3}, Landroid/database/sqlite/SQLiteDatabase;->delete(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I",
                        "move-result v2", "return v2"),
                mr(4, "update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I",
                        "new-instance v0, Landroid/database/sqlite/SQLiteDatabase;", "const-string v1, \"t\"",
                        "invoke-virtual {v0, v1, p2, p3, p4}, Landroid/database/sqlite/SQLiteDatabase;->update(Ljava/lang/String;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I",
                        "move-result v2", "return v2"));
        String act = act(mm(4, "onCreate(Landroid/os/Bundle;)V"));
        List<TaintIr.Old> card = new ArrayList<>();
        card.add(new TaintIr.Old("Lt/P;->delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I", T_SQL));
        assertEquals(0, run(card, act, prov).size());
        // a class-only key (what the scanner glue passes) answers the same way
        List<TaintIr.Old> classOnly = new ArrayList<>();
        classOnly.add(new TaintIr.Old("Lt/P;->", T_SQL));
        assertEquals(0, run(classOnly, act, prov).size());
        // no old finding in that class: both methods are new, and a provider parameter is level 1 = MEDIUM confidence
        List<SsaBridge.Item> items = run(new ArrayList<TaintIr.Old>(), act, prov);
        assertEquals(2, items.size());
        assertEquals("MEDIUM", items.get(0).confidence);
        assertEquals("HIGH", items.get(0).sev);
    }

    @Test
    public void theSameTitleInAnotherClassIsStillNew() {
        List<TaintIr.Old> old = new ArrayList<>();
        old.add(new TaintIr.Old("Lt/Other;->", T_WEB));
        assertEquals(1, run(old, directWebFlow()).size());
    }

    @Test
    public void aClassNoEntryReachesIsReturnedWithALowerConfidenceAndAnExplanation() {
        String hidden = cls("Lt/Hidden;", "Landroidx/appcompat/app/c;", mm(4, "onCreate(Landroid/os/Bundle;)V", cat(SRC,
                "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        List<SsaBridge.Item> items = run(new ArrayList<TaintIr.Old>(), act(mm(4, "onCreate(Landroid/os/Bundle;)V")), hidden);
        assertEquals(1, items.size());
        SsaBridge.Item it = items.get(0);
        assertFalse(it.reachable);
        assertEquals("", it.entry);
        assertEquals("", it.path);
        assertEquals("MEDIUM", it.confidence);   // HIGH lowered one step
        assertEquals("HIGH", it.sev);            // severity only drops when the confidence is LOW
        assertTrue(it.detail.contains("No exported component reaches this method"));
    }

    @Test
    public void aValidationLikeCallOnTheChainLowersTheConfidence() {
        String text = act(mm(4, "onCreate(Landroid/os/Bundle;)V", cat(SRC,
                "const-string v1, \"https://\"",
                "invoke-virtual {v2, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z",
                "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        List<SsaBridge.Item> items = run(new ArrayList<TaintIr.Old>(), text);
        assertEquals(1, items.size());
        assertEquals("MEDIUM", items.get(0).confidence);
        assertTrue(items.get(0).detail.contains("validation-like calls"));
    }

    @Test
    public void unreachableAndValidatedFlowEndsLowAndTheSeverityDropsOneLevel() {
        String hidden = cls("Lt/Hidden;", "Landroidx/appcompat/app/c;", mm(4, "onCreate(Landroid/os/Bundle;)V", cat(SRC,
                "const-string v1, \"https://\"",
                "invoke-virtual {v2, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z",
                "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        List<SsaBridge.Item> items = run(new ArrayList<TaintIr.Old>(), act(mm(4, "onCreate(Landroid/os/Bundle;)V")), hidden);
        assertEquals(1, items.size());
        assertEquals("LOW", items.get(0).confidence);
        assertEquals("MEDIUM", items.get(0).sev);
    }

    @Test
    public void sharedPreferencesSourceIsAlwaysLow() {
        String text = act(mm(5, "onCreate(Landroid/os/Bundle;)V",
                "const-string v1, \"k\"", "const-string v4, \"d\"",
                "invoke-interface {v0, v1, v4}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                "move-result-object v2", "new-instance v3, Landroid/webkit/WebView;", LOAD));
        List<SsaBridge.Item> items = run(new ArrayList<TaintIr.Old>(), text);
        assertEquals(1, items.size());
        assertEquals("LOW", items.get(0).confidence);
        assertEquals("MEDIUM", items.get(0).sev);
        assertTrue(items.get(0).detail.contains("only an attacker with root"));
    }

    @Test
    public void shellSinkKeepsCriticalWhenTheFlowIsStrong() {
        String text = act(mm(5, "onCreate(Landroid/os/Bundle;)V", cat(SRC,
                "invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;", "move-result-object v3",
                "invoke-virtual {v3, v2}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;")));
        List<SsaBridge.Item> items = run(new ArrayList<TaintIr.Old>(), text);
        assertEquals(1, items.size());
        assertEquals("CRITICAL", items.get(0).sev);
        assertEquals("CWE-78", items.get(0).cwe);
    }

    @Test
    public void noFlowsMeansAnEmptyListAndNullOldIsAccepted() {
        String clean = act(mm(4, "onCreate(Landroid/os/Bundle;)V", "const-string v2, \"https://x\"", "new-instance v3, Landroid/webkit/WebView;", LOAD));
        assertEquals(0, run(null, clean).size());
    }

    @Test
    public void theListIsCapped() {
        StringBuilder methods = new StringBuilder();
        for (int i = 0; i < SsaBridge.MAX_ITEMS + 10; i++) {
            methods.append(mm(4, "m" + i + "()V", cat(SRC, "new-instance v3, Landroid/webkit/WebView;", LOAD)));
        }
        String text = cls("Lt/A;", "Landroid/app/Activity;", methods.toString());
        assertEquals(SsaBridge.MAX_ITEMS, run(new ArrayList<TaintIr.Old>(), text).size());
    }
}
