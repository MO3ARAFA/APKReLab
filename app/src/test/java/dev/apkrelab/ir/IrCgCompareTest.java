package dev.apkrelab.ir;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.54.0: CgCompare sorts old-vs-new reach answers into the right buckets. */
public class IrCgCompareTest {

    private static String m(String sig, String... lines) {
        StringBuilder sb = new StringBuilder(".method public " + sig + "\n    .locals 2\n");
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static ClassIr c(String type, String sup, String... methods) {
        StringBuilder sb = new StringBuilder(".class public " + type + "\n.super " + sup + "\n\n");
        for (String x : methods) sb.append(x).append('\n');
        return SmaliParser.parse(sb.toString());
    }

    @Test
    public void bucketsAreSeparated() {
        List<ClassIr> app = new ArrayList<>(Arrays.asList(
                c("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V", "invoke-static {}, Lt/B;->go()V"),
                        m("helper()V")),
                c("Lt/B;", "Ljava/lang/Object;", m("static go()V"), m("static lonely()V"))));
        List<CgCompare.Item> items = new ArrayList<>();
        items.add(new CgCompare.Item("Lt/B;->go()V", "YES", "agree yes", "Entry: A"));
        items.add(new CgCompare.Item("Lt/B;->lonely()V", "NO", "agree no", ""));
        items.add(new CgCompare.Item("Lt/A;->helper()V", "YES", "entry class itself", ""));
        items.add(new CgCompare.Item("Lt/B;->lonely()V", "YES", "lost path", "Entry: X"));
        String r = CgCompare.run(app, Arrays.asList("Lt/A;"), items);
        assertTrue(r, r.contains("findings compared: 4"));
        assertTrue(r, r.contains("expected: the old trace counts it at depth 0): 1"));
        assertTrue(r, r.contains("NEEDS A LOOK (the new graph lost a path): 1"));
        assertTrue(r, r.contains("OLD NO, NEW YES (the new graph found a path the old one missed): 0"));
    }

    @Test
    public void newGraphFindingsTheOldMissed() {
        List<ClassIr> app = new ArrayList<>(Arrays.asList(
                c("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V", "invoke-static {}, Lt/B;->go()V")),
                c("Lt/B;", "Ljava/lang/Object;", m("static go()V"))));
        List<CgCompare.Item> items = new ArrayList<>();
        items.add(new CgCompare.Item("Lt/B;->go()V", "NO", "old missed", ""));
        String r = CgCompare.run(app, Arrays.asList("Lt/A;"), items);
        assertTrue(r, r.contains("(the new graph found a path the old one missed): 1"));
        assertTrue(r, r.contains("A.onCreate -> B.go"));
    }
}
