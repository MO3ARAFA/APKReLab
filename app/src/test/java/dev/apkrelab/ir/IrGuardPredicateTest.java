package dev.apkrelab.ir;

import static org.junit.Assert.*;
import java.util.*;
import org.junit.Test;

/** 3.0.0 (blind round 4, AndStatus ZipUtils: isFileInsideFolder(file, folder) before each entry is written): a boolean app predicate holding a strong check is a guard. */
public class IrGuardPredicateTest {
    static String act(String guardBody) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n" + IrBridgeSupport.CTOR
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n" + IrBridgeSupport.SRC
            + "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n"
            + "    invoke-static {v2}, Lt/U;->inside(Ljava/io/File;)Z\n    move-result v3\n    if-eqz v3, :skip\n"
            + "    new-instance v1, Ljava/io/FileOutputStream;\n    invoke-direct {v1, v2}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V\n    :skip\n    return-void\n.end method\n"
            + ".class public Lt/U;\n";
    }
    static String util(boolean canonical) {
        return ".class public Lt/U;\n.super Ljava/lang/Object;\n.method public static inside(Ljava/io/File;)Z\n    .locals 2\n"
            + (canonical ? "    invoke-virtual {p0}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;\n    move-result-object v0\n    const-string v1, \"/data/x/\"\n"
                          + "    invoke-virtual {v0, v1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z\n    move-result v0\n    return v0\n"
                         : "    invoke-virtual {p0}, Ljava/io/File;->exists()Z\n    move-result v0\n    return v0\n")
            + ".end method\n";
    }
    static SsaBridge.Item item(boolean canonical) {
        String a = act("").replace(".class public Lt/U;\n", "");
        List<ClassIr> all = new ArrayList<>(Arrays.asList(SmaliParser.parse(a), SmaliParser.parse(util(canonical))));
        for (SsaBridge.Item it : SsaBridge.newFlows(all, Arrays.asList("Lt/A;"), new ArrayList<TaintIr.Old>())) if (it.title.equals(TaintIr.T_FILE)) return it;
        return null;
    }

    @Test public void aCanonicalPathPredicateIsAGuard() {
        SsaBridge.Item it = item(true);
        assertNotNull(it);
        assertTrue(it.detail, it.detail.contains("validation-like calls"));
    }
    @Test public void aPredicateWithoutACheckIsNot() {                                  // twin: exists() is not a validation
        SsaBridge.Item it = item(false);
        assertNotNull(it);
        assertFalse(it.detail, it.detail.contains("validation-like calls"));
    }
    @Test public void theMutationIgnoresThePredicate() {
        boolean was = SsaBridge.GUARD_PREDICATES;
        SsaBridge.GUARD_PREDICATES = false;
        try { assertFalse(item(true).detail.contains("validation-like calls")); } finally { SsaBridge.GUARD_PREDICATES = was; }
    }
}
