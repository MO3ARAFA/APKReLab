package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.86.1 (recall kit case 36): an ObjectInputStream built over bytes that came from an exported component is a taint sink. */
public class IrDeserializationSinkTest {

    private static List<SsaBridge.Item> run(String extraSource) {
        String t = ".class public Lt/S;\n.super Landroid/app/Service;\n\n.method public onStartCommand(Landroid/content/Intent;II)I\n    .locals 6\n"
                + extraSource
                + "    new-instance v1, Ljava/io/ByteArrayInputStream;\n    invoke-direct {v1, v0}, Ljava/io/ByteArrayInputStream;-><init>([B)V\n"
                + "    new-instance v2, Ljava/io/ObjectInputStream;\n    invoke-direct {v2, v1}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V\n"
                + "    const/4 v4, 0x2\n    return v4\n.end method\n";
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(t));
        return SsaBridge.newFlows(cs, Arrays.asList("Lt/S;"), new ArrayList<TaintIr.Old>());
    }

    @Test public void bytesFromAnIntentExtraReachingObjectInputStreamAreAFinding() {
        List<SsaBridge.Item> it = run("    const-string v0, \"blob\"\n    invoke-virtual {p1, v0}, Landroid/content/Intent;->getByteArrayExtra(Ljava/lang/String;)[B\n    move-result-object v0\n");
        assertEquals(1, it.size());
        assertEquals(TaintIr.T_DESER, it.get(0).title);
        assertEquals("HIGH", it.get(0).sev);
        assertEquals("CWE-502", it.get(0).cwe);
    }

    @Test public void bytesBuiltLocallyAreNotAFinding() {                                    // negative twin
        List<SsaBridge.Item> it = run("    const/16 v0, 0x10\n    new-array v0, v0, [B\n");
        assertTrue(it.isEmpty());
    }
}
