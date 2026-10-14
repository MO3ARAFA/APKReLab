package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.74.0: two new sources found by the sink/source audit of 0.72.0 and kept as gaps until the first held-out run.
 * (1) Parcel.readString() & co inside a Parcelable constructor / createFromParcel / readFromParcel / onTransact (OVAA MemoryCorruptionParcelable).
 * (2) ZipEntry.getName() (Zip Slip): the archive entry name that reaches a file sink.
 */
public class IrParcelZipTest {

    private static TaintIr.Flow flow(String entry, String... smali) {
        List<ClassIr> cs = new ArrayList<>();
        for (String s : smali) cs.add(SmaliParser.parse(s));
        CallGraph g = CallGraph.build(cs, Arrays.asList(entry), CallGraph.Mode.RTA, null);
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        return r.flows.isEmpty() ? null : r.flows.get(0);
    }

    private static String parcelClass(String methodHeader, String parcelReg) {
        return ".class public Lt/Mc;\n.super Ljava/lang/Object;\n\n.method " + methodHeader + "\n    .locals 3\n"
                + "    invoke-virtual {" + parcelReg + "}, Landroid/os/Parcel;->readString()Ljava/lang/String;\n"
                + "    move-result-object v0\n"
                + "    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;\n"
                + "    return-void\n.end method\n";
    }

    @Test
    public void parcelableConstructorReadStringIntoClassForNameIsAFlow() {
        TaintIr.Flow f = flow("Lt/Mc;", parcelClass("public constructor <init>(Landroid/os/Parcel;)V", "p1"));
        assertNotNull(f);
        assertEquals(TaintIr.T_REFL, f.sink.title);
        assertEquals("Parcel.readString()", f.source);
    }

    @Test
    public void createFromParcelAndOnTransactAreUnmarshallingMethodsToo() {
        assertNotNull(flow("Lt/Mc;", parcelClass("public createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;", "p1")));
        assertNotNull(flow("Lt/Mc;", parcelClass("public onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z", "p2")));
    }

    @Test
    public void parcelReadInAnOrdinaryMethodIsNotASource() {
        assertNull(flow("Lt/Mc;", parcelClass("public foo(Landroid/os/Parcel;)V", "p1")));
    }

    @Test
    public void aParcelThatTheMethodObtainedItselfIsNotASource() {
        String t = ".class public Lt/Mc;\n.super Ljava/lang/Object;\n\n.method public constructor <init>()V\n    .locals 3\n"
                + "    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;\n    move-result-object v1\n"
                + "    invoke-virtual {v1}, Landroid/os/Parcel;->readString()Ljava/lang/String;\n    move-result-object v0\n"
                + "    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;\n    return-void\n.end method\n";
        assertNull(flow("Lt/Mc;", t));
    }

    @Test
    public void aFixedClassNameFromTheParcelConstructorStaysQuiet() {
        String t = ".class public Lt/Mc;\n.super Ljava/lang/Object;\n\n.method public constructor <init>(Landroid/os/Parcel;)V\n    .locals 3\n"
                + "    const-string v0, \"java.lang.String\"\n"
                + "    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;\n    return-void\n.end method\n";
        assertNull(flow("Lt/Mc;", t));
    }

    private static String unzip(String entryOwner, boolean guarded) {
        // .locals 4; p0 = this, p1 = entry, p2 = target directory (File)
        String guard = guarded
                ? "    invoke-virtual {v1}, Ljava/io/File;->getCanonicalPath()Ljava/lang/String;\n    move-result-object v3\n"
                  + "    invoke-virtual {v3, v3}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z\n    move-result v3\n"
                : "";
        return ".class public Lt/Z;\n.super Ljava/lang/Object;\n\n.method public unzip(" + "L" + entryOwner + ";Ljava/io/File;)V\n    .locals 4\n"
                + "    invoke-virtual {p1}, L" + entryOwner + ";->getName()Ljava/lang/String;\n    move-result-object v0\n"
                + "    new-instance v1, Ljava/io/File;\n    invoke-direct {v1, p2, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V\n"
                + guard
                + "    new-instance v2, Ljava/io/FileOutputStream;\n    invoke-direct {v2, v1}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V\n"
                + "    return-void\n.end method\n";
    }

    @Test
    public void zipEntryNameIntoAFileOutputStreamIsAZipSlipFlow() {
        TaintIr.Flow f = flow("Lt/Z;", unzip("java/util/zip/ZipEntry", false));
        assertNotNull(f);
        assertEquals(TaintIr.T_FILE, f.sink.title);
        assertEquals("ZipEntry.getName()", f.source);
    }

    @Test
    public void commonsCompressEntryNameIsASourceToo() {
        assertNotNull(flow("Lt/Z;", unzip("org/apache/commons/compress/archivers/zip/ZipArchiveEntry", false)));
    }

    @Test
    public void anUnrelatedGetNameIsNotASource() {
        assertNull(flow("Lt/Z;", unzip("java/io/File", false)));
    }

    @Test
    public void aCanonicalPathGuardLowersTheConfidenceToLow() {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(unzip("java/util/zip/ZipEntry", true)));
        List<SsaBridge.Item> items = SsaBridge.newFlows(cs, Arrays.asList("Lt/Z;"), new ArrayList<TaintIr.Old>());
        assertEquals(1, items.size());
        assertEquals("LOW", items.get(0).confidence);
        assertTrue(items.get(0).detail.contains("Zip Slip"));
    }
}
