package dev.apkrelab.ir;

import static org.junit.Assert.*;
import java.util.*;
import org.junit.Test;

/**
 * 3.0.0 (real-CVE benchmark C14, OsmAnd AidlParams): (1) a value handed to a method called on "this" and stored there in a field of "this" keeps the caller's taint
 * (SELF_CALL_CAPTURE); (2) a Parcel-held value is strong when the path from the exported entry goes through a Binder's onTransact (SsaBridge.ipcParcel).
 */
public class IrSelfCallAidlTest {
    static final String SRC = "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n    const-string v1, \"p\"\n"
        + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n";
    static String act(boolean onThis) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n.field public f:Ljava/lang/String;\n" + IrBridgeSupport.CTOR
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 4\n" + SRC
            + (onThis ? "    invoke-virtual {p0, v2}, Lt/A;->store(Ljava/lang/String;)V\n"
                      : "    new-instance v3, Lt/A;\n    invoke-direct {v3}, Lt/A;-><init>()V\n    invoke-virtual {v3, v2}, Lt/A;->store(Ljava/lang/String;)V\n")
            + "    invoke-virtual {p0}, Lt/A;->use()V\n    return-void\n.end method\n"
            // store() is bigger than the 8-instruction setter summary: only the self-call capture keeps the value
            + ".method public store(Ljava/lang/String;)V\n    .locals 2\n    const-string v0, \"x\"\n    invoke-virtual {p1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;\n"
            + "    move-result-object v1\n    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String;\n    move-result-object v1\n    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String;\n"
            + "    move-result-object v1\n    invoke-virtual {v1}, Ljava/lang/String;->trim()Ljava/lang/String;\n    move-result-object v1\n    iput-object v1, p0, Lt/A;->f:Ljava/lang/String;\n    return-void\n.end method\n"
            + ".method public use()V\n    .locals 2\n    iget-object v0, p0, Lt/A;->f:Ljava/lang/String;\n    new-instance v1, Ljava/io/FileInputStream;\n"
            + "    invoke-direct {v1, v0}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V\n    return-void\n.end method\n";
    }
    static boolean flowToUse(String smali, boolean on) {
        boolean was = TaintIr.SELF_CALL_CAPTURE;
        TaintIr.SELF_CALL_CAPTURE = on;
        try {
            CallGraph g = CallGraph.build(new ArrayList<>(Arrays.asList(SmaliParser.parse(smali))), Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
            for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) if (f.sink.method.startsWith("Lt/A;->use(")) return true;
            return false;
        } finally { TaintIr.SELF_CALL_CAPTURE = was; }
    }

    @Test public void aSelfCallStoreKeepsTheCallersTaint() { assertTrue(flowToUse(act(true), true)); }
    @Test public void theSwitchOffLosesIt() { assertFalse(flowToUse(act(true), false)); }                         // mutation
    @Test public void aCallOnAnotherObjectIsNotASelfCall() { assertFalse(flowToUse(act(false), true)); }          // twin

    static TaintIr.Flow parcelHeld(boolean reachable, String... path) {
        TaintIr.SinkRef r = new TaintIr.SinkRef("Lt/B;->w()V", 0, "FileOutputStream.<init>", TaintIr.T_FILE, "HIGH", "CWE-22", Collections.<String>emptyList());
        TaintIr.Flow f = new TaintIr.Flow("Parcel.readString()", 1, TaintIr.PARCEL_HELD_MARK + "P.getName()", true, r, Arrays.asList("Lt/B;->w()V"));
        f.reachable = reachable;
        f.entryPath = Arrays.asList(path);
        return f;
    }

    @Test public void aParcelableUnmarshalledByOnTransactIsAnOutsideValue() {
        assertTrue(SsaBridge.ipcParcel(parcelHeld(true, "Lt/S;-><init>()V", "Lt/I$Stub;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z", "Lt/B;->w()V")));
        assertFalse(SsaBridge.ipcParcel(parcelHeld(true, "Lt/Main;->onCreate(Landroid/os/Bundle;)V", "Lt/B;->w()V")));       // twin: no Binder on the path
        assertFalse(SsaBridge.ipcParcel(parcelHeld(false, "Lt/I$Stub;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z"))); // twin: not reachable
        boolean was = SsaBridge.AIDL_PARCEL;
        SsaBridge.AIDL_PARCEL = false;
        try { assertFalse(SsaBridge.ipcParcel(parcelHeld(true, "Lt/I$Stub;->onTransact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z"))); } finally { SsaBridge.AIDL_PARCEL = was; }   // mutation
    }
}
