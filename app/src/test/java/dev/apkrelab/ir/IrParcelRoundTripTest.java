package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 2.2 session 3a.1: a value written to a Parcel is what a later read of THE SAME Parcel object returns, and a setter/getter pair on the same field keeps the taint of
 * the value (field heap). WE Wallet / JustMarkets device reports: android/os/Parcel was the first owner of real taint drops (151 / 132).
 */
public class IrParcelRoundTripTest {

    static final String SRC = "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"p\"\n"
        + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n";
    static final String SINK = "    new-instance v4, Ljava/io/File;\n    invoke-direct {v4, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v4}, Ljava/io/File;->delete()Z\n";

    /** An exported activity that reads an extra, optionally writes it to a Parcel, reads the Parcel and deletes a File built from what it read. */
    static String parcelActivity(boolean write) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n" + SRC
            + "    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;\n    move-result-object v2\n"
            + (write ? "    invoke-virtual {v2, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V\n" : "")
            + "    invoke-virtual {v2}, Landroid/os/Parcel;->readString()Ljava/lang/String;\n    move-result-object v3\n"
            + SINK + "    return-void\n.end method\n";
    }

    static final String MODEL = ".class public Lt/M;\n.super Ljava/lang/Object;\n.field private x:Ljava/lang/String;\n.field private y:Ljava/lang/String;\n"
        + ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n"
        + ".method public setX(Ljava/lang/String;)V\n    .locals 0\n    iput-object p1, p0, Lt/M;->x:Ljava/lang/String;\n    return-void\n.end method\n"
        + ".method public getX()Ljava/lang/String;\n    .locals 1\n    iget-object v0, p0, Lt/M;->x:Ljava/lang/String;\n    return-object v0\n.end method\n"
        + ".method public getY()Ljava/lang/String;\n    .locals 1\n    iget-object v0, p0, Lt/M;->y:Ljava/lang/String;\n    return-object v0\n.end method\n";

    /** The activity stores the extra with setX and reads it back with getX (or getY, a field nothing ever wrote). */
    static String modelActivity(String getter) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n" + SRC
            + "    new-instance v2, Lt/M;\n    invoke-direct {v2}, Lt/M;-><init>()V\n    invoke-virtual {v2, v0}, Lt/M;->setX(Ljava/lang/String;)V\n"
            + "    invoke-virtual {v2}, Lt/M;->" + getter + "()Ljava/lang/String;\n    move-result-object v3\n"
            + SINK + "    return-void\n.end method\n";
    }

    static List<TaintIr.Flow> flows(String... smali) {
        List<ClassIr> all = new ArrayList<>();
        for (String s : smali) all.add(SmaliParser.parse(s));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        List<TaintIr.Flow> out = new ArrayList<>();
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) if (f.sink.method.startsWith("Lt/A;")) out.add(f);
        return out;
    }

    @Test public void parcelRoundTripKeepsTheTaintOfAWrittenValue() {
        List<TaintIr.Flow> f = flows(parcelActivity(true));
        assertEquals(1, f.size());
        assertTrue(f.get(0).source, f.get(0).source.startsWith("Intent."));
    }

    @Test public void aParcelNothingWasWrittenToStaysClean() { assertEquals(0, flows(parcelActivity(false)).size()); }

    @Test public void getterSetterRoundTripPreservesTaint() {
        List<TaintIr.Flow> f = flows(modelActivity("getX"), MODEL);
        assertEquals(1, f.size());
        assertTrue(f.get(0).source, f.get(0).source.startsWith("Intent."));
    }

    @Test public void getterOfUnwrittenFieldStaysUnclean() { assertEquals(0, flows(modelActivity("getY"), MODEL).size()); }
}
