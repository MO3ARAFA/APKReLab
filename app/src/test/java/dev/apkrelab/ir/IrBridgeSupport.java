package dev.apkrelab.ir;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 2.2 session 3b: fixtures shared by the bridge tests. What each bridge treats as SOURCE or TRANSPORT is declared in its own test class and in CallGraph (BINDER_HOSTING,
 * callbackRegistered); none of the three call-graph bridges adds a source or a sink (reach only), the SuspendLambda case is a TRANSPORT of captured fields (CTOR_CAPTURE).
 */
final class IrBridgeSupport {
    private IrBridgeSupport() {}

    static final String SRC = "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"p\"\n"
        + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v0\n";
    static final String SINK = "    new-instance v2, Ljava/io/File;\n    invoke-direct {v2, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V\n    invoke-virtual {v2}, Ljava/io/File;->delete()Z\n";
    static final String CTOR = ".method public constructor <init>()V\n    .locals 0\n    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n    return-void\n.end method\n";

    /** The flow whose sink is in class {@code target} (null when the engine reports none). */
    static TaintIr.Flow flowIn(String target, String... smali) {
        List<ClassIr> all = new ArrayList<>();
        for (String s : smali) all.add(SmaliParser.parse(s));
        CallGraph g = CallGraph.build(all, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        for (TaintIr.Flow f : TaintIr.analyze(g, false, null).flows) if (f.sink.method.startsWith(target)) return f;
        return null;
    }

    /** The engine switches of sessions 3a.1 and 3b are OFF by default; the positive bridge tests run with them on. */
    static TaintIr.Flow flowOn(String target, String... smali) {
        boolean w = CallGraph.WEBVIEW_CLIENT_EDGES, r = CallGraph.RESULT_CALLBACK_EDGES, b = CallGraph.BINDER_HOSTING, p = TaintIr.PARCEL_ROUNDTRIP;
        CallGraph.WEBVIEW_CLIENT_EDGES = true; CallGraph.RESULT_CALLBACK_EDGES = true; CallGraph.BINDER_HOSTING = true; TaintIr.PARCEL_ROUNDTRIP = true;
        try { return flowIn(target, smali); }
        finally { CallGraph.WEBVIEW_CLIENT_EDGES = w; CallGraph.RESULT_CALLBACK_EDGES = r; CallGraph.BINDER_HOSTING = b; TaintIr.PARCEL_ROUNDTRIP = p; }
    }

    static String activity(String body) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n.field public w:Landroid/webkit/WebView;\n" + CTOR
            + ".method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n" + body + "    return-void\n.end method\n";
    }
}
