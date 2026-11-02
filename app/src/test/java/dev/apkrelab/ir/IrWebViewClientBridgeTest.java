package dev.apkrelab.ir;

import static dev.apkrelab.ir.IrBridgeSupport.*;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** 2.2 session 3b, bridge (i): setWebViewClient / setWebChromeClient. REACH ONLY: the client's callbacks become reachable from the method that installs the client; no source is added (the usual shouldOverrideUrlLoading(request.getUrl()) is the app navigating where the page asked: a by-design flow on every app). */
public class IrWebViewClientBridgeTest {

    static final String WV_CLIENT = ".class public Lt/T;\n.super Landroid/webkit/WebViewClient;\n" + CTOR
        + ".method public shouldOverrideUrlLoading(Landroid/webkit/WebView;Ljava/lang/String;)Z\n    .locals 4\n" + SRC + SINK + "    const/4 v3, 0x0\n    return v3\n.end method\n";
    static final String WV_NEW = "    new-instance v4, Lt/T;\n    invoke-direct {v4}, Lt/T;-><init>()V\n";
    static final String WV_SET = "    iget-object v5, p0, Lt/A;->w:Landroid/webkit/WebView;\n    invoke-virtual {v5, v4}, Landroid/webkit/WebView;->setWebViewClient(Landroid/webkit/WebViewClient;)V\n";

    @Test public void aWebViewClientThatTheActivityInstallsIsReached() {
        TaintIr.Flow f = flowOn("Lt/T;", activity(WV_NEW + WV_SET), WV_CLIENT);
        assertTrue(f != null && f.reachable);
    }
    @Test public void aWebViewClientThatIsNeverInstalledIsNotReached() {
        TaintIr.Flow f = flowIn("Lt/T;", activity(WV_NEW), WV_CLIENT);
        assertTrue(f == null || !f.reachable);
    }

    @Test public void theBridgeIsOffByDefault() {
        TaintIr.Flow f = flowIn("Lt/T;", activity(WV_NEW + WV_SET), WV_CLIENT);
        assertTrue(f == null || !f.reachable);
    }
}
