package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.74.0: intent redirection. The Intent OBJECT that came from the caller (getParcelableExtra) is handed to startActivity & co.
 * An Intent that only carries tainted extras (putExtra / putExtras) is the normal forwarding pattern and must stay quiet.
 */
public class IrRedirectTest {

    private static TaintIr.Flow flow(String entry, String smali) {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(smali));
        CallGraph g = CallGraph.build(cs, Arrays.asList(entry), CallGraph.Mode.RTA, null);
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        for (TaintIr.Flow f : r.flows) if (f.sink.title.equals(TaintIr.T_REDIRECT)) return f;
        return null;
    }

    private static String activity(String body) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 5\n"
                + "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
                + body + "    return-void\n.end method\n";
    }

    private static final String GET_PARCEL =
            "    const-string v1, \"extra_intent\"\n"
          + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;\n"
          + "    move-result-object v2\n    check-cast v2, Landroid/content/Intent;\n";

    @Test
    public void parcelableIntentFromTheCallerLaunchedWithStartActivityIsRedirection() {
        TaintIr.Flow f = flow("Lt/A;", activity(GET_PARCEL + "    invoke-virtual {p0, v2}, Lt/A;->startActivity(Landroid/content/Intent;)V\n"));
        assertNotNull(f);
        assertEquals("Intent.getParcelableExtra()", f.source);
    }

    @Test
    public void startServiceAndSendBroadcastCountToo() {
        assertNotNull(flow("Lt/A;", activity(GET_PARCEL + "    invoke-virtual {p0, v2}, Lt/A;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;\n")));
        assertNotNull(flow("Lt/A;", activity(GET_PARCEL + "    invoke-virtual {p0, v2}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n")));
    }

    @Test
    public void anIntentBuiltFromAStringExtraIsNotRedirection() {
        String body = "    const-string v1, \"k\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + "    new-instance v3, Landroid/content/Intent;\n    const-class v4, Lt/B;\n"
                + "    invoke-direct {v3, p0, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n"
                + "    invoke-virtual {v3, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n"
                + "    invoke-virtual {p0, v3}, Lt/A;->startActivity(Landroid/content/Intent;)V\n";
        assertNull(flow("Lt/A;", activity(body)));
    }

    @Test
    public void forwardingTheExtrasBundleIsNotRedirection() {
        String body = "    invoke-virtual {v0}, Landroid/content/Intent;->getExtras()Landroid/os/Bundle;\n    move-result-object v2\n"
                + "    new-instance v3, Landroid/content/Intent;\n    const-class v4, Lt/B;\n"
                + "    invoke-direct {v3, p0, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n"
                + "    invoke-virtual {v3, v2}, Landroid/content/Intent;->putExtras(Landroid/os/Bundle;)Landroid/content/Intent;\n"
                + "    invoke-virtual {p0, v3}, Lt/A;->startActivity(Landroid/content/Intent;)V\n";
        assertNull(flow("Lt/A;", activity(body)));
    }

    @Test
    public void aFixedIntentIsQuiet() {
        String body = "    new-instance v3, Landroid/content/Intent;\n    const-class v4, Lt/B;\n"
                + "    invoke-direct {v3, p0, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n"
                + "    invoke-virtual {p0, v3}, Lt/A;->startActivity(Landroid/content/Intent;)V\n";
        assertNull(flow("Lt/A;", activity(body)));
    }

    @Test
    public void aParcelableThatIsNotLaunchedIsQuiet() {
        assertNull(flow("Lt/A;", activity(GET_PARCEL)));
    }

    @Test
    public void theParcelableIntentWrappedAsAnExtraOfAFixedIntentIsQuiet() {
        // the attacker Intent only travels as DATA inside our own Intent (typical "forward" screen): not a redirect by itself
        String body = GET_PARCEL
                + "    new-instance v3, Landroid/content/Intent;\n    const-class v4, Lt/B;\n"
                + "    invoke-direct {v3, p0, v4}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n"
                + "    const-string v1, \"inner\"\n"
                + "    invoke-virtual {v3, v1, v2}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;\n"
                + "    invoke-virtual {p0, v3}, Lt/A;->startActivity(Landroid/content/Intent;)V\n";
        assertNull(flow("Lt/A;", activity(body)));
    }
}
