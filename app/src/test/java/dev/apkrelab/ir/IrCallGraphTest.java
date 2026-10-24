package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/** 0.53.0 (P0): tests for {@link CallGraph} on tiny hand-written smali. No APK, no device. */
public class IrCallGraphTest {

    private static String m(String sig, String... lines) {
        StringBuilder sb = new StringBuilder(".method public " + sig + "\n    .locals 3\n");
        for (String l : lines) sb.append("    ").append(l).append('\n');
        return sb.append("    return-void\n.end method\n").toString();
    }

    private static String cls(String flags, String type, String sup, String[] ifaces, String... methods) {
        StringBuilder sb = new StringBuilder(".class " + flags + " " + type + "\n.super " + sup + "\n");
        for (String i : ifaces) sb.append(".implements ").append(i).append('\n');
        sb.append('\n');
        for (String x : methods) sb.append(x).append('\n');
        return sb.toString();
    }

    private static String cls(String type, String sup, String... methods) {
        return cls("public", type, sup, new String[0], methods);
    }

    private static CallGraph graph(CallGraph.Mode mode, List<String> comps, String... texts) {
        List<ClassIr> cs = new ArrayList<>();
        for (String t : texts) cs.add(SmaliParser.parse(t));
        return CallGraph.build(cs, comps, mode, null);
    }

    private static final String OBJ = "Ljava/lang/Object;";

    // ---------- plain edges ----------

    @Test
    public void directChainFromComponentEntry() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                cls("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V", "invoke-static {}, Lt/B;->go()V")),
                cls("Lt/B;", OBJ, m("static go()V", "invoke-static {}, Lt/C;->run()V")),
                cls("Lt/C;", OBJ, m("static run()V"), m("static dead()V")));
        assertTrue(g.entries.contains("Lt/A;->onCreate(Landroid/os/Bundle;)V"));
        assertTrue(g.isReachable("Lt/C;->run()V"));
        assertFalse(g.isReachable("Lt/C;->dead()V"));
        assertEquals(Arrays.asList("Lt/A;->onCreate(Landroid/os/Bundle;)V", "Lt/B;->go()V", "Lt/C;->run()V"),
                g.pathTo("Lt/C;->run()V"));
        assertTrue(g.pathTo("Lt/C;->dead()V").isEmpty());
    }

    @Test
    public void frameworkCallsAreExternalEdges() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                cls("Lt/A;", "Landroid/app/Activity;",
                        m("onCreate(Landroid/os/Bundle;)V", "invoke-virtual {p0}, Landroid/app/Activity;->finish()V")));
        assertTrue(g.externalCalls.contains("Landroid/app/Activity;->finish()V"));
    }

    @Test
    public void superCallGoesToTheParent() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/Sub;"),
                cls("Lt/Base;", OBJ, m("onCreate(Landroid/os/Bundle;)V")),
                cls("Lt/Sub;", "Lt/Base;",
                        m("onCreate(Landroid/os/Bundle;)V", "invoke-super {p0, p1}, Lt/Base;->onCreate(Landroid/os/Bundle;)V")));
        assertTrue(g.calleesOf("Lt/Sub;->onCreate(Landroid/os/Bundle;)V").contains("Lt/Base;->onCreate(Landroid/os/Bundle;)V"));
    }

    @Test
    public void inheritedMethodResolvesToTheDeclaringClass() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                cls("Lt/Base;", OBJ, m("foo()V")),
                cls("Lt/Sub;", "Lt/Base;"),
                cls("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V",
                        "new-instance v0, Lt/Sub;", "invoke-virtual {v0}, Lt/Sub;->foo()V")));
        assertTrue(g.isReachable("Lt/Base;->foo()V"));
    }

    // ---------- virtual dispatch ----------

    private static String[] ifaceWorld(String callerBody) {
        return new String[]{
                cls("public interface abstract", "Lt/I;", OBJ, new String[0], ".method public abstract run()V\n.end method\n"),
                cls("public", "Lt/X;", OBJ, new String[]{"Lt/I;"}, m("run()V")),
                cls("public", "Lt/Y;", OBJ, new String[]{"Lt/I;"}, m("run()V")),
                cls("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V", callerBody.split("\n")))
        };
    }

    @Test
    public void rtaOnlyLinksInstantiatedTypes() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                ifaceWorld("new-instance v0, Lt/X;\ninvoke-interface {v0}, Lt/I;->run()V"));
        assertTrue(g.isReachable("Lt/X;->run()V"));
        assertFalse(g.isReachable("Lt/Y;->run()V"));
    }

    @Test
    public void chaLinksEveryConcreteImplementation() {
        CallGraph g = graph(CallGraph.Mode.CHA, Arrays.asList("Lt/A;"),
                ifaceWorld("new-instance v0, Lt/X;\ninvoke-interface {v0}, Lt/I;->run()V"));
        assertTrue(g.isReachable("Lt/X;->run()V"));
        assertTrue(g.isReachable("Lt/Y;->run()V"));
    }

    @Test
    public void rtaFallsBackToChaWhenNothingIsInstantiated() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                ifaceWorld("invoke-interface {p1}, Lt/I;->run()V"));
        assertTrue(g.isReachable("Lt/X;->run()V"));
        assertTrue(g.isReachable("Lt/Y;->run()V"));
        boolean approx = false;
        for (CallGraph.Edge e : g.edgesTo("Lt/X;->run()V")) approx |= e.kind.endsWith("~");
        assertTrue("fallback edges must be marked", approx);
    }

    @Test
    public void instantiationAfterTheCallSiteStillLinks() {
        // the call is visited first (callee 'use'), the new-instance comes later in another reachable method
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                cls("public interface abstract", "Lt/I;", OBJ, new String[0], ".method public abstract run()V\n.end method\n"),
                cls("public", "Lt/X;", OBJ, new String[]{"Lt/I;"}, m("run()V")),
                cls("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V",
                        "invoke-static {p1}, Lt/U;->use(Lt/I;)V", "invoke-static {}, Lt/U;->make()V")),
                cls("Lt/U;", OBJ, m("static use(Lt/I;)V", "invoke-interface {p0}, Lt/I;->run()V"),
                        m("static make()V", "new-instance v0, Lt/X;")));
        assertTrue(g.isReachable("Lt/X;->run()V"));
        for (CallGraph.Edge e : g.edgesTo("Lt/X;->run()V")) assertFalse(e.kind.endsWith("~"));
    }

    // ---------- implicit edges ----------

    @Test
    public void threadStartReachesRun() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                cls("Lt/T;", "Ljava/lang/Thread;", m("run()V")),
                cls("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V",
                        "new-instance v0, Lt/T;", "invoke-virtual {v0}, Lt/T;->start()V")));
        assertTrue(g.isReachable("Lt/T;->run()V"));
    }

    @Test
    public void listenerPassedToFrameworkIsACallback() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                cls("public", "Lt/Click;", OBJ, new String[]{"Landroid/view/View$OnClickListener;"},
                        m("onClick(Landroid/view/View;)V")),
                cls("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V",
                        "new-instance v1, Lt/Click;",
                        "invoke-virtual {v0, v1}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V")));
        assertTrue(g.isReachable("Lt/Click;->onClick(Landroid/view/View;)V"));
    }

    @Test
    public void staticInitialiserRunsWhenTheClassIsTouched() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                cls("Lt/K;", OBJ, ".method static constructor <clinit>()V\n    .locals 1\n    return-void\n.end method\n"),
                cls("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V",
                        "sget-object v0, Lt/K;->X:Ljava/lang/String;")));
        assertTrue(g.isReachable("Lt/K;-><clinit>()V"));
    }

    // ---------- output ----------

    @Test
    public void dotAndStats() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                cls("Lt/A;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V", "invoke-static {}, Lt/B;->go()V")),
                cls("Lt/B;", OBJ, m("static go()V")));
        String dot = g.toDot(g.pathTo("Lt/B;->go()V"));
        assertTrue(dot.contains("\"Lt/A;->onCreate(Landroid/os/Bundle;)V\" -> \"Lt/B;->go()V\""));
        assertTrue(g.stats().startsWith("RTA: "));
    }

    @Test
    public void emptyInputIsFine() {
        CallGraph g = CallGraph.build(new ArrayList<ClassIr>(), null, null, null);
        assertTrue(g.reachable.isEmpty());
    }

    // ---------- explicit ICC (0.54.1) ----------

    @Test
    public void explicitIntentLaunchLinksTheTargetLifecycle() {
        // InsecureBankv2 shape: LoginActivity.performlogin -> new Intent(this, DoLogin.class) -> DoLogin.onCreate -> AsyncTask.execute -> postData
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/Login;"),
                cls("Lt/Login;", "Landroid/app/Activity;",
                        m("onCreate(Landroid/os/Bundle;)V", "invoke-virtual {p0}, Lt/Login;->performlogin()V"),
                        m("performlogin()V",
                                "new-instance v0, Landroid/content/Intent;",
                                "const-class v1, Lt/DoLogin;",
                                "invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V",
                                "invoke-virtual {p0, v0}, Lt/Login;->startActivity(Landroid/content/Intent;)V")),
                cls("Lt/DoLogin;", "Landroid/app/Activity;",
                        m("onCreate(Landroid/os/Bundle;)V",
                                "new-instance v0, Lt/DoLogin$Req;",
                                "invoke-direct {v0}, Lt/DoLogin$Req;-><init>()V",
                                "invoke-virtual {v0, v1}, Lt/DoLogin$Req;->execute([Ljava/lang/Object;)Landroid/os/AsyncTask;")),
                cls("Lt/DoLogin$Req;", "Landroid/os/AsyncTask;",
                        m("<init>()V"),
                        m("doInBackground([Ljava/lang/Object;)Ljava/lang/Object;", "invoke-virtual {p0}, Lt/DoLogin$Req;->postData()V"),
                        m("postData()V")));
        assertTrue(g.isReachable("Lt/DoLogin;->onCreate(Landroid/os/Bundle;)V"));
        assertTrue(g.isReachable("Lt/DoLogin$Req;->postData()V"));
        List<String> path = g.pathTo("Lt/DoLogin$Req;->postData()V");
        assertTrue(path.contains("Lt/Login;->performlogin()V"));
        assertTrue(path.contains("Lt/DoLogin;->onCreate(Landroid/os/Bundle;)V"));
    }

    @Test
    public void classConstantWithoutIntentBuilderIsNotALaunch() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/A;"),
                cls("Lt/A;", "Landroid/app/Activity;",
                        m("onCreate(Landroid/os/Bundle;)V", "const-class v0, Lt/B;")),
                cls("Lt/B;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V")));
        assertFalse(g.isReachable("Lt/B;->onCreate(Landroid/os/Bundle;)V"));
    }

    // ---------- android:onClick handlers (0.54.2) ----------

    @Test
    public void layoutOnClickHandlerOfALaunchedActivityIsReachable() {
        // InsecureShop shape: Main -> new Intent(this, Login.class); Login.onLogin(View) is only named in the layout XML
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/Main;"),
                cls("Lt/Main;", "Landroid/app/Activity;",
                        m("onCreate(Landroid/os/Bundle;)V",
                                "new-instance v0, Landroid/content/Intent;",
                                "const-class v1, Lt/Login;",
                                "invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V")),
                cls("Lt/Login;", "Landroid/app/Activity;",
                        m("onCreate(Landroid/os/Bundle;)V"),
                        m("onLogin(Landroid/view/View;)V", "invoke-static {}, Lt/Log;->leak()V"),
                        ".method private hidden(Landroid/view/View;)V\n    .locals 1\n    return-void\n.end method\n",
                        m("helper(Ljava/lang/String;)V")),
                cls("Lt/Log;", OBJ, m("static leak()V")));
        assertTrue(g.isReachable("Lt/Login;->onLogin(Landroid/view/View;)V"));
        assertTrue(g.isReachable("Lt/Log;->leak()V"));
        assertFalse(g.isReachable("Lt/Login;->hidden(Landroid/view/View;)V"));
        assertFalse(g.isReachable("Lt/Login;->helper(Ljava/lang/String;)V"));
    }

    @Test
    public void exportedActivityOnClickHandlerIsAnEntry() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/About;"),
                cls("Lt/About;", "Landroid/app/Activity;", m("onSendData(Landroid/view/View;)V")));
        assertTrue(g.entries.contains("Lt/About;->onSendData(Landroid/view/View;)V"));
    }

    @Test
    public void serviceViewMethodIsNotAnEntry() {
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/S;"),
                cls("Lt/S;", "Landroid/app/Service;", m("poke(Landroid/view/View;)V")));
        assertFalse(g.entries.contains("Lt/S;->poke(Landroid/view/View;)V"));
    }

    // ---------- CgCompare diagnostics (0.54.3) ----------

    @Test
    public void compareExplainsWhereAPathBreaks() {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(cls("Lt/Main;", "Landroid/app/Activity;",
                m("onCreate(Landroid/os/Bundle;)V",
                        "const-class v1, Lt/Other;",
                        "invoke-virtual {p0}, Landroid/app/Activity;->finish()V"))));
        cs.add(SmaliParser.parse(cls("Lt/Other;", "Landroid/app/Activity;", m("onCreate(Landroid/os/Bundle;)V"), m("sink()V"))));
        List<CgCompare.Item> items = new ArrayList<>();
        items.add(new CgCompare.Item("Lt/Other;->sink()V", "YES", "demo",
                "Entry: exported activity t.Main Path: t.Main.onCreate() -> t.Other.onCreate() -> t.Other.sink()"));
        String r = CgCompare.run(cs, Arrays.asList("Lt/Main;"), items);
        assertTrue(r, r.contains("Other.onCreate: NOT REACHED"));
        assertTrue(r, r.contains("const-class: Other"));
        assertTrue(r, r.contains("Activity.finish"));
    }

    @Test
    public void compareShowsWhoCallsTheBrokenHopEvenWhenUnreached() {
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(cls("Lt/Main;", "Landroid/app/Activity;",
                m("onCreate(Landroid/os/Bundle;)V",
                        "new-instance v0, Landroid/content/Intent;",
                        "const-class v1, Lt/Other;",
                        "invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V"))));
        cs.add(SmaliParser.parse(cls("Lt/Other;", "Landroid/app/Activity;",
                m("onCreate(Landroid/os/Bundle;)V"),
                m("static lambda$0(Lt/Other;)V", "invoke-virtual {p0}, Lt/Other;->isRooted1()Z"),
                m("isRooted1()Z"))));
        List<CgCompare.Item> items = new ArrayList<>();
        items.add(new CgCompare.Item("Lt/Other;->isRooted1()Z", "YES", "demo",
                "Entry: exported activity t.Main Path: t.Main.onCreate() -> t.Other.isRooted1()"));
        String r = CgCompare.run(cs, Arrays.asList("Lt/Main;"), items);
        assertTrue(r, r.contains("Other.isRooted1: NOT REACHED"));
        assertTrue(r, r.contains("isRooted1()Z [public]"));
        assertTrue(r, r.contains("isRooted1 <- Other.lambda$0 (NOT reached)"));
        assertTrue(r, r.contains("Other.lambda$0 <- no caller"));
        assertTrue(r, r.contains("has a reached method"));
    }

    @Test
    public void onClickHandlerOfAnActivityWithAnUnexpectedBaseChainIsStillAnEntry() {
        // app base class on top of a framework class that is not named "...Activity"
        CallGraph g = graph(CallGraph.Mode.RTA, Arrays.asList("Lt/Main;"),
                cls("Lt/Main;", "Lt/Base;", m("go(Landroid/view/View;)V")),
                cls("Lt/Base;", "Landroidx/core/app/Weird;"));
        assertTrue(g.entries.contains("Lt/Main;->go(Landroid/view/View;)V"));
        assertTrue(g.superChain("Lt/Main;").equals("Lt/Main; -> Lt/Base; -> Landroidx/core/app/Weird;"));
    }
}
