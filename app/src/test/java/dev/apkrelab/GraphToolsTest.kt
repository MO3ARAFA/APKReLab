package dev.apkrelab

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** 0.103.0: the agent's graph tools (callers / callees / flow_path) on synthetic smali and a real CallIndex built by SecurityScanner.collectEdges. Each positive has a negative twin. */
class GraphToolsTest {
    private val b = ".class public Lcom/example/B;\n.super Ljava/lang/Object;\n" +
        ".method public bar()V\n    .locals 1\n    return-void\n.end method\n" +
        ".method public bar(I)V\n    .locals 1\n    return-void\n.end method\n" +
        ".method public baz()V\n    .locals 2\n" +
        "    invoke-virtual {p0}, Lcom/example/B;->bar()V\n" +
        "    invoke-virtual {p0}, Lcom/example/B;->bar()V\n" +
        "    invoke-static {v0}, Lcom/example/Util;->helper(I)V\n" +
        "    invoke-virtual {v0}, Lcom/squareup/okhttp3/Call;->execute()Lx/Response;\n" +
        "    invoke-virtual {v0}, Ljava/lang/String;->length()I\n" +
        ".end method\n" +
        ".method public other()V\n    .locals 1\n    invoke-static {}, Lcom/example/Secret;->only()V\n.end method\n" +
        ".method public abstract gone()V\n.end method\n"
    private val a = ".class public Lcom/example/A;\n.super Ljava/lang/Object;\n" +
        ".method public foo()V\n    .locals 1\n    invoke-virtual {v0}, Lcom/example/B;->bar()V\n.end method\n"
    private val c = ".class public Lcom/example/C;\n.super Ljava/lang/Object;\n" +
        ".method public run()V\n    .locals 1\n    invoke-virtual {v0}, Lcom/example/B;->bar()V\n.end method\n" +
        ".method public never()V\n    .locals 1\n    return-void\n.end method\n"

    // ---------------- signatures ----------------
    @Test fun signaturesByNameOverloadsAndFullSignature() {
        assertEquals(listOf("bar()V", "bar(I)V"), GraphTools.signatures(b, "bar"))
        assertEquals(listOf("bar(I)V"), GraphTools.signatures(b, "bar(I)V"))
        assertTrue(GraphTools.signatures(b, "ba").isEmpty())                          // twin: a prefix of a name is not a name
        assertTrue(GraphTools.signatures(b, "").isEmpty()); assertTrue(GraphTools.signatures(b, "nothing").isEmpty())
    }

    // ---------------- callees ----------------
    @Test fun calleesAreDistinctCountedAndStayInsideTheMethod() {
        val l = GraphTools.callees(b, "baz()V")
        assertEquals(listOf("Lcom/example/B;->bar()V", "Lcom/example/Util;->helper(I)V", "Lcom/squareup/okhttp3/Call;->execute()Lx/Response;", "Ljava/lang/String;->length()I"), l.map { it.target })
        assertEquals(2, l[0].count); assertEquals("virtual", l[0].kind); assertEquals("static", l[1].kind)
        assertTrue(l.none { it.target.contains("Secret") })                           // twin: the invoke of the NEXT method is not included
        assertTrue(GraphTools.callees(b, "gone()V").isEmpty())                        // abstract: nothing
        assertTrue(GraphTools.callees(b, "missing()V").isEmpty())
    }

    @Test fun calleesAreSplitIntoAppLibraryAndFramework() {
        val app = setOf("Lcom/example/B;", "Lcom/example/Util;")
        val out = GraphTools.renderCallees("Lcom/example/B;", "baz()V", GraphTools.callees(b, "baz()V"), { it in app }, 10)
        assertTrue(out.contains("4 distinct method(s): 2 in the app, 1 in libraries, 1 in the framework"))
        assertTrue(out.indexOf("App code:") < out.indexOf("Libraries:") && out.indexOf("Libraries:") < out.indexOf("Framework:"))
        assertTrue(out.contains("com.example.B.bar()V  [virtual x2]")); assertTrue(out.contains("java.lang.String.length()I"))
        assertTrue(GraphTools.renderCallees("Lcom/example/B;", "baz()V", GraphTools.callees(b, "baz()V"), { it in app }, 1).contains("... 1 more"))    // the limit
        assertTrue(GraphTools.renderCallees("Lcom/example/B;", "gone()V", emptyList(), { true }, 5).contains("no invoke calls"))                  // twin
    }

    // ---------------- callers (a real CallIndex) ----------------
    private fun index(): SecurityScanner.CallIndex {
        val idx = SecurityScanner.CallIndex()
        SecurityScanner.collectEdges("Lcom/example/A;", 0, a, idx)
        SecurityScanner.collectEdges("Lcom/example/B;", 1, b, idx)
        SecurityScanner.collectEdges("Lcom/example/C;", 2, c, idx)
        return idx
    }
    private val types = listOf("Lcom/example/A;", "Lcom/example/B;", "Lcom/example/C;")
    private val texts = listOf(a, b, c)
    private fun describe(ref: Long): String? {
        val ci = (ref ushr 32).toInt()
        val m = GraphTools.methodByHash(types[ci], texts[ci], ref.toInt()) ?: return null
        return types[ci].removePrefix("L").removeSuffix(";").replace('/', '.') + "." + m
    }

    @Test fun callersComeFromTheCallIndexAndAreNamedByTheirMethod() {
        val idx = index()
        val refs = idx.callersOf("Lcom/example/B;->bar()V".hashCode())
        val out = GraphTools.renderCallers("Lcom/example/B;", "bar()V", refs, ::describe, 10)
        assertTrue(out.contains("com.example.A.foo()V")); assertTrue(out.contains("com.example.C.run()V")); assertTrue(out.contains("com.example.B.baz()V"))
        assertFalse(out.contains("never"))                                            // twin: a method that calls nothing is not listed
        // the overload bar(I)V has its own key: nobody calls it
        val none = GraphTools.renderCallers("Lcom/example/B;", "bar(I)V", idx.callersOf("Lcom/example/B;->bar(I)V".hashCode()), ::describe, 10)
        assertTrue(none.startsWith("No caller of com.example.B.bar(I)V")); assertTrue(none.contains("interface"))
        // the limit
        assertTrue(GraphTools.renderCallers("Lcom/example/B;", "bar()V", refs, ::describe, 1).contains("the first 1 shown"))
    }

    @Test fun methodByHashRoundTripsAndRejectsAWrongHash() {
        assertEquals("bar()V", GraphTools.methodByHash("Lcom/example/B;", b, "Lcom/example/B;->bar()V".hashCode()))
        assertNull(GraphTools.methodByHash("Lcom/example/B;", b, "Lcom/example/B;->nope()V".hashCode()))
        assertNull(GraphTools.methodByHash("Lcom/example/Other;", b, "Lcom/example/B;->bar()V".hashCode()))      // the class type is part of the key
    }

    // ---------------- flow_path ----------------
    private fun finding(title: String, cls: String = "Lcom/example/A;") = SecurityScanner.Finding(SecurityScanner.Severity.HIGH, title, "detail", "fix", cls, 0, 10, "CWE-89")

    @Test fun flowPathReportsTheDataPathTheReachChainAndWhatIsMissing() {
        val f = finding("Untrusted input reaches an SQL statement").also {
            it.ruleId = "taint-flow"; it.confidence = "HIGH"; it.dataPath = "Intent.getStringExtra -> A.foo -> rawQuery"; it.sourceMethod = "Lcom/example/A;->foo()V"
            it.reach = "YES"; it.chain = "Entry: com.example.Main\nPath: Main.onCreate -> A.foo"; it.adjusted = "lowered one level: not exported"
        }
        val out = GraphTools.flowPath(f, 3, "Lcom/example/A;->foo()V")
        for (s in listOf("Finding #3 [HIGH]", "in Lcom/example/A;->foo()V", "Rule: taint-flow (confidence HIGH)", "Data path (SSA taint, source -> sink): Intent.getStringExtra", "Source value first held in", "reachable from an exported component", "Entry: com.example.Main", "Severity adjusted: lowered"))
            assertTrue(s, out.contains(s))
        // twins: a pattern finding has no data path; reach NO; not traced
        val p = GraphTools.flowPath(finding("Weak cipher mode: ECB"), 1, null)
        assertTrue(p.contains("none recorded (this finding comes from a pattern rule")); assertTrue(p.contains("not traced yet"))
        assertTrue(GraphTools.flowPath(finding("x").also { it.reach = "NO" }, 1, null).contains("no path from an exported component"))
        assertTrue(GraphTools.flowPath(finding("x").also { it.reach = "YES~"; it.chain = "Approximate path" }, 1, null).contains("approximately reachable"))
        assertFalse(p.contains("Source value first held in"))
    }

    @Test fun aFindingIsPickedByNumberOrTitleAndNothingIsGuessed() {
        val l = listOf(finding("First issue"), finding("Second issue", "Lcom/example/Pay;"), finding("Third"))
        assertEquals(2, GraphTools.pick(l, "2")!!.first); assertEquals(2, GraphTools.pick(l, "#2")!!.first)
        assertEquals("Second issue", GraphTools.pick(l, "second")!!.second.title)
        assertEquals(2, GraphTools.pick(l, "example.pay")!!.first)                    // by location
        assertNull(GraphTools.pick(l, "0")); assertNull(GraphTools.pick(l, "4")); assertNull(GraphTools.pick(l, "")); assertNull(GraphTools.pick(l, "nothing like this"))
    }

    // ---------------- the tool registry ----------------
    @Test fun theThreeToolsAreRegisteredAndOfferedToTheModel() {
        for (n in listOf("callers", "callees", "flow_path")) {
            val t = Tools.all.firstOrNull { it.name == n }
            assertNotNull(n, t); assertFalse("a read-only tool must not ask the user", t!!.asks)
            assertTrue(Tools.systemPrompt(false, "").contains(n))
        }
        assertEquals(Tools.all.size, Tools.all.map { it.name }.toSet().size)           // no duplicate names
    }
}
