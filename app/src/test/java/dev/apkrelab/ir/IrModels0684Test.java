package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 0.68.4 (sandbox measurement on Wikipedia / NewPipe / Mastodon / k9mail): Pair / Triple / MatrixCursor / okhttp builders hold what they are given,
 * Json / Base64 / Pattern / java.time hand the taint of their input to the result. Every positive has a clean twin.
 */
public class IrModels0684Test {

    private static final String[] SRC = {
            "new-instance v0, Landroid/content/Intent;", "const-string v1, \"u\"",
            "invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;", "move-result-object v2"};

    private static final String SINK = "invoke-virtual {v1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V";

    private static TaintIr.Result run(String... body) {
        StringBuilder sb = new StringBuilder(".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 7\n");
        for (String l : SRC) sb.append("    ").append(l).append('\n');
        for (String l : body) sb.append("    ").append(l).append('\n');
        sb.append("    return-void\n.end method\n");
        List<ClassIr> cs = new ArrayList<>();
        cs.add(SmaliParser.parse(sb.toString()));
        CallGraph g = CallGraph.build(cs, Arrays.asList("Lt/A;"), CallGraph.Mode.RTA, null);
        return TaintIr.analyze(g, true, null);
    }

    private static TaintIr.Result pair(String valueReg) {
        return run(
                "const-string v6, \"k\"",
                "new-instance v3, Lkotlin/Pair;",
                "invoke-direct {v3, v6, " + valueReg + "}, Lkotlin/Pair;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V",
                "invoke-virtual {v3}, Lkotlin/Pair;->getSecond()Ljava/lang/Object;", "move-result-object v4",
                SINK);
    }

    @Test
    public void aPairKeepsTheTaintOfItsValue() {
        TaintIr.Result r = pair("v2");
        assertEquals(1, r.flows.size());
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void aPairOfCleanValuesStaysClean() {
        assertEquals(0, pair("v6").flows.size());
    }

    private static TaintIr.Result base64(String reg) {
        return run(
                "const/4 v5, 0x0",
                "invoke-static {" + reg + ", v5}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B", "move-result-object v4",
                SINK);
    }

    @Test
    public void base64DecodeHandsTheTaintToItsResult() {
        TaintIr.Result r = base64("v2");
        assertEquals(1, r.flows.size());
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void base64DecodeOfACleanStringStaysClean() {
        assertEquals(0, base64("v1").flows.size());
    }

    private static TaintIr.Result json(String reg) {
        return run(
                "new-instance v3, Lkotlinx/serialization/json/Json;",
                "invoke-virtual {v3, v6, " + reg + "}, Lkotlinx/serialization/json/Json;->decodeFromString(Lkotlinx/serialization/DeserializationStrategy;Ljava/lang/String;)Ljava/lang/Object;", "move-result-object v4",
                SINK);
    }

    @Test
    public void jsonDecodeFromStringHandsTheTaintToItsResult() {
        TaintIr.Result r = json("v2");
        assertEquals(1, r.flows.size());
        assertEquals(0, r.stats.library[0]);
    }

    @Test
    public void jsonDecodeOfACleanStringStaysClean() {
        assertEquals(0, json("v1").flows.size());
    }

    private static TaintIr.Result date(String reg) {
        return run(
                "invoke-static {" + reg + "}, Ljava/time/LocalDate;->parse(Ljava/lang/CharSequence;)Ljava/time/LocalDate;", "move-result-object v4",
                SINK);
    }

    @Test
    public void localDateParseHandsTheTaintToItsResult() {
        assertEquals(1, date("v2").flows.size());
    }

    @Test
    public void localDateParseOfACleanStringStaysClean() {
        assertEquals(0, date("v1").flows.size());
    }

    @Test
    public void aMatcherCarriesTheTaintOfTheInputIntoItsGroup() {
        TaintIr.Result r = run(
                "const-string v6, \"x\"",
                "invoke-static {v6}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;", "move-result-object v3",
                "invoke-virtual {v3, v2}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;", "move-result-object v5",
                "invoke-virtual {v5}, Ljava/util/regex/Matcher;->group()Ljava/lang/String;", "move-result-object v4",
                SINK);
        assertEquals(1, r.flows.size());
    }

    @Test
    public void anOkhttpHeadersBuilderKeepsWhatWasAdded() {
        TaintIr.Result r = run(
                "const-string v6, \"h\"",
                "new-instance v3, Lokhttp3/HttpUrl$Builder;",
                "invoke-virtual {v3, v2}, Lokhttp3/HttpUrl$Builder;->host(Ljava/lang/String;)Lokhttp3/HttpUrl$Builder;",
                "invoke-virtual {v3}, Lokhttp3/HttpUrl$Builder;->toString()Ljava/lang/String;", "move-result-object v4",
                SINK);
        assertEquals(1, r.flows.size());
    }
}
