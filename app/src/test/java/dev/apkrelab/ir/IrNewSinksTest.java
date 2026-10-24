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
 * 0.72.0: two sink families the catalog did not have. (1) SQLiteQueryBuilder.query / buildQuery / update / delete: the normal body of
 * ContentProvider.query (InsecureBankv2 TrackUserContentProvider.query was missed because only appendWhere / setTables were sinks).
 * (2) ContentResolver.openInputStream / openOutputStream / openFileDescriptor / openAssetFileDescriptor: a file:// or content:// URI chosen by
 * the caller makes the app open its own private files (InsecureShop ChooserActivity.makeTempCopy).
 */
public class IrNewSinksTest {

    private static final String QB = "Landroid/database/sqlite/SQLiteQueryBuilder;";
    private static final String QUERY_SIG = "query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;";

    private static TaintIr.Flow flow(String entry, String... smali) {
        List<ClassIr> cs = new ArrayList<>();
        for (String s : smali) cs.add(SmaliParser.parse(s));
        CallGraph g = CallGraph.build(cs, Arrays.asList(entry), CallGraph.Mode.RTA, null);
        TaintIr.Result r = TaintIr.analyze(g, false, null);
        return r.flows.isEmpty() ? null : r.flows.get(0);
    }

    /** Provider whose query() calls qb.query(db, projection, selection, selectionArgs, groupBy, having, sortOrder) with the given registers. */
    private static String provider(String projection, String selection, String args, String sortOrder) {
        // .locals 8: v8 = this, v9 = uri, v10 = projection, v11 = selection, v12 = selectionArgs, v13 = sortOrder
        return ".class public Lt/P;\n.super Landroid/content/ContentProvider;\n\n.method public " + QUERY_SIG + "\n    .locals 8\n"
                + "    new-instance v0, " + QB + "\n"
                + "    const/4 v1, 0x0\n"
                + "    move-object v2, " + projection + "\n"
                + "    move-object v3, " + selection + "\n"
                + "    move-object v4, " + args + "\n"
                + "    const/4 v5, 0x0\n    const/4 v6, 0x0\n"
                + "    move-object v7, " + sortOrder + "\n"
                + "    invoke-virtual/range {v0 .. v7}, " + QB + "->query(Landroid/database/sqlite/SQLiteDatabase;[Ljava/lang/String;Ljava/lang/String;"
                + "[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;\n"
                + "    move-result-object v1\n    return-object v1\n.end method\n";
    }

    @Test
    public void providerSelectionReachingQueryBuilderQueryIsSql() {
        TaintIr.Flow f = flow("Lt/P;", provider("v1", "v11", "v12", "v1"));
        assertNotNull(f);
        assertEquals(TaintIr.T_SQL, f.sink.title);
    }

    @Test
    public void providerSortOrderReachingQueryBuilderQueryIsSql() {
        TaintIr.Flow f = flow("Lt/P;", provider("v1", "v1", "v12", "v13"));
        assertNotNull(f);
        assertEquals(TaintIr.T_SQL, f.sink.title);
    }

    @Test
    public void onlySelectionArgsAreBoundSoTheyAreNotASink() {
        // selectionArgs (p4 = v12) is the one parameter that is bound safely
        assertNull(flow("Lt/P;", provider("v1", "v1", "v12", "v1")));
    }

    @Test
    public void fixedSelectionIsNotASink() {
        assertNull(flow("Lt/P;", provider("v1", "v1", "v1", "v1")));
    }

    private static String activity(String body) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public onCreate(Landroid/os/Bundle;)V\n    .locals 6\n" + body
                + "    return-void\n.end method\n";
    }

    private static final String GET_URI =
            "    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
                    + "    const-string v1, \"uri\"\n"
                    + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;\n    move-result-object v2\n"
                    + "    check-cast v2, Landroid/net/Uri;\n"
                    + "    invoke-virtual {p0}, Lt/A;->getContentResolver()Landroid/content/ContentResolver;\n    move-result-object v3\n";

    @Test
    public void uriFromTheIntentOpenedByContentResolverIsReported() {
        TaintIr.Flow f = flow("Lt/A;", activity(GET_URI
                + "    invoke-virtual {v3, v2}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;\n"));
        assertNotNull(f);
        assertEquals(TaintIr.T_URI, f.sink.title);
        assertTrue(f.source.contains("getParcelableExtra"));
    }

    @Test
    public void openFileDescriptorWithACallerUriIsReported() {
        TaintIr.Flow f = flow("Lt/A;", activity(GET_URI + "    const-string v4, \"r\"\n"
                + "    invoke-virtual {v3, v2, v4}, Landroid/content/ContentResolver;->openFileDescriptor(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;\n"));
        assertNotNull(f);
        assertEquals(TaintIr.T_URI, f.sink.title);
    }

    @Test
    public void aFixedUriIsNotReported() {
        assertNull(flow("Lt/A;", activity("    const-string v1, \"content://media/external/images/media\"\n"
                + "    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;\n    move-result-object v2\n"
                + "    invoke-virtual {p0}, Lt/A;->getContentResolver()Landroid/content/ContentResolver;\n    move-result-object v3\n"
                + "    invoke-virtual {v3, v2}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;\n")));
    }

    @Test
    public void theUriParameterOfOtherArgumentsOfOpenIsNotTheSink() {
        // openFileDescriptor(uri, mode): the mode string is not the URI, a tainted mode alone is not this finding
        assertNull(flow("Lt/A;", activity("    invoke-virtual {p0}, Lt/A;->getIntent()Landroid/content/Intent;\n    move-result-object v0\n"
                + "    const-string v1, \"m\"\n"
                + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v4\n"
                + "    const-string v1, \"content://x/y\"\n"
                + "    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;\n    move-result-object v2\n"
                + "    invoke-virtual {p0}, Lt/A;->getContentResolver()Landroid/content/ContentResolver;\n    move-result-object v3\n"
                + "    invoke-virtual {v3, v2, v4}, Landroid/content/ContentResolver;->openFileDescriptor(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;\n")));
    }
}
