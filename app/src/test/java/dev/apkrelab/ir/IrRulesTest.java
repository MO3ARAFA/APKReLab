package dev.apkrelab.ir;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.List;

import org.junit.Test;

/** 0.75.0: IrRules (intent sniffing, plain SQLite, setPluginState). Every positive has a negative twin. */
public class IrRulesTest {

    private static String cls(String body) {
        return ".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public go(Ljava/lang/String;)V\n    .locals 6\n" + body + "    return-void\n.end method\n";
    }

    private static List<IrRules.Hit> sends(String body) {
        return IrRules.intentSends(SmaliParser.parse(cls(body)));
    }

    private static final String NEW_ACTION_INTENT =
            "    new-instance v0, Landroid/content/Intent;\n"
          + "    invoke-direct {v0}, Landroid/content/Intent;-><init>()V\n"
          + "    const-string v1, \"com.example.Broadcast\"\n"
          + "    invoke-virtual {v0, v1}, Landroid/content/Intent;->setAction(Ljava/lang/String;)Landroid/content/Intent;\n";

    // ---------------- intent sniffing

    @Test public void implicitBroadcastWithoutPermissionIsFound() {          // Vuldroid EmailViewer shape
        List<IrRules.Hit> h = sends(NEW_ACTION_INTENT + "    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n");
        assertEquals(1, h.size());
        assertEquals("LOW", h.get(0).sev);                                    // no extras
        assertTrue(h.get(0).detail.contains("com.example.Broadcast"));
    }

    @Test public void sensitiveExtraMakesItHigh() {
        String b = NEW_ACTION_INTENT + "    const-string v2, \"token\"\n"
                + "    invoke-virtual {v0, v2, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;\n"
                + "    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n";
        assertEquals("HIGH", sends(b).get(0).sev);
    }

    @Test public void setPackageMakesItExplicit() {
        String b = NEW_ACTION_INTENT + "    const-string v2, \"com.example\"\n"
                + "    invoke-virtual {v0, v2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;\n"
                + "    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n";
        assertTrue(sends(b).isEmpty());
    }

    @Test public void setPackageNullDoesNotMakeItExplicit() {
        String b = NEW_ACTION_INTENT + "    const/4 v2, 0x0\n"
                + "    invoke-virtual {v0, v2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;\n"
                + "    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n";
        assertEquals(1, sends(b).size());
    }

    @Test public void explicitConstructorIsQuiet() {
        String b = "    new-instance v0, Landroid/content/Intent;\n    const-class v1, Lt/R;\n"
                + "    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n"
                + "    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n";
        assertTrue(sends(b).isEmpty());
    }

    @Test public void receiverPermissionIsAGuardButANullPermissionIsNot() {
        String guarded = NEW_ACTION_INTENT + "    const-string v2, \"com.example.permission.X\"\n"
                + "    invoke-virtual {p0, v0, v2}, Lt/A;->sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V\n";
        assertTrue(sends(guarded).isEmpty());
        String open = NEW_ACTION_INTENT + "    const/4 v2, 0x0\n"
                + "    invoke-virtual {p0, v0, v2}, Lt/A;->sendBroadcast(Landroid/content/Intent;Ljava/lang/String;)V\n";
        assertEquals(1, sends(open).size());
    }

    @Test public void registerReuseDoesNotConfuseTheIntents() {
        // v0 first holds an explicit Intent that is sent, then is REUSED for an implicit one: two sends, only the second is implicit
        String b = "    new-instance v0, Landroid/content/Intent;\n    const-class v1, Lt/R;\n"
                + "    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n"
                + "    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n"
                + NEW_ACTION_INTENT
                + "    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n";
        assertEquals(1, sends(b).size());
    }

    @Test public void phiOfExplicitAndImplicitIsFoundButPhiWithAParameterIsNot() {
        String phi = "    if-eqz p1, :a\n"
                + "    new-instance v0, Landroid/content/Intent;\n    const-class v1, Lt/R;\n"
                + "    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V\n"
                + "    goto :b\n    :a\n"
                + "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"com.example.X\"\n"
                + "    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V\n"
                + "    :b\n    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n";
        assertEquals(1, sends(phi).size());
        String withParam = ".class public Lt/A;\n.super Landroid/app/Activity;\n\n.method public go(Landroid/content/Intent;)V\n    .locals 3\n"
                + "    invoke-virtual {p0, p1}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n    return-void\n.end method\n";
        assertTrue(IrRules.intentSends(SmaliParser.parse(withParam)).isEmpty());
    }

    @Test public void anIntentHandedToAHelperBeforeSendingIsNotJudged() {
        String b = NEW_ACTION_INTENT + "    invoke-static {v0}, Lt/Util;->configure(Landroid/content/Intent;)V\n"
                + "    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n";
        assertTrue(sends(b).isEmpty());
    }

    @Test public void localBroadcastManagerAndPlatformActionsAreQuiet() {
        String lbm = NEW_ACTION_INTENT + "    invoke-static {p0}, Landroidx/localbroadcastmanager/content/LocalBroadcastManager;->getInstance(Landroid/content/Context;)Landroidx/localbroadcastmanager/content/LocalBroadcastManager;\n"
                + "    move-result-object v3\n"
                + "    invoke-virtual {v3, v0}, Landroidx/localbroadcastmanager/content/LocalBroadcastManager;->sendBroadcast(Landroid/content/Intent;)Z\n";
        assertTrue(sends(lbm).isEmpty());
        String scan = "    new-instance v0, Landroid/content/Intent;\n    const-string v1, \"android.intent.action.MEDIA_SCANNER_SCAN_FILE\"\n"
                + "    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V\n"
                + "    invoke-virtual {p0, v0}, Lt/A;->sendBroadcast(Landroid/content/Intent;)V\n";
        assertTrue(sends(scan).isEmpty());
    }

    @Test public void implicitStartServiceIsReportedUnderItsOwnRule() {
        List<IrRules.Hit> h = sends(NEW_ACTION_INTENT + "    invoke-virtual {p0, v0}, Lt/A;->startService(Landroid/content/Intent;)Landroid/content/ComponentName;\n");
        assertEquals(1, h.size());
        assertEquals("implicit-service-intent", h.get(0).rule);
    }

    // ---------------- plain SQLite

    private static String dbClass(String body) {
        return ".class public Lt/Db;\n.super Landroid/database/sqlite/SQLiteOpenHelper;\n\n.method public save(Landroid/database/sqlite/SQLiteDatabase;Ljava/lang/String;)V\n    .locals 6\n"
                + body + "    return-void\n.end method\n";
    }

    private static List<IrRules.Hit> sql(String body) {
        String t = dbClass(body);
        return IrRules.sqliteSensitive(SmaliParser.parse(t), t);
    }

    private static final String CV_NEW = "    new-instance v0, Landroid/content/ContentValues;\n    invoke-direct {v0}, Landroid/content/ContentValues;-><init>()V\n";
    private static final String INSERT = "    const-string v3, \"users\"\n    const/4 v4, 0x0\n"
            + "    invoke-virtual {p1, v3, v4, v0}, Landroid/database/sqlite/SQLiteDatabase;->insert(Ljava/lang/String;Ljava/lang/String;Landroid/content/ContentValues;)J\n";

    @Test public void passwordColumnIsMedium() {
        List<IrRules.Hit> h = sql(CV_NEW + "    const-string v1, \"password\"\n"
                + "    invoke-virtual {v0, v1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V\n" + INSERT);
        assertEquals(1, h.size());
        assertEquals("MEDIUM", h.get(0).sev);
    }

    @Test public void hashedPasswordIsQuietAndGivesTheInfoInstead() {
        List<IrRules.Hit> h = sql(CV_NEW + "    const-string v1, \"password\"\n"
                + "    invoke-static {p2}, Lt/Crypto;->sha256Hash(Ljava/lang/String;)Ljava/lang/String;\n    move-result-object v2\n"
                + "    invoke-virtual {v0, v1, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V\n" + INSERT);
        assertEquals(1, h.size());
        assertEquals("INFO", h.get(0).sev);
    }

    @Test public void piiSourceThroughStringBuilderIsFoundWithANeutralColumn() {
        List<IrRules.Hit> h = sql(CV_NEW + "    const-string v1, \"note\"\n"
                + "    invoke-virtual {p0}, Lt/Db;->tm()Landroid/telephony/TelephonyManager;\n    move-result-object v5\n"
                + "    invoke-virtual {v5}, Landroid/telephony/TelephonyManager;->getDeviceId()Ljava/lang/String;\n    move-result-object v2\n"
                + "    new-instance v3, Ljava/lang/StringBuilder;\n    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V\n"
                + "    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;\n    move-result-object v3\n"
                + "    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;\n    move-result-object v2\n"
                + "    invoke-virtual {v0, v1, v2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V\n" + INSERT);
        assertEquals(1, h.size());
        assertTrue(h.get(0).detail.contains("getDeviceId"));
    }

    @Test public void createTableWithAPasswordColumnIsHighConfidence() {
        List<IrRules.Hit> h = sql("    const-string v0, \"CREATE TABLE users (id INTEGER, username TEXT, password TEXT)\"\n"
                + "    invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V\n");
        assertEquals(1, h.size());
        assertEquals("HIGH", h.get(0).conf);
    }

    @Test public void neutralColumnsGiveOneInfoAndSqlcipherGivesNothing() {
        List<IrRules.Hit> h = sql(CV_NEW + "    const-string v1, \"title\"\n"
                + "    invoke-virtual {v0, v1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V\n" + INSERT);
        assertEquals(1, h.size());
        assertEquals("INFO", h.get(0).sev);
        String t = dbClass("    invoke-static {}, Lnet/sqlcipher/database/SQLiteDatabase;->loadLibs()V\n" + CV_NEW + "    const-string v1, \"password\"\n"
                + "    invoke-virtual {v0, v1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V\n" + INSERT);
        assertTrue(IrRules.sqliteSensitive(SmaliParser.parse(t), t).isEmpty());
    }

    @Test public void columnConstantFromAnotherClassIsReadByFieldName() {
        List<IrRules.Hit> h = sql(CV_NEW + "    sget-object v1, Lt/Contract;->COLUMN_PASSWORD:Ljava/lang/String;\n"
                + "    invoke-virtual {v0, v1, p2}, Landroid/content/ContentValues;->put(Ljava/lang/String;Ljava/lang/String;)V\n" + INSERT);
        assertEquals("MEDIUM", h.get(0).sev);
    }

    // ---------------- setPluginState

    private static List<IrRules.Hit> plugin(String body) {
        return IrRules.pluginState(SmaliParser.parse(cls(body)));
    }

    private static final String SETTINGS = "    invoke-virtual {p0}, Lt/A;->ws()Landroid/webkit/WebSettings;\n    move-result-object v0\n";

    @Test public void pluginStateOnIsFound() {
        List<IrRules.Hit> h = plugin(SETTINGS + "    sget-object v1, Landroid/webkit/WebSettings$PluginState;->ON:Landroid/webkit/WebSettings$PluginState;\n"
                + "    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setPluginState(Landroid/webkit/WebSettings$PluginState;)V\n");
        assertEquals(1, h.size());
        assertEquals("LOW", h.get(0).sev);
    }

    @Test public void pluginStateOffIsQuietEvenWhenTheRegisterHeldOnBefore() {
        String b = SETTINGS + "    sget-object v1, Landroid/webkit/WebSettings$PluginState;->ON:Landroid/webkit/WebSettings$PluginState;\n"
                + "    invoke-static {v1}, Lt/Log;->d(Ljava/lang/Object;)V\n"
                + "    sget-object v1, Landroid/webkit/WebSettings$PluginState;->OFF:Landroid/webkit/WebSettings$PluginState;\n"
                + "    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setPluginState(Landroid/webkit/WebSettings$PluginState;)V\n";
        assertTrue(plugin(b).isEmpty());
    }

    @Test public void pluginStateOnOnOneBranchIsFoundAndValueOfIsTraced() {
        String b = SETTINGS + "    if-eqz p1, :a\n"
                + "    sget-object v1, Landroid/webkit/WebSettings$PluginState;->OFF:Landroid/webkit/WebSettings$PluginState;\n    goto :b\n    :a\n"
                + "    const-string v2, \"ON\"\n"
                + "    invoke-static {v2}, Landroid/webkit/WebSettings$PluginState;->valueOf(Ljava/lang/String;)Landroid/webkit/WebSettings$PluginState;\n    move-result-object v1\n"
                + "    :b\n    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setPluginState(Landroid/webkit/WebSettings$PluginState;)V\n";
        List<IrRules.Hit> h = plugin(b);
        assertEquals(1, h.size());
        assertTrue(h.get(0).detail.contains("on at least one path"));
    }

    @Test public void pluginsEnabledTrueIsFoundFalseIsNot() {
        assertEquals(1, plugin(SETTINGS + "    const/4 v1, 0x1\n    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setPluginsEnabled(Z)V\n").size());
        assertTrue(plugin(SETTINGS + "    const/4 v1, 0x0\n    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setPluginsEnabled(Z)V\n").isEmpty());
    }

    // ---------------- weak random (0.75.1)

    private static List<IrRules.Hit> rnd(String cls, String header, String body, String extra) {
        String t = ".class public " + cls + "\n.super Ljava/lang/Object;\n\n.method public static " + header + "\n    .locals 5\n" + body + ".end method\n" + extra;
        return IrRules.weakRandom(SmaliParser.parse(t), t);
    }

    private static final String NEW_RANDOM = "    new-instance v1, Ljava/util/Random;\n    invoke-direct {v1}, Ljava/util/Random;-><init>()V\n";

    @Test public void randomReturnedFromACryptoClassIsFound() {           // PIVAA Encryption.rng() shape
        String body = NEW_RANDOM + "    const v2, 0x186a0\n    invoke-virtual {v1, v2}, Ljava/util/Random;->nextInt(I)I\n    move-result v2\n"
                + "    add-int/lit8 v0, v2, 0x1\n    invoke-static {v0}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;\n    move-result-object v2\n    return-object v2\n";
        String crypto = "\n.method public static x()V\n    .locals 1\n    const-string v0, \"AES\"\n    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n    return-void\n.end method\n";
        assertEquals(1, rnd("Lt/Encryption;", "rng()Ljava/lang/String;", body, crypto).size());
        // the same method in a class with no crypto and no security name: a game die, quiet
        assertTrue(rnd("Lt/Dice;", "roll()Ljava/lang/String;", body, "").isEmpty());
    }

    @Test public void randomBytesIntoAnIvSpecIsFoundAndSecureRandomIsNot() {
        String body = NEW_RANDOM + "    const/16 v2, 0x10\n    new-array v3, v2, [B\n"
                + "    invoke-virtual {v1, v3}, Ljava/util/Random;->nextBytes([B)V\n"
                + "    new-instance v4, Ljavax/crypto/spec/IvParameterSpec;\n    invoke-direct {v4, v3}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V\n    return-void\n";
        assertEquals(1, rnd("Lt/U;", "iv()V", body, "").size());
        String secure = body.replace("new-instance v1, Ljava/util/Random;\n    invoke-direct {v1}, Ljava/util/Random;-><init>()V",
                "new-instance v1, Ljava/security/SecureRandom;\n    invoke-direct {v1}, Ljava/security/SecureRandom;-><init>()V\n    check-cast v1, Ljava/util/Random;");
        assertTrue(rnd("Lt/U;", "iv()V", secure, "").isEmpty());
    }

    @Test public void constantSeedIsHighAndAFieldOfUnknownTypeIsQuiet() {
        String seeded = "    new-instance v1, Ljava/util/Random;\n    const-wide/16 v2, 0x2a\n    invoke-direct {v1, v2, v3}, Ljava/util/Random;-><init>(J)V\n"
                + "    invoke-virtual {v1}, Ljava/util/Random;->nextInt()I\n    move-result v0\n"
                + "    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;\n    move-result-object v4\n"
                + "    sput-object v4, Lt/U;->sessionToken:Ljava/lang/String;\n    return-void\n";
        List<IrRules.Hit> h = rnd("Lt/U;", "make()V", seeded, "");
        assertEquals(1, h.size());
        assertEquals("HIGH", h.get(0).sev);
        String field = "    sget-object v1, Lt/U;->rng:Ljava/util/Random;\n"
                + "    invoke-virtual {v1}, Ljava/util/Random;->nextInt()I\n    move-result v0\n"
                + "    invoke-static {v0}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;\n    move-result-object v4\n"
                + "    sput-object v4, Lt/U;->sessionToken:Ljava/lang/String;\n    return-void\n";
        assertTrue(rnd("Lt/U;", "make()V", field, "").isEmpty());
    }

    @Test public void randomForANonSecurityFieldIsQuiet() {
        String body = NEW_RANDOM + "    invoke-virtual {v1}, Ljava/util/Random;->nextInt()I\n    move-result v0\n"
                + "    sput v0, Lt/U;->animationDelay:I\n    return-void\n";
        assertTrue(rnd("Lt/U;", "anim()V", body, "").isEmpty());
    }

    // ---------------- 0.75.2 precision fixes

    @Test public void passwordWordInsideInsertValuesIsNotAColumn() {     // Allsafe NoteDatabaseHelper
        List<IrRules.Hit> h = sql("    const-string v0, \"insert into note ( user, note ) values ('admin', 'Jill is still using 123456 as her password')\"\n"
                + "    invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V\n");
        assertEquals(1, h.size());
        assertEquals("INFO", h.get(0).sev);
        List<IrRules.Hit> real = sql("    const-string v0, \"INSERT INTO users (name, password) VALUES ('a', 'b')\"\n"
                + "    invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V\n");
        assertEquals("MEDIUM", real.get(0).sev);
    }

    @Test public void aSensitiveTableNameIsCalledATable() {               // Sieve "CREATE TABLE Passwords (...)"
        List<IrRules.Hit> h = sql("    const-string v0, \"CREATE TABLE Passwords (_id INTEGER, service TEXT, username TEXT)\"\n"
                + "    invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->execSQL(Ljava/lang/String;)V\n");
        assertTrue(h.get(0).detail.contains("the table \"Passwords\""));
        assertEquals("MEDIUM", h.get(0).conf);
    }

    // ---------------- 0.80.0: R8-merged Object fields in short renamed packages
    @Test public void mergedObjectFieldInAShortRenamedPackageIsWeak() {
        assertTrue(TaintIr.mergedObjectField("LG2/m;->r:Ljava/lang/Object;"));
        assertTrue(TaintIr.mergedObjectField("Laq3;->a:Ljava/lang/Object;"));
        assertTrue(!TaintIr.mergedObjectField("Lcom/example/Holder;->value:Ljava/lang/Object;"));
        assertTrue(!TaintIr.mergedObjectField("LG2/m;->r:Ljava/lang/String;"));
    }
}
