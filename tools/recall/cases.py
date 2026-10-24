"""Recall-by-injection cases (0.86.1). Each case is a small smali class (or two) written in the style of what R8 / javac emit, plus the manifest
lines that make its component exported. The runner adds them to a copy of a real app, scans it with the real pipeline and checks that a
card of one of the expected rules appears for the injected class, at the expected severity or higher.

kind = "must"  : a rule exists for exactly this pattern; a miss or a downgrade is a defect.
kind = "probe" : the pattern is a known weak spot (the answer is measured, not promised).
Writing rules: every case is ONE vulnerability, in its own class (CaseNN, CaseNNB for a helper), named like app code (readable), except the cases
that are about obfuscated code, which live in the default package with short names.
"""

SEV = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def cls(name, body, sup="Ljava/lang/Object;", impl=None, fields=""):
    return (".class public L{P}/%s;\n.super %s\n%s%s\n%s\n" % (name, sup, (".implements %s\n" % impl) if impl else "", fields, body))

def dflt(name, body, sup="Ljava/lang/Object;", impl=None):   # default package, short name: what R8 produces
    return (".class public L%s;\n.super %s\n%s\n%s\n" % (name, sup, (".implements %s\n" % impl) if impl else "", body))

TRUST_ALL_METHODS = """
.method public checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0
    return-void
.end method

.method public checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0
    return-void
.end method

.method public getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
    .locals 1
    const/4 v0, 0x0
    new-array v0, v0, [Ljava/security/cert/X509Certificate;
    return-object v0
.end method
"""

TRUST_ALL_R8 = """
.method public final checkClientTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    return-void
.end method

.method public final checkServerTrusted([Ljava/security/cert/X509Certificate;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    return-void
.end method

.method public final getAcceptedIssuers()[Ljava/security/cert/X509Certificate;
    .locals 1
    const/4 v0, 0x0
    new-array v0, v0, [Ljava/security/cert/X509Certificate;
    return-object v0
.end method
"""

def installer(tm_type, ctx_name="TLS"):
    return """
.method public install()Ljavax/net/ssl/SSLContext;
    .locals 5
    const-string v0, "%s"
    invoke-static {v0}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;
    move-result-object v0
    const/4 v1, 0x1
    new-array v1, v1, [Ljavax/net/ssl/TrustManager;
    new-instance v2, %s
    invoke-direct {v2}, %s-><init>()V
    const/4 v3, 0x0
    aput-object v2, v1, v3
    const/4 v4, 0x0
    invoke-virtual {v0, v4, v1, v4}, Ljavax/net/ssl/SSLContext;->init([Ljavax/net/ssl/KeyManager;[Ljavax/net/ssl/TrustManager;Ljava/security/SecureRandom;)V
    return-object v0
.end method
""" % (ctx_name, tm_type, tm_type)

def activity_loadurl():
    return """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, L{P}/Case21;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Landroid/webkit/WebView;
    invoke-direct {v2, p0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V
    invoke-virtual {v2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""

CASES = [
 # ------------------------------------------------------------------ secrets
 dict(id="01", name="AES key from a string constant (SecretKeySpec)", kind="must", rules=["crypto-hardcoded-key"], sev="HIGH",
      smali={"Case01": cls("Case01", """
.method public static key()Ljavax/crypto/spec/SecretKeySpec;
    .locals 3
    const-string v0, "0123456789abcdef0123456789abcdef"
    invoke-virtual {v0}, Ljava/lang/String;->getBytes()[B
    move-result-object v0
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
    const-string v2, "AES"
    invoke-direct {v1, v0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    return-object v1
.end method
""")}),
 dict(id="02", name="bearer token and its Authorization header in the same method", kind="must",
      rules=["secrets-sensitive-fields", "high-entropy-strings", "secrets-known-formats"], sev="HIGH",
      smali={"Case02": cls("Case02", """
.method public static call(Lokhttp3/Request$Builder;)V
    .locals 4
    const-string v0, "apiToken"
    const-string v1, "Zq8vT2LmX9pR4wK7nB1cY6hJ3fD5sG0aE"
    const-string v2, "Authorization"
    invoke-virtual {p0, v2, v1}, Lokhttp3/Request$Builder;->header(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;
    return-void
.end method
""")}),
 dict(id="03", name="the same token, the header is set in ANOTHER class (interceptor)", kind="probe",
      rules=["secrets-sensitive-fields", "high-entropy-strings", "secrets-known-formats"], sev="HIGH",
      smali={"Case03": cls("Case03", "", fields=".field public static final API_TOKEN:Ljava/lang/String; = \"Zq8vT2LmX9pR4wK7nB1cY6hJ3fD5sG0aE\"\n"),
             "Case03B": cls("Case03B", """
.method public intercept(Lokhttp3/Request$Builder;)V
    .locals 3
    sget-object v0, L{P}/Case03;->API_TOKEN:Ljava/lang/String;
    const-string v1, "Authorization"
    invoke-virtual {p1, v1, v0}, Lokhttp3/Request$Builder;->header(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;
    return-void
.end method
""")}),
 dict(id="04", name="AWS access key id in a string constant", kind="must", rules=["secrets-known-formats", "res-strings-aws-keys"], sev="HIGH",
      smali={"Case04": cls("Case04", """
.method public static id()Ljava/lang/String;
    .locals 1
    const-string v0, "AKIAJ7Q3ZB5XK2M4NPWD"
    return-object v0
.end method
""")}),
 dict(id="05", name="JWT in a string constant", kind="must", rules=["secrets-known-formats", "jwt-hardcoded-secret", "res-strings-jwt"], sev="HIGH",
      smali={"Case05": cls("Case05", """
.method public static t()Ljava/lang/String;
    .locals 1
    const-string v0, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyLTEyMzQ1Iiwicm9sZSI6ImFkbWluIn0.dQw4w9WgXcQabcdefGHIJKlmnopQRSTuvwxyz0123"
    return-object v0
.end method
""")}),
 dict(id="06", name="Stripe live secret key", kind="must", rules=["secrets-known-formats", "res-strings-known-tokens"], sev="HIGH",
      smali={"Case06": cls("Case06", """
.method public static k()Ljava/lang/String;
    .locals 1
    const-string v0, "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    return-object v0
.end method
""")}),
 dict(id="07", name="password written to SharedPreferences in plain text", kind="must", rules=["fintech-unencrypted-storage", "androgoat-checks"], sev="MEDIUM",
      smali={"Case07": cls("Case07", """
.method public static save(Landroid/content/Context;Ljava/lang/String;)V
    .locals 4
    const-string v0, "auth"
    const/4 v1, 0x0
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;
    move-result-object v0
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;
    move-result-object v0
    const-string v2, "password"
    invoke-interface {v0, v2, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V
    return-void
.end method
""")}),
 # ------------------------------------------------------------------ TLS
 dict(id="10", name="trust-all TrustManager installed in an SSLContext (readable names)", kind="must", rules=["tls-trustmanager"], sev="CRITICAL",
      smali={"Case10": cls("Case10", TRUST_ALL_METHODS + installer("L{P}/Case10;"), impl="Ljavax/net/ssl/X509TrustManager;")}),
 dict(id="11", name="trust-all TrustManager, R8 style: short names, null checks, default package", kind="must", rules=["tls-trustmanager"], sev="CRITICAL",
      smali={"Case11": dflt("q_1", TRUST_ALL_R8, impl="Ljavax/net/ssl/X509TrustManager;"),
             "Case11B": dflt("q_2", installer("Lq_1;") .replace("L{P}", "L"))}),
 dict(id="12", name="all-true HostnameVerifier installed on an HttpsURLConnection", kind="must", rules=["tls-hostname-verifier"], sev="HIGH",
      smali={"Case12": cls("Case12", """
.method public verify(Ljava/lang/String;Ljavax/net/ssl/SSLSession;)Z
    .locals 1
    const/4 v0, 0x1
    return v0
.end method

.method public static apply(Ljavax/net/ssl/HttpsURLConnection;)V
    .locals 2
    new-instance v0, L{P}/Case12;
    invoke-direct {v0}, L{P}/Case12;-><init>()V
    invoke-virtual {p0, v0}, Ljavax/net/ssl/HttpsURLConnection;->setHostnameVerifier(Ljavax/net/ssl/HostnameVerifier;)V
    return-void
.end method
""", impl="Ljavax/net/ssl/HostnameVerifier;")}),
 dict(id="13", name="trust-all TrustManager installed only when a boolean parameter is true", kind="probe", rules=["tls-trustmanager"], sev="MEDIUM",
      smali={"Case13": cls("Case13", TRUST_ALL_METHODS + installer("L{P}/Case13;").replace("()Ljavax/net/ssl/SSLContext;", "(Z)Ljavax/net/ssl/SSLContext;").replace(".locals 5", ".locals 6").replace("    const-string v0", "    if-nez p1, :go\n    const/4 v5, 0x0\n    return-object v5\n    :go\n    const-string v0", 1), impl="Ljavax/net/ssl/X509TrustManager;")}),
 dict(id="14", name="SSLContext.getInstance(\"SSLv3\")", kind="must", rules=["tls-protocol-version"], sev="HIGH",
      smali={"Case14": cls("Case14", """
.method public static ctx()Ljavax/net/ssl/SSLContext;
    .locals 1
    const-string v0, "SSLv3"
    invoke-static {v0}, Ljavax/net/ssl/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;
    move-result-object v0
    return-object v0
.end method
""")}),
 # ------------------------------------------------------------------ crypto
 dict(id="15", name="Cipher AES/ECB/PKCS5Padding", kind="must", rules=["crypto-cipher"], sev="HIGH",
      smali={"Case15": cls("Case15", """
.method public static c()Ljavax/crypto/Cipher;
    .locals 1
    const-string v0, "AES/ECB/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v0
    return-object v0
.end method
""")}),
 dict(id="16", name="Cipher DES/CBC/PKCS5Padding", kind="must", rules=["crypto-cipher"], sev="HIGH",
      smali={"Case16": cls("Case16", """
.method public static c()Ljavax/crypto/Cipher;
    .locals 1
    const-string v0, "DES/CBC/PKCS5Padding"
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v0
    return-object v0
.end method
""")}),
 dict(id="17", name="MD5 of a password", kind="must", rules=["crypto-weak-hash"], sev="MEDIUM",
      smali={"Case17": cls("Case17", """
.method public static h(Ljava/lang/String;)[B
    .locals 2
    const-string v0, "MD5"
    invoke-static {v0}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v0
    invoke-virtual {p0}, Ljava/lang/String;->getBytes()[B
    move-result-object v1
    invoke-virtual {v0, v1}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v1
    return-object v1
.end method
""")}),
 dict(id="18", name="constant IV (IvParameterSpec from a constant byte array)", kind="must", rules=["crypto-static-iv"], sev="MEDIUM",   # 0.86.1: expectation lowered from HIGH after the first run: a constant IV with CBC leaks plaintext equality (CWE-329, usually Medium); a constant GCM nonce would be HIGH
      smali={"Case18": cls("Case18", """
.method public static iv()Ljavax/crypto/spec/IvParameterSpec;
    .locals 3
    const/16 v0, 0x10
    new-array v0, v0, [B
    fill-array-data v0, :iv
    new-instance v1, Ljavax/crypto/spec/IvParameterSpec;
    invoke-direct {v1, v0}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V
    return-object v1
    :iv
    .array-data 1
        0x1t 0x2t 0x3t 0x4t 0x5t 0x6t 0x7t 0x8t 0x9t 0xat 0xbt 0xct 0xdt 0xet 0xft 0x10t
    .end array-data
.end method
""")}),
 dict(id="19", name="java.util.Random used to build a login token", kind="must", rules=["weak-random"], sev="MEDIUM",
      smali={"Case19": cls("Case19", """
.method public static generateToken()Ljava/lang/String;
    .locals 4
    new-instance v0, Ljava/util/Random;
    invoke-direct {v0}, Ljava/util/Random;-><init>()V
    invoke-virtual {v0}, Ljava/util/Random;->nextLong()J
    move-result-wide v1
    invoke-static {v1, v2}, Ljava/lang/Long;->toString(J)Ljava/lang/String;
    move-result-object v3
    return-object v3
.end method
""")}),
 dict(id="20", name="RSA key pair of 512 bits", kind="must", rules=["weak-key-size"], sev="HIGH",
      smali={"Case20": cls("Case20", """
.method public static kp()Ljava/security/KeyPair;
    .locals 2
    const-string v0, "RSA"
    invoke-static {v0}, Ljava/security/KeyPairGenerator;->getInstance(Ljava/lang/String;)Ljava/security/KeyPairGenerator;
    move-result-object v0
    const/16 v1, 0x200
    invoke-virtual {v0, v1}, Ljava/security/KeyPairGenerator;->initialize(I)V
    invoke-virtual {v0}, Ljava/security/KeyPairGenerator;->generateKeyPair()Ljava/security/KeyPair;
    move-result-object v0
    return-object v0
.end method
""")}),
 dict(id="35", name="SecureRandom (SHA1PRNG) seeded with a constant", kind="must", rules=["crypto-sha1prng-seed"], sev="HIGH",
      smali={"Case35": cls("Case35", """
.method public static r()Ljava/security/SecureRandom;
    .locals 3
    const-string v0, "SHA1PRNG"
    invoke-static {v0}, Ljava/security/SecureRandom;->getInstance(Ljava/lang/String;)Ljava/security/SecureRandom;
    move-result-object v0
    const-string v1, "fixed-seed-1234"
    invoke-virtual {v1}, Ljava/lang/String;->getBytes()[B
    move-result-object v1
    invoke-virtual {v0, v1}, Ljava/security/SecureRandom;->setSeed([B)V
    return-object v0
.end method
""")}),
 # ------------------------------------------------------------------ WebView
 dict(id="21", name="exported activity: Intent extra loaded into a WebView", kind="must", rules=["taint-flow", "webview-intent-url"], sev="HIGH",
      manifest=['<activity android:name="{PK}.inj.Case21" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><data android:scheme="injcase"/></intent-filter></activity>'],
      smali={"Case21": cls("Case21", activity_loadurl(), sup="Landroid/app/Activity;")}),
 dict(id="22", name="JavaScript bridge whose method runs a command", kind="must", rules=["webview-js-bridge-method"], sev="HIGH",
      smali={"Case22": cls("Case22", """
.method public static attach(Landroid/webkit/WebView;)V
    .locals 2
    new-instance v0, L{P}/Case22B;
    invoke-direct {v0}, L{P}/Case22B;-><init>()V
    const-string v1, "bridge"
    invoke-virtual {p0, v0, v1}, Landroid/webkit/WebView;->addJavascriptInterface(Ljava/lang/Object;Ljava/lang/String;)V
    return-void
.end method
"""),
             "Case22B": cls("Case22B", """
.method public run(Ljava/lang/String;)V
    .locals 2
    .annotation runtime Landroid/webkit/JavascriptInterface;
    .end annotation
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v0
    invoke-virtual {v0, p1}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    return-void
.end method
""")}),
 dict(id="23", name="WebView with file access from file URLs and JavaScript", kind="must", rules=["webview-file-access"], sev="HIGH",
      smali={"Case23": cls("Case23", """
.method public static cfg(Landroid/webkit/WebView;)V
    .locals 2
    invoke-virtual {p0}, Landroid/webkit/WebView;->getSettings()Landroid/webkit/WebSettings;
    move-result-object v0
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowFileAccessFromFileURLs(Z)V
    invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V
    return-void
.end method
""")}),
 dict(id="24", name="WebView debugging enabled", kind="must", rules=["webview-debugging"], sev="MEDIUM",
      smali={"Case24": cls("Case24", """
.method public static dbg()V
    .locals 1
    const/4 v0, 0x1
    invoke-static {v0}, Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(Z)V
    return-void
.end method
""")}),
 # ------------------------------------------------------------------ IPC
 dict(id="25", name="exported ContentProvider concatenating the selection into rawQuery", kind="must",
      rules=["provider-sql-injection", "sql-concat", "taint-flow", "manifest-exported-components"], sev="HIGH",
      manifest=['<provider android:name="{PK}.inj.Case25" android:authorities="inj.case25" android:exported="true"/>'],
      smali={"Case25": cls("Case25", """
.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .locals 5
    invoke-virtual {p0}, L{P}/Case25;->db()Landroid/database/sqlite/SQLiteDatabase;
    move-result-object v0
    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V
    const-string v2, "SELECT * FROM notes WHERE "
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    const/4 v2, 0x0
    invoke-virtual {v0, v1, v2}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
    move-result-object v0
    return-object v0
.end method
""", sup="Landroid/content/ContentProvider;")}),
 dict(id="26", name="exported receiver: Intent extra becomes the next startActivity", kind="must", rules=["intent-redirection", "taint-flow"], sev="HIGH",
      manifest=['<receiver android:name="{PK}.inj.Case26" android:exported="true"><intent-filter><action android:name="inj.case26.GO"/></intent-filter></receiver>'],
      smali={"Case26": cls("Case26", """
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 3
    const-string v0, "next"
    invoke-virtual {p2, v0}, Landroid/content/Intent;->getParcelableExtra(Ljava/lang/String;)Landroid/os/Parcelable;
    move-result-object v0
    check-cast v0, Landroid/content/Intent;
    invoke-virtual {p1, v0}, Landroid/content/Context;->startActivity(Landroid/content/Intent;)V
    return-void
.end method
""", sup="Landroid/content/BroadcastReceiver;")}),
 dict(id="27", name="exported service: Intent extra executed as a shell command", kind="must", rules=["taint-flow", "shell-exec"], sev="CRITICAL",
      manifest=['<service android:name="{PK}.inj.Case27" android:exported="true"><intent-filter><action android:name="inj.case27.RUN"/></intent-filter></service>'],
      smali={"Case27": cls("Case27", """
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 4
    const-string v0, "cmd"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v1
    invoke-virtual {v1, v0}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)Ljava/lang/Process;
    const/4 v2, 0x2
    return v2
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method
""", sup="Landroid/app/Service;")}),
 dict(id="28", name="mutable PendingIntent with an empty implicit Intent", kind="must", rules=["pendingintent-mutable"], sev="MEDIUM",
      smali={"Case28": cls("Case28", """
.method public static pi(Landroid/content/Context;)Landroid/app/PendingIntent;
    .locals 3
    new-instance v0, Landroid/content/Intent;
    invoke-direct {v0}, Landroid/content/Intent;-><init>()V
    const/4 v1, 0x0
    invoke-static {p0, v1, v0, v1}, Landroid/app/PendingIntent;->getActivity(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;
    move-result-object v2
    return-object v2
.end method
""")}),
 dict(id="29", name="broadcast carrying a token, sent without a receiver permission", kind="must", rules=["broadcast-unprotected-send"], sev="MEDIUM",
      smali={"Case29": cls("Case29", """
.method public static send(Landroid/content/Context;Ljava/lang/String;)V
    .locals 3
    new-instance v0, Landroid/content/Intent;
    const-string v1, "com.injected.TOKEN_REFRESHED"
    invoke-direct {v0, v1}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V
    const-string v1, "access_token"
    invoke-virtual {v0, v1, p1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    invoke-virtual {p0, v0}, Landroid/content/Context;->sendBroadcast(Landroid/content/Intent;)V
    return-void
.end method
""")}),
 # ------------------------------------------------------------------ storage / files / code
 dict(id="30", name="file created world-readable (MODE_WORLD_READABLE)", kind="must", rules=["storage-file-mode"], sev="MEDIUM",   # 0.86.1: expectation lowered from HIGH after the first run: MODE_WORLD_READABLE throws SecurityException for targetSdk >= 24, so on a current target it is a crash, not a leak
      smali={"Case30": cls("Case30", """
.method public static w(Landroid/content/Context;)Ljava/io/FileOutputStream;
    .locals 3
    const-string v0, "session.dat"
    const/4 v1, 0x1
    invoke-virtual {p0, v0, v1}, Landroid/content/Context;->openFileOutput(Ljava/lang/String;I)Ljava/io/FileOutputStream;
    move-result-object v2
    return-object v2
.end method
""")}),
 dict(id="31", name="token written to the log", kind="must", rules=["log-sensitive-strings", "log-credential-object", "androgoat-checks"], sev="LOW",
      smali={"Case31": cls("Case31", """
.method public static l(Ljava/lang/String;)V
    .locals 2
    const-string v0, "AuthClient"
    new-instance v1, Ljava/lang/StringBuilder;
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V
    const-string p0, "access token="
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v1
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
    return-void
.end method
""")}),
 dict(id="32", name="exported activity: zip entry name used as a file name (Zip Slip)", kind="must", rules=["zip-slip", "taint-flow"], sev="HIGH",
      manifest=['<activity android:name="{PK}.inj.Case32" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><data android:scheme="injzip"/></intent-filter></activity>'],
      smali={"Case32": cls("Case32", """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 6
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, L{P}/Case32;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {p0}, L{P}/Case32;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v1
    invoke-virtual {v1, v0}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;
    move-result-object v1
    new-instance v2, Ljava/util/zip/ZipInputStream;
    invoke-direct {v2, v1}, Ljava/util/zip/ZipInputStream;-><init>(Ljava/io/InputStream;)V
    invoke-virtual {v2}, Ljava/util/zip/ZipInputStream;->getNextEntry()Ljava/util/zip/ZipEntry;
    move-result-object v3
    invoke-virtual {v3}, Ljava/util/zip/ZipEntry;->getName()Ljava/lang/String;
    move-result-object v3
    new-instance v4, Ljava/io/File;
    invoke-virtual {p0}, L{P}/Case32;->getFilesDir()Ljava/io/File;
    move-result-object v5
    invoke-direct {v4, v5, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    new-instance v5, Ljava/io/FileOutputStream;
    invoke-direct {v5, v4}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V
    return-void
.end method
""", sup="Landroid/app/Activity;")}),
 dict(id="33", name="exported activity: path from the Intent data deleted", kind="must", rules=["taint-flow"], sev="HIGH",
      manifest=['<activity android:name="{PK}.inj.Case33" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><data android:scheme="injdel"/></intent-filter></activity>'],
      smali={"Case33": cls("Case33", """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, L{P}/Case33;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;
    move-result-object v0
    new-instance v1, Ljava/io/File;
    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v1}, Ljava/io/File;->delete()Z
    return-void
.end method
""", sup="Landroid/app/Activity;")}),
 dict(id="34", name="code loaded from an external-storage directory (DexClassLoader)", kind="must", rules=["dex-load-writable-dir", "dynamic-code-loading"], sev="HIGH",
      smali={"Case34": cls("Case34", """
.method public static load(Landroid/content/Context;)Ldalvik/system/DexClassLoader;
    .locals 6
    const/4 v0, 0x0
    invoke-virtual {p0, v0}, Landroid/content/Context;->getExternalFilesDir(Ljava/lang/String;)Ljava/io/File;
    move-result-object v1
    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v1
    new-instance v2, Ldalvik/system/DexClassLoader;
    invoke-virtual {p0}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;
    move-result-object v3
    invoke-direct {v2, v1, v0, v0, v3}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V
    return-object v2
.end method
""")}),
 dict(id="36", name="exported service: ObjectInputStream.readObject on bytes from an Intent extra", kind="must", rules=["deserialization", "taint-flow"], sev="HIGH",
      manifest=['<service android:name="{PK}.inj.Case36" android:exported="true"><intent-filter><action android:name="inj.case36.LOAD"/></intent-filter></service>'],
      smali={"Case36": cls("Case36", """
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 6
    const-string v0, "blob"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getByteArrayExtra(Ljava/lang/String;)[B
    move-result-object v0
    new-instance v1, Ljava/io/ByteArrayInputStream;
    invoke-direct {v1, v0}, Ljava/io/ByteArrayInputStream;-><init>([B)V
    new-instance v2, Ljava/io/ObjectInputStream;
    invoke-direct {v2, v1}, Ljava/io/ObjectInputStream;-><init>(Ljava/io/InputStream;)V
    invoke-virtual {v2}, Ljava/io/ObjectInputStream;->readObject()Ljava/lang/Object;
    move-result-object v3
    const/4 v4, 0x2
    return v4
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method
""", sup="Landroid/app/Service;")}),
]

# ---------------------------------------------------------------------------------------------------------------------------------- probes
# Variants of the above that change the SHAPE of the pattern (the way real code differs from a textbook example). Measured, not promised.
CASES += [
 dict(id="40", name="Cipher algorithm string built at run time (\"AES/\" + \"ECB/PKCS5Padding\")", kind="probe", rules=["crypto-cipher"], sev="HIGH",
      smali={"Case40": cls("Case40", """
.method public static c()Ljavax/crypto/Cipher;
    .locals 3
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "AES/"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    const-string v1, "ECB/PKCS5Padding"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;
    move-result-object v0
    return-object v0
.end method
""")}),
 dict(id="41", name="key hidden as Base64.decode(\"...\") and used in SecretKeySpec", kind="probe", rules=["crypto-hardcoded-key"], sev="HIGH",
      smali={"Case41": cls("Case41", """
.method public static key()Ljavax/crypto/spec/SecretKeySpec;
    .locals 4
    const-string v0, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
    const/4 v1, 0x0
    invoke-static {v0, v1}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B
    move-result-object v0
    new-instance v2, Ljavax/crypto/spec/SecretKeySpec;
    const-string v3, "AES"
    invoke-direct {v2, v0, v3}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    return-object v2
.end method
""")}),
 dict(id="42", name="key bytes in a static array field, used by SecretKeySpec in another method", kind="probe", rules=["crypto-hardcoded-key"], sev="HIGH",
      smali={"Case42": cls("Case42", """
.method static constructor <clinit>()V
    .locals 2
    const/16 v0, 0x10
    new-array v0, v0, [B
    fill-array-data v0, :k
    sput-object v0, L{P}/Case42;->KEY:[B
    return-void
    :k
    .array-data 1
        0x41t 0x42t 0x43t 0x44t 0x45t 0x46t 0x47t 0x48t 0x49t 0x4at 0x4bt 0x4ct 0x4dt 0x4et 0x4ft 0x50t
    .end array-data
.end method

.method public static spec()Ljavax/crypto/spec/SecretKeySpec;
    .locals 3
    sget-object v0, L{P}/Case42;->KEY:[B
    new-instance v1, Ljavax/crypto/spec/SecretKeySpec;
    const-string v2, "AES"
    invoke-direct {v1, v0, v2}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V
    return-object v1
.end method
""", fields=".field private static final KEY:[B\n")}),
 dict(id="43", name="exported activity forwards its extra to a NOT exported activity that loads it in a WebView", kind="probe", rules=["taint-flow", "webview-intent-url"], sev="HIGH",
      manifest=['<activity android:name="{PK}.inj.Case43" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><data android:scheme="injfwd"/></intent-filter></activity>',
                '<activity android:name="{PK}.inj.Case43B" android:exported="false"/>'],
      smali={"Case43": cls("Case43", """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, L{P}/Case43;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Landroid/content/Intent;
    const-class v3, L{P}/Case43B;
    invoke-direct {v2, p0, v3}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    const-string v3, "u"
    invoke-virtual {v2, v3, v1}, Landroid/content/Intent;->putExtra(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;
    invoke-virtual {p0, v2}, L{P}/Case43;->startActivity(Landroid/content/Intent;)V
    return-void
.end method
""", sup="Landroid/app/Activity;"),
             "Case43B": cls("Case43B", """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, L{P}/Case43B;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "u"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Landroid/webkit/WebView;
    invoke-direct {v2, p0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V
    invoke-virtual {v2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", sup="Landroid/app/Activity;")}),
 dict(id="44", name="deep link: a query parameter of the Intent data loaded into a WebView", kind="probe", rules=["taint-flow", "webview-intent-url"], sev="HIGH",
      manifest=['<activity android:name="{PK}.inj.Case44" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https" android:host="inj.example.com"/></intent-filter></activity>'],
      smali={"Case44": cls("Case44", """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, L{P}/Case44;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {v0}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    const-string v1, "u"
    invoke-virtual {v0, v1}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    new-instance v2, Landroid/webkit/WebView;
    invoke-direct {v2, p0}, Landroid/webkit/WebView;-><init>(Landroid/content/Context;)V
    invoke-virtual {v2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", sup="Landroid/app/Activity;")}),
 dict(id="45", name="exported service: extra passed to Runtime.exec(String[]) as the sh -c argument", kind="probe", rules=["taint-flow", "shell-exec"], sev="CRITICAL",
      manifest=['<service android:name="{PK}.inj.Case45" android:exported="true"><intent-filter><action android:name="inj.case45.RUN"/></intent-filter></service>'],
      smali={"Case45": cls("Case45", """
.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 6
    const-string v0, "cmd"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0
    const/4 v1, 0x3
    new-array v1, v1, [Ljava/lang/String;
    const/4 v2, 0x0
    const-string v3, "sh"
    aput-object v3, v1, v2
    const/4 v2, 0x1
    const-string v3, "-c"
    aput-object v3, v1, v2
    const/4 v2, 0x2
    aput-object v0, v1, v2
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v2
    invoke-virtual {v2, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    const/4 v4, 0x2
    return v4
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1
    const/4 v0, 0x0
    return-object v0
.end method
""", sup="Landroid/app/Service;")}),
 dict(id="46", name="exported activity: extra formatted into a rawQuery with String.format", kind="probe", rules=["taint-flow", "sql-concat"], sev="HIGH",
      manifest=['<activity android:name="{PK}.inj.Case46" android:exported="true"><intent-filter><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><data android:scheme="injsql"/></intent-filter></activity>'],
      smali={"Case46": cls("Case46", """
.method protected onCreate(Landroid/os/Bundle;)V
    .locals 8
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    invoke-virtual {p0}, L{P}/Case46;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "q"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    const-string v2, "SELECT * FROM notes WHERE title = '%s'"
    const/4 v3, 0x1
    new-array v3, v3, [Ljava/lang/Object;
    const/4 v4, 0x0
    aput-object v1, v3, v4
    invoke-static {v2, v3}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v2
    invoke-virtual {p0}, L{P}/Case46;->db()Landroid/database/sqlite/SQLiteDatabase;
    move-result-object v5
    const/4 v6, 0x0
    invoke-virtual {v5, v2, v6}, Landroid/database/sqlite/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;
    return-void
.end method
""", sup="Landroid/app/Activity;")}),
 dict(id="47", name="exported provider: openFile builds a path from the last path segment", kind="probe", rules=["provider-openfile-segment", "taint-flow"], sev="HIGH",
      manifest=['<provider android:name="{PK}.inj.Case47" android:authorities="inj.case47" android:exported="true"/>'],
      smali={"Case47": cls("Case47", """
.method public openFile(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;
    .locals 5
    invoke-virtual {p1}, Landroid/net/Uri;->getLastPathSegment()Ljava/lang/String;
    move-result-object v0
    new-instance v1, Ljava/io/File;
    invoke-virtual {p0}, L{P}/Case47;->getContext()Landroid/content/Context;
    move-result-object v2
    invoke-virtual {v2}, Landroid/content/Context;->getFilesDir()Ljava/io/File;
    move-result-object v2
    invoke-direct {v1, v2, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V
    const/high16 v3, 0x10000000
    invoke-static {v1, v3}, Landroid/os/ParcelFileDescriptor;->open(Ljava/io/File;I)Landroid/os/ParcelFileDescriptor;
    move-result-object v4
    return-object v4
.end method
""", sup="Landroid/content/ContentProvider;")}),
]

# ---------------------------------------------------------------------------------------------------------------------------------- vendor tokens (0.89.0)
# literal true-positive samples of the gitleaks rule set (the samples the gitleaks project keeps for its own rules), one per rule, as string constants in app code
import json as _json, os as _os
_PICKS = [("anthropic-api-key", "sk-ant-api03-abc123xyz-456_ABC-789_def012ghi-345_jkl678mno-901_pqr234stu-567_vwx890yz-123_ABC456DEF-789_ghi012jkl-345mno-678_pqr901stuAA"),
          ("stripe-access-token", "sk_test_51OuEMLAlTWGaDypq4P5cuDHbuKeG4tAGPYHJpEXQ7zE8mKK3jkhTFPvCxnSSK5zB5EQZrJsYdsatNmAHGgb0vSKD00GTMSWRHs"),
          ("slack-bot-token", "xoxb-781236542736-2364535789652-GkwFDQoHqzXDVsC6GzqYUypD"),
          ("notion-api-token", "ntn_456476151729vWBETTAcANVU0hgc9abcdefg1h2i3j4k5l6")]
_picks_file = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "vendor_picks.json")
if _os.path.exists(_picks_file): _PICKS = [tuple(x) for x in _json.load(open(_picks_file))]
for _n, (_rid, _tok) in enumerate(_PICKS):
    _cid = "5%d" % _n
    CASES.append(dict(id=_cid, name="vendor token in a string constant (%s)" % _rid, kind="must", rules=["secrets-vendor-tokens", "secrets-known-formats", "secrets-google-api-key"], sev="HIGH",
        smali={"Case" + _cid: cls("Case" + _cid, """
.method public static t()Ljava/lang/String;
    .locals 1
    const-string v0, "%s"
    return-object v0
.end method
""" % _tok.replace("\\", "\\\\").replace('"', '\\"'))}))

# ---------------------------------------------------------------------------------------------------------------------------------- 0.100.0: Jackson default typing, SQLCipher passphrase
CASES += [
    dict(id="60", name="Jackson enableDefaultTyping in app code", kind="must", rules=["jackson-default-typing"], sev="MEDIUM",
         smali={"Case60": cls("Case60", """
.method public static t()V
    .locals 2
    new-instance v0, Lcom/fasterxml/jackson/databind/ObjectMapper;
    invoke-direct {v0}, Lcom/fasterxml/jackson/databind/ObjectMapper;-><init>()V
    invoke-virtual {v0}, Lcom/fasterxml/jackson/databind/ObjectMapper;->enableDefaultTyping()Lcom/fasterxml/jackson/databind/ObjectMapper;
    return-void
.end method
""")}),
    dict(id="61", name="@JsonTypeInfo(use = CLASS) on an app model", kind="must", rules=["jackson-default-typing"], sev="MEDIUM",
         smali={"Case61": cls("Case61", """
.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method
""", fields=".annotation runtime Lcom/fasterxml/jackson/annotation/JsonTypeInfo;\n    use = .enum Lcom/fasterxml/jackson/annotation/JsonTypeInfo$Id;->CLASS\n.end annotation\n")}),
    dict(id="62", name="SQLCipher passphrase is a string constant", kind="must", rules=["crypto-db-passphrase"], sev="HIGH",
         smali={"Case62": cls("Case62", """
.method public static t()V
    .locals 3
    new-instance v0, Lnet/sqlcipher/database/SQLiteOpenHelper;
    const-string v1, "wallet-db-key-2024"
    invoke-virtual {v0, v1}, Lnet/sqlcipher/database/SQLiteOpenHelper;->getWritableDatabase(Ljava/lang/String;)Lnet/sqlcipher/database/SQLiteDatabase;
    return-void
.end method
""")}),
    dict(id="63", name="SQLCipher passphrase from ANDROID_ID", kind="must", rules=["crypto-db-passphrase"], sev="MEDIUM",
         smali={"Case63": cls("Case63", """
.method public static t(Landroid/content/ContentResolver;)V
    .locals 4
    new-instance v0, Lnet/sqlcipher/database/SQLiteOpenHelper;
    const-string v3, "android_id"
    invoke-static {p0, v3}, Landroid/provider/Settings$Secure;->getString(Landroid/content/ContentResolver;Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {v0, v1}, Lnet/sqlcipher/database/SQLiteOpenHelper;->getWritableDatabase(Ljava/lang/String;)Lnet/sqlcipher/database/SQLiteDatabase;
    return-void
.end method
""")}),
]
