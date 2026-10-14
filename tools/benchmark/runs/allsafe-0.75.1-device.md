# APK ReLab report: infosecadventures.allsafe

> Educational static analysis. Use only on apps you own or are allowed to analyze.

## App info

```
Package: infosecadventures.allsafe
Size: 10.3 MB | Files: 1087
DEX: 7 (classes3.dex 6.6 KB, classes6.dex 4.5 KB, classes5.dex 14.0 KB, classes4.dex 55.2 KB, classes2.dex 533.1 KB, classes7.dex 7.9 MB, classes.dex 9.3 MB)
```

## AndroidManifest.xml

```xml
<?xml version='1.0' encoding='utf-8' ?>
<manifest android:versionCode="5"
          android:versionName="1.5"
          android:compileSdkVersion="35"
          android:compileSdkVersionCodename="15"
          package="infosecadventures.allsafe"
          platformBuildVersionCode="35"
          platformBuildVersionName="15" xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-sdk android:minSdkVersion="23"
            android:targetSdkVersion="35" />
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
  <uses-permission android:name="android.permission.RECORD_AUDIO" />
  <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
  <uses-permission android:name="android.permission.QUERY_ALL_PACKAGES" />
  <permission android:name="infosecadventures.allsafe.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
              android:protectionLevel="signature" />
  <uses-permission android:name="infosecadventures.allsafe.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" />
  <application android:theme="@style/Theme.Allsafe"
               android:label="@string/app_name"
               android:icon="@mipmap/ic_launcher"
               android:name="infosecadventures.allsafe.ArbitraryCodeExecution"
               android:debuggable="true"
               android:allowBackup="true"
               android:extractNativeLibs="false"
               android:networkSecurityConfig="@xml/network_security_config"
               android:roundIcon="@mipmap/ic_launcher_round"
               android:appComponentFactory="androidx.core.app.CoreComponentFactory"
               android:requestLegacyExternalStorage="true">
    <activity android:name="infosecadventures.allsafe.ProxyActivity"
              android:exported="true" />
    <activity android:theme="@style/Theme.Allsafe.NoActionBar"
              android:name="infosecadventures.allsafe.challenges.DeepLinkTask"
              android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="allsafe"
              android:host="infosecadventures"
              android:pathPrefix="/congrats" />
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" />
      </intent-filter>
    </activity>
    <activity android:name="infosecadventures.allsafe.MainActivity"
              android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <receiver android:name="infosecadventures.allsafe.challenges.NoteReceiver"
              android:exported="true">
      <intent-filter>
        <action android:name="infosecadventures.allsafe.action.PROCESS_NOTE" />
      </intent-filter>
    </receiver>
    <service android:name="infosecadventures.allsafe.challenges.RecorderService"
             android:enabled="true"
             android:exported="true" />
    <provider android:name="infosecadventures.allsafe.challenges.DataProvider"
              android:enabled="true"
              android:exported="true"
              android:authorities="infosecadventures.allsafe.dataprovider" />
    <provider android:name="androidx.core.content.FileProvider"
              android:exported="false"
              android:authorities="infosecadventures.allsafe.fileprovider"
              android:grantUriPermissions="true">
      <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
                 android:resource="@xml/provider_paths" />
    </provider>
    <service android:name="com.google.firebase.components.ComponentDiscoveryService"
             android:exported="false"
             android:directBootAware="true">
      <meta-data android:name="com.google.firebase.components:com.google.firebase.database.ktx.FirebaseDatabaseLegacyRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
      <meta-data android:name="com.google.firebase.components:com.google.firebase.storage.ktx.FirebaseStorageLegacyRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
      <meta-data android:name="com.google.firebase.components:com.google.firebase.database.FirebaseDatabaseKtxRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
      <meta-data android:name="com.google.firebase.components:com.google.firebase.database.DatabaseRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
      <meta-data android:name="com.google.firebase.components:com.google.firebase.storage.FirebaseStorageKtxRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
      <meta-data android:name="com.google.firebase.components:com.google.firebase.storage.StorageRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
      <meta-data android:name="com.google.firebase.components:com.google.firebase.appcheck.FirebaseAppCheckKtxRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
      <meta-data android:name="com.google.firebase.components:com.google.firebase.appcheck.FirebaseAppCheckRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
      <meta-data android:name="com.google.firebase.components:com.google.firebase.ktx.FirebaseCommonLegacyRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
      <meta-data android:name="com.google.firebase.components:com.google.firebase.FirebaseCommonKtxRegistrar"
                 android:value="com.google.firebase.components.ComponentRegistrar" />
    </service>
    <provider android:name="com.google.firebase.provider.FirebaseInitProvider"
              android:exported="false"
              android:authorities="infosecadventures.allsafe.firebaseinitprovider"
              android:initOrder="100"
              android:directBootAware="true" />
    <activity android:theme="@android:style/Theme.Translucent.NoTitleBar"
              android:name="com.google.android.gms.common.api.GoogleApiActivity"
              android:exported="false" />
    <provider android:name="androidx.startup.InitializationProvider"
              android:exported="false"
              android:authorities="infosecadventures.allsafe.androidx-startup">
      <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer"
                 android:value="androidx.startup" />
      <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer"
                 android:value="androidx.startup" />
      <meta-data android:name="androidx.profileinstaller.ProfileInstallerInitializer"
                 android:value="androidx.startup" />
    </provider>
    <uses-library android:name="androidx.window.extensions"
                  android:required="false" />
    <uses-library android:name="androidx.window.sidecar"
                  android:required="false" />
    <meta-data android:name="com.google.android.gms.version"
               android:value="@integer/google_play_services_version" />
    <receiver android:name="androidx.profileinstaller.ProfileInstallReceiver"
              android:permission="android.permission.DUMP"
              android:enabled="true"
              android:exported="true"
              android:directBootAware="false">
      <intent-filter>
        <action android:name="androidx.profileinstaller.action.INSTALL_PROFILE" />
      </intent-filter>
      <intent-filter>
        <action android:name="androidx.profileinstaller.action.SKIP_FILE" />
      </intent-filter>
      <intent-filter>
        <action android:name="androidx.profileinstaller.action.SAVE_PROFILE" />
      </intent-filter>
      <intent-filter>
        <action android:name="androidx.profileinstaller.action.BENCHMARK_OPERATION" />
      </intent-filter>
    </receiver>
  </application>
</manifest>
```

## Attack surface

Exported components (reachable by other apps): **7** - requested permissions: **7**

| Component | Kind | Intent-filter actions |
|---|---|---|
| `infosecadventures.allsafe.ProxyActivity` | activity | - |
| `infosecadventures.allsafe.challenges.DeepLinkTask` | activity | VIEW |
| `infosecadventures.allsafe.MainActivity` | activity | MAIN |
| `infosecadventures.allsafe.challenges.NoteReceiver` | receiver | PROCESS_NOTE |
| `infosecadventures.allsafe.challenges.RecorderService` | service | - |
| `infosecadventures.allsafe.challenges.DataProvider` | provider | - |
| `androidx.profileinstaller.ProfileInstallReceiver` | receiver | INSTALL_PROFILE, SKIP_FILE, SAVE_PROFILE, BENCHMARK_OPERATION |

**Permissions:** ACCESS_NETWORK_STATE, INTERNET, QUERY_ALL_PACKAGES, READ_EXTERNAL_STORAGE, RECORD_AUDIO, WRITE_EXTERNAL_STORAGE, infosecadventures.allsafe.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION

## Security scan

Deep scan status: finished, 12077 / 12077 classes; SSA taint: +2 flow(s) (taint losses real/param-only: callee not analysed 0/1, app method unresolved 1/76, library or outside group 4/115 (top owners of real drops: android/content/ContentUris 1, androidx/core/app/NotificationCompat$Builder 1, app infosecadventures/allsafe/ProxyActivity 1, okhttp3/HttpUrl 1, okhttp3/OkHttpClient 1); caps hit: sink refs 0, rounds 0 method(s), requeue 0 method(s), ~ sites 0; slowest methods: ObjectSerialization.lambda$onCreateView$1(Ljava/lang/String;Landroid/view/View;)V 3ms [45 insns, 2 rounds, 2 runs], ProxyActivity.onCreate(Landroid/os/Bundle;)V 3ms [7 insns, 2 rounds, 1 runs], ObjectSerialization.lambda$onCreateView$0(Lcom/google/android/material/textfield/TextInputEditText;Lcom/google/android/material/textfield/TextInputEditText;Ljava/lang/String;Landroid/view/View;)V 2ms [42 insns, 2 rounds, 2 runs], DeepLinkTask.onCreate(Landroid/os/Bundle;)V 2ms [42 insns, 2 rounds, 2 runs], ArbitraryCodeExecution.invokeUpdate()V 2ms [47 insns, 2 rounds, 1 runs])

Heuristic static scan - 91 finding(s) in total; 55 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 10 |
| MEDIUM | 28 |
| LOW | 16 |

**OWASP Mobile Top 10 (2024) coverage**

- M9 Insecure Data Storage: 20
- M8 Security Misconfiguration: 12
- M4 Insufficient Input/Output Validation: 9
- M10 Insufficient Cryptography: 6
- M1 Improper Credential Usage: 3
- M3 Insecure Authentication/Authorization: 3
- M5 Insecure Communication: 2

### Findings

#### 1. [CRITICAL] Debuggable build

- Location: `AndroidManifest.xml`
- CWE: CWE-489 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-RESILIENCE | Confidence: HIGH | Rule: manifest-debuggable
- Priority: 90/100 (P1)
- Why flagged: android:debuggable="true" is set. Anyone with the APK (or USB access to the device) can attach a debugger, set breakpoints, dump memory, or step through the logic - including past client-side checks.
- Risk scenario: A debuggable app lets anyone attach a debugger, run code inside the process and read its private data; WebView debugging exposes pages and JS state over USB. android:testOnly marks a test build that may carry relaxed checks and must not be shipped.
- Fix: Remove android:debuggable, or make sure it is only true in debug build variants and never in what you ship/test for release.

#### 2. [HIGH] Untrusted input reaches an SQL statement (x3)

- Location: `infosecadventures.allsafe.challenges.DataProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 60/100 (P2)
- Call path: Entry: exported provider infosecadventures.allsafe.challenges.DataProvider | Path: infosecadventures.allsafe.challenges.DataProvider.delete()
- AI triage: TRUE POSITIVE - The delete method of an exported ContentProvider directly passes the untrusted selection parameter into SQLiteDatabase.delete() without sanitization or input validation, enabling SQL injection. Fix: Use parameterized queries by separating the column names in the selection string from user-supplied values in the selectionArgs array. (confidence 90%) ⚖️ Council confirmed: The critic (OpenRouter/nvidia/nemotron-3-ultra-550b-a55b:free) agreed: The exported ContentProvider's delete() receives attacker-controlled 'selection' and 'selectionArgs' directly from any calling app. The selection string is concatenated into the WHERE clause of SQLite
- Why flagged: Data from a ContentProvider method parameter (other apps can call it when the provider is exported) reaches SQLiteDatabase.delete() in method delete(): the table or the WHERE clause contains the input. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way.  (around line 56)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 3. [HIGH] Code loaded from another app's package context

- Location: `infosecadventures.allsafe.ArbitraryCodeExecution`
- CWE: CWE-94 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: package-context-code | Scope: APP
- Priority: 42/100 (P3)
- AI triage: TRUE POSITIVE - The application iterates through installed packages, checks if their names start with the application's own package prefix, and dynamically loads code and executes reflection methods from them using createPackageContext with CONTEXT_INCLUDE_CODE without verifying signatures, leading to arbitrary code execution. Fix: Remove dynamic loading of code from external package contexts, or implement strict cryptographic signature verification of the target package to ensure it is signed by a trusted developer certificate before loading its classes. (confidence 95%) ⚖️ Council confirmed: The critic (OpenRouter/nvidia/nemotron-3-ultra-550b-a55b:free) agreed: The method uses createPackageContext with CONTEXT_INCLUDE_CODE|CONTEXT_IGNORE_SECURITY (flag 3), loads a fixed class name via reflection from any installed package whose name starts with the app's own
- Why flagged: createPackageContext() is called with CONTEXT_INCLUDE_CODE and the resulting context's class loader is used, and no signature check of the target package is visible. Any app installed under that package name runs its code inside this process.  (around line 109)  Also matched by: dynamic-code-loading (merged).
- Risk scenario: Code loaded at runtime from a writable, downloaded or attacker-reachable location executes with the app's permissions, so replacing that file means running the attacker's code.
- Fix: Do not load code from other apps. If you must, verify the package signature with PackageManager.checkSignatures / signing certificates first and drop CONTEXT_IGNORE_SECURITY.

#### 4. [HIGH] Dex code loaded from a shared or world-accessible directory

- Location: `infosecadventures.allsafe.ArbitraryCodeExecution`
- CWE: CWE-94 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: dex-load-writable-dir | Scope: APP
- Priority: 42/100 (P3)
- AI triage: TRUE POSITIVE - The application dynamic loader reads executable Dex code from shared external storage (/sdcard/), allowing untrusted processes to modify or substitute the binary before execution. Fix: Store executable files exclusively in private internal storage (Context.getFilesDir()) and verify code integrity or signatures prior to class loading. (confidence 90%) ⚖️ Council confirmed: The critic (Gemini/gemini-3.5-flash-lite) agreed: The code explicitly loads a DEX file from a world-readable external storage path (/sdcard/Download/allsafe_updater.apk) using DexClassLoader, which constitutes an insecure deserialization/arbitrary co
- Why flagged: A class loader is created in a class that also builds a hardcoded /sdcard or /data/local/tmp path. If the dex/jar sits there, another app (or a rooted user) can replace it and run code with this app's permissions.  (around line 231)
- Risk scenario: Code loaded at runtime from a writable, downloaded or attacker-reachable location executes with the app's permissions, so replacing that file means running the attacker's code.
- Fix: Copy the dex into app-private storage (filesDir, mode private), make it read-only (File.setReadOnly) before loading, and verify a hash or signature, or ship the code inside the APK.

#### 5. [HIGH] Untrusted Intent is launched by this app (intent redirection)

- Location: `infosecadventures.allsafe.ProxyActivity`
- CWE: CWE-940 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 70/100 (P1)
- Call path: Entry: ProxyActivity.onCreate(Landroid/os/Bundle;)V | Path: ProxyActivity.onCreate(Landroid/os/Bundle;)V
- AI triage: TRUE POSITIVE - The exported activity extracts an arbitrary Intent from incoming extras and passes it directly to startActivity without validation, creating an intent redirection vulnerability. Fix: Validate that the target component in the nested intent is explicitly allowed before calling startActivity, or set android:exported="false" in AndroidManifest.xml if external invocation is not required. (confidence 95%) ⚖️ Council confirmed: The critic (Gemini/gemini-3.5-flash-lite) agreed: The ProxyActivity is exported and extracts a nested Intent from the parcelable extra without any validation or permission checks, passing it directly to startActivity, which is a textbook Intent Redir
- Why flagged: Data from Intent.getParcelableExtra() reaches Context.startActivity() in method ProxyActivity.onCreate(Landroid/os/Bundle;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.  (around line 38)
- Risk scenario: An Intent object received from another app is launched as it is, so the attacker chooses which component runs (even a non-exported one) with this app's identity, permissions and URI grants.
- Fix: Do not launch an Intent you received from a caller. Build a new Intent for a fixed component of your own and copy over only the extras you need, or check getComponent() / getPackage() against an allow-list and clear the URI-permission flags before launching.

#### 6. [HIGH] Sensitive financial value stored without encryption

- Location: `infosecadventures.allsafe.challenges.InsecureSharedPreferences`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: fintech-unencrypted-storage | Scope: APP
- Priority: 42/100 (P3)
- AI triage: TRUE POSITIVE - The application stores user credentials (password) in plaintext using standard SharedPreferences, which can be easily extracted from the device's data directory on rooted devices. Fix: Migrate from standard SharedPreferences to Jetpack's EncryptedSharedPreferences to encrypt both keys and values using Android Keystore. (confidence 90%) ⚖️ Council confirmed: The critic (OpenRouter/nvidia/nemotron-3-ultra-550b-a55b:free) agreed: The code explicitly stores a user-supplied password from an EditText into plain SharedPreferences under the key "password" in a registration flow. The class name (InsecureSharedPreferences) and packag
- Why flagged: A value under the key "password" is written with SharedPreferences.Editor.putString(), and this class never touches EncryptedSharedPreferences or the Android Keystore. Plain SharedPreferences XML is readable on a rooted device, from an adb backup, or from any app sharing the same Linux UID (shared UID apps) - for a PIN, API key or session token that's a direct credential-theft path.  (around line 160)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Move this key to androidx.security.crypto.EncryptedSharedPreferences, or better, keep it only in the Android Keystore (StrongBox/TEE-backed where available) and never serialize it to disk in cleartext.

#### 7. [HIGH] High-entropy embedded string near a credential-like name

- Location: `infosecadventures.allsafe.challenges.NoteReceiver`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: high-entropy-strings | Scope: APP | Reachable from an exported component
- Priority: 60/100 (P2)
- Call path: Entry: exported receiver infosecadventures.allsafe.challenges.NoteReceiver | Path: infosecadventures.allsafe.challenges.NoteReceiver.onReceive()
- AI triage: TRUE POSITIVE - A hardcoded authentication token is embedded directly in the source code as a Base64-encoded string and transmitted via query parameters, making it vulnerable to extraction via reverse engineering. Fix: Remove the hardcoded credential from the application binary and instead retrieve it securely from server-side authentication or secure storage mechanisms. (confidence 90%)
- Why flagged: A 32-char string with high character randomness (entropy 4.3 bits/char, mixed character classes) sits in a method that also mentions a credential-like identifier (token/secret/password/api key...). Looks like an embedded secret: "YWxs…".  (around line 107)
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Check manually whether this is really a secret. If so, remove it from the APK and load it from a secure backend or the Android Keystore at runtime instead.

#### 8. [HIGH] Weak cipher mode: ECB ("AES/ECB/PKCS5PADDING")

- Location: `infosecadventures.allsafe.challenges.WeakCryptography`
- CWE: CWE-327 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-cipher | Scope: APP
- Priority: 49/100 (P2)
- AI triage: TRUE POSITIVE - The code explicitly uses AES in Electronic Codebook (ECB) mode via Cipher.getInstance("AES/ECB/PKCS5PADDING"), which lacks an initialization vector (IV) and exposes data patterns. Fix: Replace "AES/ECB/PKCS5PADDING" with a secure authenticated mode such as "AES/GCM/NoPadding" and supply a unique initialization vector (IV). (confidence 90%)
- Why flagged: Cipher.getInstance("AES/ECB/PKCS5PADDING") uses ECB (a bare "AES"/"DES" defaults to ECB on Android): identical plaintext blocks give identical ciphertext blocks, leaking structure and allowing block swapping.  (around line 68)
- Risk scenario: DES/RC4/MD5/ECB-mode data can be decrypted or forged much faster than the key length suggests. ECB shows patterns (equal blocks give equal ciphertext) and has no integrity.
- Fix: Use AES/GCM/NoPadding with a fresh random 12-byte IV per message (or AES/CBC + HMAC if GCM is not possible).

#### 9. [HIGH] Hardcoded encryption key

- Location: `infosecadventures.allsafe.challenges.WeakCryptography`
- CWE: CWE-321 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-hardcoded-key | Scope: APP
- Priority: 49/100 (P2)
- AI triage: TRUE POSITIVE - The method contains a hardcoded AES encryption key ("1nf053c4dv3n7ur3") directly in the Smali source code, which can be easily extracted via static analysis. Furthermore, it uses the insecure ECB mode ("AES/ECB/PKCS5PADDING"), lacking semantic security. Fix: Remove the hardcoded secret key and derive it securely using the Android Keystore system with a strong cipher mode like GCM instead of ECB. (confidence 95%)
- Why flagged: A SecretKeySpec is built from a string literal ("1nf…", 16 chars) that sits in the APK - anyone who decompiles it can decrypt/forge whatever this key protects.  (around line 62)
- Risk scenario: The key is the same for every install and is readable from the APK, so all data protected with it can be decrypted offline by anyone.
- Fix: Generate the key at runtime into the Android Keystore (KeyGenParameterSpec) or derive it from a user secret with PBKDF2; never compile it in.

#### 10. [HIGH] Hardcoded credentials in a URL

- Location: `resources.arsc`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: res-strings-url-credentials
- Priority: 60/100 (P2)
- Why flagged: A URL with an embedded user name and password (user adm..., host dev.infosecadventures.com) is stored in the resources.  [resources.arsc]
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Remove the credentials from the URL and rotate that password. Authenticate with a per-user token obtained after login.

#### 11. [HIGH] Exported provider without a permission: infosecadventures.allsafe.challenges.DataProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 70/100 (P1)
- Why flagged: This provider is exported (usable by other apps) and declares no android:permission. A ContentProvider exported with no permission can let any app on the device query/insert/update/delete its data; if it builds file paths or SQL from the incoming Uri, that's also a path-traversal / SQL-injection surface.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 12. [MEDIUM] Possible intent redirection (an Intent from the extras is launched)

- Location: `infosecadventures.allsafe.ProxyActivity`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: intent-redirection | Scope: APP | Reachable from an exported component
- Priority: 38/100 (P3)
- Call path: Entry: exported activity infosecadventures.allsafe.ProxyActivity | Path: infosecadventures.allsafe.ProxyActivity.onCreate()
- AI triage: TRUE POSITIVE - The exported ProxyActivity extracts a Parcelable from the intent extras, casts it directly to an Intent, and passes it to startActivity without validation. This allows a malicious external app to invoke arbitrary internal, unexported components using this application's privileges. Fix: Validate the extracted Intent before passing it to startActivity, or restrict the ProxyActivity to be unexported if it is only intended for internal use. (confidence 70%)
- Why flagged: This method reads a Parcelable from the incoming extras, casts it to Intent and then starts an activity/service or sends a broadcast. If the component is reachable by other apps, the caller chooses WHAT gets started - including non-exported components of this app, with this app's permissions.  (around line 32)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Do not launch an Intent received from outside. If you must, check the target (resolveActivity / allow-list of components) and clear flags such as FLAG_GRANT_*_URI_PERMISSION first.

#### 13. [MEDIUM] Sensitive value written to log

- Location: `infosecadventures.allsafe.challenges.InsecureLogging`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 27/100 (P3)
- AI triage: TRUE POSITIVE - The code explicitly reads user input from a TextInputEditText and passes it directly into a Log.d statement with a credential-like label, leaking sensitive data to Logcat. Fix: Remove the logging statement that outputs the sensitive secret or replace it with generic non-sensitive status logging. (confidence 90%)
- Why flagged: A log call is built from a credential-like label ("User entered secret: ") plus an appended variable. Logcat can be read from a computer over ADB, and by other apps on some devices.  (around line 79)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Never log passwords, tokens, or personal data; strip such Log calls from release builds.

#### 14. [MEDIUM] Credentials may be written to the log

- Location: `infosecadventures.allsafe.challenges.InsecureLogging`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: log-credential-object | Scope: APP
- Priority: 27/100 (P3)
- Note: Not reached from an exported component by method calls or explicit startActivity(new Intent(ctx, X.class)) hops. It can still be reached through implicit Intents with a framework action (VIEW, SEND), string-built ComponentNames or PendingIntents (the call graph follows explicit launches and custom-action implicit Intents only): check who launches this component.
- AI triage: TRUE POSITIVE - The method explicitly reads user input from a TextInputEditText and writes it directly to the system log using Log.d(), which exposes sensitive data via Logcat. Fix: Remove the logging statement that outputs the sensitive user input or replace it with safe diagnostic logging that does not include credentials. (confidence 70%)
- Why flagged: This method builds a log message with a StringBuilder and writes it with Log.d(). Credential-like variable names in the method: secret. Logcat can be read over adb and, on older Android versions, by other apps.  (around line 79)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Remove the log call or log only a non-sensitive id; never put a login/credential object in a message, and strip debug logging from release builds (R8 -assumenosideeffects).

#### 15. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `infosecadventures.allsafe.challenges.InsecureSharedPreferences`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 27/100 (P3)
- AI triage: TRUE POSITIVE - The application stores user credentials in plaintext using standard SharedPreferences, which can be easily extracted on rooted devices or via device backups. Fix: Use EncryptedSharedPreferences from the Android Security library to securely encrypt both keys and values at rest. (confidence 90%)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 147)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

#### 16. [MEDIUM] Untrusted input chooses the server the app contacts

- Location: `infosecadventures.allsafe.challenges.NoteReceiver`
- CWE: CWE-918 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE / MASVS-NETWORK | Confidence: HIGH | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 45/100 (P2)
- Call path: Entry: NoteReceiver.onReceive(Landroid/content/Context;Landroid/content/Intent;)V | Path: NoteReceiver.onReceive(Landroid/content/Context;Landroid/content/Intent;)V
- AI triage: TRUE POSITIVE - The static analysis flags an exported BroadcastReceiver whose Intent extras are passed directly into a network URL builder without validation, allowing a malicious app to trigger arbitrary HTTP requests (Server-Side Request Forgery). Fix: Validate and sanitize any input received from Intents before using it to construct URLs or perform network operations, or make the BroadcastReceiver unexported if it is only intended for internal use. (confidence 70%)
- Why flagged: Data from Intent.getStringExtra() reaches Request$Builder.url() in method NoteReceiver.onReceive(Landroid/content/Context;Landroid/content/Intent;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.  (around line 139)
- Risk scenario: When a deep link, Intent extra or web page decides which host the app connects to, an attacker can point it at an internal service, a server that logs the app's headers and tokens, or a cleartext endpoint.
- Fix: Allow-list the host (and use https) before opening the connection; resolve a small id to a fixed URL on your side.

#### 17. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `infosecadventures.allsafe.challenges.ObjectSerialization`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 230)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 18. [MEDIUM] Weak hash: MD5

- Location: `infosecadventures.allsafe.challenges.SQLInjection`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: MD5 is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum.  (around line 66)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash.

#### 19. [MEDIUM] Possible SQL built by string concatenation

- Location: `infosecadventures.allsafe.challenges.SQLInjection`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: APP
- Priority: 27/100 (P3)
- Note: Not reached from an exported component by method calls or explicit startActivity(new Intent(ctx, X.class)) hops. It can still be reached through implicit Intents with a framework action (VIEW, SEND), string-built ComponentNames or PendingIntents (the call graph follows explicit launches and custom-action implicit Intents only): check who launches this component.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 174)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 20. [MEDIUM] Sensitive value written to SQLite (plaintext)

- Location: `infosecadventures.allsafe.challenges.SQLInjection`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: An SQL statement in this class creates or fills a table with a credential-like column. SQLite files are unencrypted and readable on rooted devices or from a backup.  (around line 310)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords in SQLite; if you must keep sensitive columns use SQLCipher or encrypt the values with a Keystore key.

#### 21. [MEDIUM] Sensitive data stored in plain SQLite

- Location: `infosecadventures.allsafe.challenges.SQLInjection`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: sqlite-unencrypted | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: Private data is written to a plain (unencrypted) SQLite database: the column "password" (CREATE TABLE). The database file sits in /data/data/<package>/databases and is readable on a rooted device, from an adb backup (allowBackup) or a forensic image. No hash or cipher call was seen on the value in this method (SSA backward slice; values from other methods are not followed).  (around line 312)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not keep credentials in a database at all (store a salted hash or a revocable token). For private data use SQLCipher (net.zetetic:sqlcipher-android) or encrypt the values with a key from the Android Keystore; set allowBackup=false or exclude the database from backups.

#### 22. [MEDIUM] Weak hash: MD5

- Location: `infosecadventures.allsafe.challenges.WeakCryptography`
- CWE: CWE-328 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: crypto-weak-hash | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: MD5 is broken for integrity/signature purposes (practical collisions); fine only as a non-security checksum.  (around line 336)
- Risk scenario: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.
- Fix: Use SHA-256+ for integrity; for passwords use a salted KDF (PBKDF2/bcrypt/Argon2), never a raw hash.

#### 23. [MEDIUM] Hardcoded encryption key (field)

- Location: `infosecadventures.allsafe.challenges.WeakCryptography`
- CWE: CWE-321 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: MEDIUM | Rule: crypto-hardcoded-key | Scope: APP
- Priority: 38/100 (P3)
- Why flagged: The field "KEY" is initialised with a string literal ("1nf…", 16 chars) in a class that uses javax.crypto; if it feeds a key or cipher it is compiled into the APK. Anyone who decompiles the app can read it and decrypt/forge whatever it protects.  (around line 7)
- Risk scenario: The key is the same for every install and is readable from the APK, so all data protected with it can be decrypted offline by anyone.
- Fix: Generate the key at runtime into the Android Keystore (KeyGenParameterSpec) or derive it from a user secret with PBKDF2; never compile it in.

#### 24. [MEDIUM] Predictable random value used for security

- Location: `infosecadventures.allsafe.challenges.WeakCryptography`
- CWE: CWE-338 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: weak-random | Scope: APP
- Priority: 45/100 (P2)
- Why flagged: The output of java.util.Random.nextInt() is returned by randomNumber() of WeakCryptography (a class that uses javax.crypto / MessageDigest). java.util.Random is a linear congruential generator: after a few outputs (or from the seed) every next value can be computed, so a token / PIN / key built from it can be guessed. Traced in SSA inside randomNumber(); the receiver is a new java.util.Random (a SecureRandom held in a Random variable is not reported).  (around line 420)
- Risk scenario: java.util.Random is predictable from a few outputs; session ids, OTPs, reset tokens or keys built from it can be guessed.
- Fix: Use java.security.SecureRandom (and never a fixed seed) for tokens, PINs, salts, IVs and keys.

#### 25. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/fragment_insecure_shared_preferences.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f0901ab") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 23: devices below Android 12 do not block touches through overlays.  [res/layout/fragment_insecure_shared_preferences.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 26. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/fragment_native_library.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f0901ab") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 23: devices below Android 12 do not block touches through overlays.  [res/layout/fragment_native_library.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 27. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/fragment_object_serialization.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f0901ab") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 23: devices below Android 12 do not block touches through overlays.  [res/layout/fragment_object_serialization.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 28. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/fragment_pin_bypass.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f0901b6") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 23: devices below Android 12 do not block touches through overlays.  [res/layout/fragment_pin_bypass.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 29. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/fragment_sql_injection.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f0901ab") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 23: devices below Android 12 do not block touches through overlays.  [res/layout/fragment_sql_injection.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 30. [MEDIUM] Network Security Config: cleartext permitted for specific domains

- Location: `res/xml/network_security_config.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-cleartext-domains
- Priority: 45/100 (P2)
- Why flagged: Plain HTTP is allowed for: infosecadventures.io (+subdomains). Traffic to these hosts can be read and modified on the network.  [res/xml/network_security_config.xml]
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Move the backend to HTTPS and remove cleartextTrafficPermitted="true". If a legacy host cannot be fixed yet, keep the exception scoped to that exact domain and track its removal.

#### 31. [MEDIUM] FileProvider shares too much (<files-path path=".">)

- Location: `res/xml/provider_paths.xml`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: LOW | Rule: res-fileprovider-paths
- Priority: 27/100 (P3)
- Why flagged: These FileProvider paths cover a whole directory tree (the root of the file system or the app's private data: databases, shared_prefs, tokens). Any content:// URI the app hands out, or lets a caller choose, can then point at files that were never meant to be shared.  [res/xml/provider_paths.xml]
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: List only the specific sub-folder to share (for example path="shared/"), never root-path or path=".", and keep the provider exported="false" with grantUriPermissions="true".

#### 32. [MEDIUM] Firebase Realtime Database URL

- Location: `resources.arsc`
- CWE: CWE-284 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-AUTH / MASVS-PLATFORM | Confidence: MEDIUM | Rule: res-strings-firebase-url
- Priority: 38/100 (P3)
- Why flagged: The app resources contain a Firebase Realtime Database URL (https://allsafe-8cef0.firebaseio.com). The URL alone is not a flaw, but if the database rules allow public reads or writes, anyone can dump or change the data. This cannot be checked statically.  [resources.arsc]
- Risk scenario: Data or functions are reachable without a proper check: for example an open Firebase database or a provider anyone can query. A Firebase Realtime Database URL in the resources is not a flaw by itself: the question is whether its rules allow public reads or writes, because the URL is readable by anyone who unpacks the APK.
- Fix: Open this URL + "/.json" from a test device you own: if it returns data, the database rules allow public reads. Lock the rules down (auth != null) and require authentication.

#### 33. [MEDIUM] Backup allowed (allowBackup)

- Location: `AndroidManifest.xml`
- CWE: CWE-530 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-allow-backup
- Priority: 45/100 (P2)
- Why flagged: android:allowBackup is not explicitly "false" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.
- Risk scenario: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.
- Fix: Set android:allowBackup="false", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.

#### 34. [MEDIUM] Exported activity without a permission: infosecadventures.allsafe.ProxyActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 35. [MEDIUM] Exported receiver without a permission: infosecadventures.allsafe.challenges.NoteReceiver

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This receiver is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 36. [MEDIUM] Exported service without a permission: infosecadventures.allsafe.challenges.RecorderService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 37. [MEDIUM] Shell command execution

- Location: `com.scottyab.rootbeer.RootBeer`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec
- Priority: 38/100 (P3)
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 137)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 38. [LOW] Firebase Realtime Database SDK used

- Location: `infosecadventures.allsafe.challenges.FirebaseDatabase`
- CWE: CWE-284 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-AUTH / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: This class initializes/uses the Firebase Realtime Database SDK. No literal database URL turned up nearby in this class (it may come from google-services.json's generated resources, a remote config, or a different class) - but the app does talk to a Firebase backend, so its security rules matter just as much as if the URL were visible here.  (around line 62)
- Risk scenario: Data or functions are reachable without a proper check: for example an open Firebase database or a provider anyone can query. A Firebase Realtime Database URL in the resources is not a flaw by itself: the question is whether its rules allow public reads or writes, because the URL is readable by anyone who unpacks the APK.
- Fix: Confirm the project's rules require authentication rather than the default public "test mode" (which Firebase itself only allows temporarily, but is often left in place). Try https://<project-id>-default-rtdb.<region>.firebasedatabase.app/.json (or the older https://<project>.firebaseio.com/.json) from outside the app: data returned with no login means the rules are public.

#### 39. [LOW] HTTP client built without certificate pinning

- Location: `infosecadventures.allsafe.challenges.NoteReceiver`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: LOW | Rule: androgoat-checks | Scope: APP
- Priority: 12/100 (P4)
- Why flagged: An OkHttpClient is built in this class with no CertificatePinner. A user-installed or rogue CA can then intercept the HTTPS traffic (this is what a proxy like Burp relies on).  (around line 56)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: For traffic to your own backend add a CertificatePinner (or a <pin-set> in network_security_config.xml).

#### 40. [LOW] WebView JavaScript enabled

- Location: `infosecadventures.allsafe.challenges.VulnerableWebView`
- CWE: CWE-79 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: setJavaScriptEnabled(true) widens the attack surface of every page this WebView loads.  (around line 181)
- Risk scenario: Untrusted text placed into HTML inside a WebView runs as script in that page. With a JavaScript bridge or file access enabled it can reach app data or native methods.
- Fix: Enable it only if needed and only for trusted https:// origins.

#### 41. [LOW] Data copied to clipboard

- Location: `infosecadventures.allsafe.utils.ClipUtil`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 108)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 42. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/fragment_insecure_logging.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "@0x7f0901e4" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/fragment_insecure_logging.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 43. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/fragment_insecure_shared_preferences.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "@0x7f09024c" looks sensitive or is the main input of this screen, but its inputType (0x1) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/fragment_insecure_shared_preferences.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 44. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/fragment_object_serialization.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "@0x7f09024c" looks sensitive or is the main input of this screen, but its inputType (0x1) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/fragment_object_serialization.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 45. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/fragment_sql_injection.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "@0x7f09024c" looks sensitive or is the main input of this screen, but its inputType (0x1) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/fragment_sql_injection.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 46. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/fragment_weak_cryptography.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "@0x7f0901e4" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/fragment_weak_cryptography.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 47. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/material_time_input.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/material_time_input.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 48. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/mtrl_picker_text_input_date.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (0x14) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/mtrl_picker_text_input_date.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 49. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/mtrl_picker_text_input_date_range.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (0x14) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/mtrl_picker_text_input_date_range.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 50. [LOW] Google API key in resources

- Location: `resources.arsc`
- CWE: CWE-798 | OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO | Confidence: MEDIUM | Rule: res-strings-google-api-key
- Priority: 17/100 (P4)
- Why flagged: A Google API key (AIzaSy... (39 chars)) is stored in the app resources. The APK also has a Firebase app id, so this is the standard client key of google-services: it is meant to ship in the app, but it is only safe when it is restricted. Check it in the Google Cloud console (Credentials).  [resources.arsc]
- Risk scenario: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.
- Fix: Restrict the key to this app (package name + SHA-1) and to the APIs you use, set a quota alert, and rotate it if it was ever unrestricted.

#### 51. [LOW] Deep link entry point: infosecadventures.allsafe.challenges.DeepLinkTask

- Location: `AndroidManifest.xml`
- CWE: CWE-939 | OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-deep-links
- Priority: 17/100 (P4)
- Why flagged: This activity can be opened from a browser/other apps via allsafe, https://infosecadventures. Anything in the link (path, query, fragment) is attacker-controlled input. No android:autoVerify, so the link is not verified as belonging to this app.
- Risk scenario: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.
- Fix: Validate every parameter taken from the incoming Intent data (host allow-list, type checks), never load it into a WebView or use it as a file path unchecked; for web links use verified App Links (autoVerify + assetlinks.json).

#### 52. [LOW] Exported activity without a permission: infosecadventures.allsafe.challenges.DeepLinkTask

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: VIEW).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 53. [LOW] Legacy external storage requested

- Location: `AndroidManifest.xml`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-legacy-external-storage
- Priority: 20/100 (P4)
- Why flagged: android:requestLegacyExternalStorage="true" opts out of scoped storage, so files the app writes to shared storage stay readable (and replaceable) by other apps that hold the storage permission.
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Migrate to scoped storage (MediaStore / SAF / getExternalFilesDir) and remove the flag.

#### 54. [MEDIUM] Sensitive data stored in plain SQLite

- Location: `infosecadventures.allsafe.challenges.NoteDatabaseHelper`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: sqlite-unencrypted | Scope: APP
- Priority: 27/100 (P3)
- AI triage: FALSE POSITIVE - The SAST tool incorrectly flagged sample note strings containing the word 'password' as sensitive user credentials being stored in a database. The data is hardcoded sample text rather than actual user secrets. Fix: No fix is required, but you can remove the word 'password' from the sample note string or use encrypted storage if sensitive data is handled in the future. (confidence 95%)
- Why flagged: Private data is written to a plain (unencrypted) SQLite database: the column "password" (INSERT). The database file sits in /data/data/<package>/databases and is readable on a rooted device, from an adb backup (allowBackup) or a forensic image. No hash or cipher call was seen on the value in this method (SSA backward slice; values from other methods are not followed).  (around line 43)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not keep credentials in a database at all (store a salted hash or a revocable token). For private data use SQLCipher (net.zetetic:sqlcipher-android) or encrypt the values with a key from the Android Keystore; set allowBackup=false or exclude the database from backups.

#### 55. [MEDIUM] Sensitive value written to SQLite (plaintext)

- Location: `infosecadventures.allsafe.challenges.NoteDatabaseHelper`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 27/100 (P3)
- AI triage: FALSE POSITIVE - The database contains hardcoded sample text for an intentionally vulnerable training application rather than actual user-submitted secrets or credentials. Fix: If this were production code, the SQLite database should be encrypted using SQLCipher or sensitive data should be avoided. (confidence 90%)
- Why flagged: An SQL statement in this class creates or fills a table with a credential-like column. SQLite files are unencrypted and readable on rooted devices or from a backup.  (around line 41)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords in SQLite; if you must keep sensitive columns use SQLCipher or encrypt the values with a Keystore key.

### Remediation guide

One entry per weakness type found above.

#### CWE-489 - Active Debug Code

OWASP: M8 Security Misconfiguration | MASVS: MASVS-RESILIENCE

Risk: A debuggable app lets anyone attach a debugger, run code inside the process and read its private data; WebView debugging exposes pages and JS state over USB. android:testOnly marks a test build that may carry relaxed checks and must not be shipped.

Vulnerable:

```kotlin
<application android:debuggable="true" android:testOnly="true" ...>
WebView.setWebContentsDebuggingEnabled(true)
```

Secure:

```kotlin
<!-- release builds are not debuggable by default: remove android:debuggable and android:testOnly -->
if (BuildConfig.DEBUG) WebView.setWebContentsDebuggingEnabled(true)
```

References: [CWE-489 (MITRE)](https://cwe.mitre.org/data/definitions/489.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-89 - Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE

Risk: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.

Vulnerable:

```kotlin
db.rawQuery("SELECT * FROM users WHERE name = '" + name + "'", null)
```

Secure:

```kotlin
db.rawQuery("SELECT * FROM users WHERE name = ?", arrayOf(name))   // bound parameter
// ContentProvider.query: pass selection with ? and selectionArgs, never concatenate them
```

References: [CWE-89 (MITRE)](https://cwe.mitre.org/data/definitions/89.html) | [SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-94 - Improper Control of Generation of Code (Code Injection)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE

Risk: Code loaded at runtime from a writable, downloaded or attacker-reachable location executes with the app's permissions, so replacing that file means running the attacker's code.

Vulnerable:

```kotlin
DexClassLoader(File(getExternalFilesDir(null), "plugin.dex").path, optDir, null, classLoader)
```

Secure:

```kotlin
// ship the code in the APK, or download it over HTTPS, verify a signature, and keep it in app-private storage (read-only after verification)
val f = File(filesDir, "plugin.dex"); verifySignature(f); f.setReadOnly()
```

References: [CWE-94 (MITRE)](https://cwe.mitre.org/data/definitions/94.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-940 - Improper Verification of Source of a Communication Channel (Intent Redirection)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM

Risk: An Intent object received from another app is launched as it is, so the attacker chooses which component runs (even a non-exported one) with this app's identity, permissions and URI grants.

Vulnerable:

```kotlin
val next = intent.getParcelableExtra<Intent>("extra_intent"); startActivity(next)
```

Secure:

```kotlin
val next = intent.getParcelableExtra<Intent>("extra_intent")
val ok = next?.component?.packageName == packageName && next.component?.className in ALLOWED_SCREENS
if (ok) startActivity(Intent(this, Class.forName(next!!.component!!.className))) else finish()
```

References: [CWE-940 (MITRE)](https://cwe.mitre.org/data/definitions/940.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-312 - Cleartext Storage of Sensitive Information

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.

Vulnerable:

```kotlin
prefs.edit().putString("password", password).apply()
db.execSQL("INSERT INTO users(pin) VALUES ('" + pin + "')")
```

Secure:

```kotlin
// store a token (not the password) and encrypt it with a Keystore-backed AES-GCM key
val sealed = keystoreCipher.encrypt(token.toByteArray())     // see CWE-321 sample for the key
prefs.edit().putString("token", Base64.encodeToString(sealed, Base64.NO_WRAP)).apply()
// database: SQLCipher or per-field encryption; never keep the password itself
```

References: [CWE-312 (MITRE)](https://cwe.mitre.org/data/definitions/312.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-798 - Use of Hard-coded Credentials

OWASP: M1 Improper Credential Usage | MASVS: MASVS-STORAGE / MASVS-CRYPTO

Risk: Anyone can unzip the APK (or run strings on the dex) and read the key, token or password. A leaked cloud/API key lets the attacker call the backend as the app, run up the bill, or read other users' data. Removing it in the next release does not help: old APKs stay in the wild, so the key must be rotated. Resources are no hiding place: res/values/strings.xml is compiled into resources.arsc, and apktool or a plain unzip shows every string. Tokens (JWT) can be decoded by anyone, and a Google / Firebase API key is only safe when it is restricted to your app.

Vulnerable:

```kotlin
const val API_KEY = "EXAMPLE_ONLY_NOT_A_REAL_KEY"   // shipped inside every APK
val client = Api(API_KEY)
<!-- res/values/strings.xml: this ends up readable inside resources.arsc -->
<string name="api_secret">EXAMPLE_ONLY_NOT_A_REAL_KEY</string>
```

Secure:

```kotlin
// keep the secret on YOUR server; the app only holds a short-lived user token
val token = authRepository.sessionToken()      // issued after login, expires, revocable
val client = Api(token)
// if a client key is unavoidable: restrict it (package name + SHA-256 cert, API scope, quota) and rotate it
// Google / Firebase API key in strings.xml: in the Cloud console restrict it to Android apps (package name + SHA-1) and to the APIs you use
<!-- strings.xml keeps only public identifiers; secrets and long-lived tokens stay on your backend -->
```

References: [CWE-798 (MITRE)](https://cwe.mitre.org/data/definitions/798.html) | [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-327 - Use of a Broken or Risky Cryptographic Algorithm

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: DES/RC4/MD5/ECB-mode data can be decrypted or forged much faster than the key length suggests. ECB shows patterns (equal blocks give equal ciphertext) and has no integrity.

Vulnerable:

```kotlin
Cipher.getInstance("AES/ECB/PKCS5Padding")
MessageDigest.getInstance("MD5")
```

Secure:

```kotlin
val cipher = Cipher.getInstance("AES/GCM/NoPadding")        // authenticated encryption
cipher.init(Cipher.ENCRYPT_MODE, key)                        // let the provider create a fresh random IV
val iv = cipher.iv; val ct = cipher.doFinal(plain)           // store iv next to ct
// hashing: SHA-256 or better; passwords: PBKDF2 / Argon2 / scrypt, never a plain hash
```

References: [CWE-327 (MITRE)](https://cwe.mitre.org/data/definitions/327.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-321 - Use of Hard-coded Cryptographic Key

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: The key is the same for every install and is readable from the APK, so all data protected with it can be decrypted offline by anyone.

Vulnerable:

```kotlin
SecretKeySpec("MySecretKey12345".toByteArray(), "AES")
```

Secure:

```kotlin
// generate the key on the device inside the Android Keystore (non-exportable)
val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
kg.init(KeyGenParameterSpec.Builder("data_key", KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).build())
val key = kg.generateKey()
```

References: [CWE-321 (MITRE)](https://cwe.mitre.org/data/definitions/321.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-926 - Improper Export of Android Application Components

OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM

Risk: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.

Vulnerable:

```kotlin
<activity android:name=".AdminActivity" android:exported="true" />
<permission android:name="com.example.PERM" android:protectionLevel="normal" />   <!-- any app can request it -->
<provider android:name=".Db" android:exported="true" android:readPermission="com.example.READ" />   <!-- writes are open -->
```

Secure:

```kotlin
<activity android:name=".AdminActivity" android:exported="false" />
<!-- if another app must call it: android:permission="com.example.PERM" with protectionLevel="signature", and validate every extra -->
<permission android:name="com.example.PERM" android:protectionLevel="signature" />
<provider android:name=".Db" android:exported="true" android:readPermission="com.example.READ" android:writePermission="com.example.WRITE" />
```

References: [CWE-926 (MITRE)](https://cwe.mitre.org/data/definitions/926.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-927 - Use of Implicit Intent for Sensitive Communication

OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM

Risk: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.

Vulnerable:

```kotlin
sendBroadcast(Intent("com.example.TOKEN").putExtra("token", t))
PendingIntent.getActivity(this, 0, intent, 0)
```

Secure:

```kotlin
sendBroadcast(Intent("com.example.TOKEN").setPackage(packageName).putExtra("token", t))
PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE)
```

References: [CWE-927 (MITRE)](https://cwe.mitre.org/data/definitions/927.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-532 - Insertion of Sensitive Information into Log File

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.

Vulnerable:

```kotlin
Log.d("Login", "user=" + user + " password=" + password)
```

Secure:

```kotlin
if (BuildConfig.DEBUG) Log.d("Login", "login attempt")      // never log credentials or tokens
// release builds: strip logs with R8 (-assumenosideeffects class android.util.Log { *; })
```

References: [CWE-532 (MITRE)](https://cwe.mitre.org/data/definitions/532.html) | [Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-918 - Server-Side Request Forgery (SSRF)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE / MASVS-NETWORK

Risk: When a deep link, Intent extra or web page decides which host the app connects to, an attacker can point it at an internal service, a server that logs the app's headers and tokens, or a cleartext endpoint.

Vulnerable:

```kotlin
val url = intent.getStringExtra("endpoint")
val conn = URL(url).openConnection()      // host chosen by the caller
```

Secure:

```kotlin
val id = intent.getStringExtra("endpoint")
val url = ENDPOINTS[id] ?: return          // fixed allow-list, https only
val conn = URL(url).openConnection()
```

References: [CWE-918 (MITRE)](https://cwe.mitre.org/data/definitions/918.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-502 - Deserialization of Untrusted Data

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE

Risk: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.

Vulnerable:

```kotlin
val obj = ObjectInputStream(input).readObject()
```

Secure:

```kotlin
// use a data-only format with a schema (JSON / Protobuf) and validate every field
val dto = Json.decodeFromString<Message>(text)
// if Java serialization is unavoidable: set an ObjectInputFilter allow-list
```

References: [CWE-502 (MITRE)](https://cwe.mitre.org/data/definitions/502.html) | [Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-328 - Use of Weak Hash

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: MD5 and SHA-1 collisions are practical, so signatures, integrity checks or password hashes built on them can be forged or cracked quickly.

Vulnerable:

```kotlin
MessageDigest.getInstance("SHA-1").digest(data)
```

Secure:

```kotlin
MessageDigest.getInstance("SHA-256").digest(data)
// passwords: use a slow KDF (PBKDF2WithHmacSHA256 with 600000+ iterations, Argon2id, scrypt)
```

References: [CWE-328 (MITRE)](https://cwe.mitre.org/data/definitions/328.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-338 - Use of Cryptographically Weak PRNG

OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO

Risk: java.util.Random is predictable from a few outputs; session ids, OTPs, reset tokens or keys built from it can be guessed.

Vulnerable:

```kotlin
val otp = Random().nextInt(999999)
```

Secure:

```kotlin
val otp = SecureRandom().nextInt(1_000_000)
```

References: [CWE-338 (MITRE)](https://cwe.mitre.org/data/definitions/338.html) | [Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-1021 - Improper Restriction of Rendered UI Layers or Frames (Tapjacking)

OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM

Risk: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.

Vulnerable:

```kotlin
<EditText android:inputType="textPassword" ... />   <!-- no filterTouchesWhenObscured -->
```

Secure:

```kotlin
<LinearLayout android:filterTouchesWhenObscured="true" ...>
// or, API 31+: window.setHideOverlayWindows(true)  (needs HIDE_OVERLAY_WINDOWS)
```

References: [CWE-1021 (MITRE)](https://cwe.mitre.org/data/definitions/1021.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-319 - Cleartext Transmission of Sensitive Information

OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK

Risk: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.

Vulnerable:

```kotlin
<application android:usesCleartextTraffic="true" ...>
val url = "http://api.example.com/login"   // plain HTTP
<network-security-config>
    <base-config cleartextTrafficPermitted="true" />   <!-- every domain may use plain HTTP -->
</network-security-config>
```

Secure:

```kotlin
<application android:usesCleartextTraffic="false" android:networkSecurityConfig="@xml/network_security_config" ...>
val url = "https://api.example.com/login"   // TLS
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false" />
</network-security-config>
<!-- only if one legacy host really needs HTTP: scope it to that host, never to base-config -->
<domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="false">legacy.example.com</domain>
</domain-config>
```

References: [CWE-319 (MITRE)](https://cwe.mitre.org/data/definitions/319.html) | [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-200 - Exposure of Sensitive Information to an Unauthorized Actor

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM

Risk: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.

Vulnerable:

```kotlin
webSettings.allowFileAccessFromFileURLs = true
<provider android:exported="true" android:grantUriPermissions="true" ... />   <!-- every path can be handed out -->
```

Secure:

```kotlin
webSettings.allowFileAccessFromFileURLs = false
webSettings.allowUniversalAccessFromFileURLs = false
<provider android:exported="false" android:grantUriPermissions="false" ...>
    <grant-uri-permission android:pathPrefix="/shared/" />   <!-- only the paths that must be shared -->
</provider>
```

References: [CWE-200 (MITRE)](https://cwe.mitre.org/data/definitions/200.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-284 - Improper Access Control

OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-AUTH / MASVS-PLATFORM

Risk: Data or functions are reachable without a proper check: for example an open Firebase database or a provider anyone can query. A Firebase Realtime Database URL in the resources is not a flaw by itself: the question is whether its rules allow public reads or writes, because the URL is readable by anyone who unpacks the APK.

Vulnerable:

```kotlin
// Firebase rules: { ".read": true, ".write": true }
```

Secure:

```kotlin
// Firebase rules: only authenticated users, only their own node
{ "rules": { "users": { "uid": { ".read": "auth != null && auth.uid == 'uid'" } } } }
// test your own database from a device you own: open PROJECT-ID.firebaseio.com/.json  -> it must answer Permission denied
```

References: [CWE-284 (MITRE)](https://cwe.mitre.org/data/definitions/284.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-530 - Exposure of Backup File to an Unauthorized Control Sphere

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.

Vulnerable:

```kotlin
<application android:allowBackup="true" ...>
```

Secure:

```kotlin
<application android:allowBackup="false" android:dataExtractionRules="@xml/data_extraction_rules" ...>
<!-- or keep backup and exclude secrets with fullBackupContent / dataExtractionRules -->
```

References: [CWE-530 (MITRE)](https://cwe.mitre.org/data/definitions/530.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-78 - Improper Neutralization of Special Elements used in an OS Command

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE

Risk: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).

Vulnerable:

```kotlin
Runtime.getRuntime().exec("ping " + host)
```

Secure:

```kotlin
// no shell: fixed program, arguments as separate list items, validated input
ProcessBuilder("ping", "-c", "1", validatedHost).redirectErrorStream(true).start()
// better: use an Android API instead of a command
```

References: [CWE-78 (MITRE)](https://cwe.mitre.org/data/definitions/78.html) | [OS Command Injection Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-295 - Improper Certificate Validation

OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK

Risk: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.

Vulnerable:

```kotlin
object : X509TrustManager {
    override fun checkServerTrusted(c: Array<X509Certificate>, a: String) { }   // accepts everything
    override fun checkClientTrusted(c: Array<X509Certificate>, a: String) { }
    override fun getAcceptedIssuers() = arrayOf<X509Certificate>()
}
<!-- res/xml/network_security_config.xml: trusts any CA the user (or malware) installed -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
```

Secure:

```kotlin
// use the platform trust store (do not override TrustManager at all)
val client = OkHttpClient.Builder()
    .certificatePinner(CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAA...=")      // optional: pin to your own backend
        .build())
    .build()
// WebView: in onReceivedSslError call handler.cancel(), never handler.proceed()

<!-- network_security_config.xml: system CAs only in release; user CAs only for the debugging proxy -->
<network-security-config>
    <base-config>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2027-06-30">
            <pin digest="SHA-256">CURRENT_KEY_PIN_BASE64=</pin>
            <pin digest="SHA-256">BACKUP_KEY_PIN_BASE64=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

References: [CWE-295 (MITRE)](https://cwe.mitre.org/data/definitions/295.html) | [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | [Pinning Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Pinning_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-79 - Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM

Risk: Untrusted text placed into HTML inside a WebView runs as script in that page. With a JavaScript bridge or file access enabled it can reach app data or native methods.

Vulnerable:

```kotlin
webView.loadData("<h1>Hello " + userName + "</h1>", "text/html", "UTF-8")
```

Secure:

```kotlin
val safe = android.text.Html.escapeHtml(userName)   // or TextUtils.htmlEncode
webView.loadDataWithBaseURL(null, "<h1>Hello " + safe + "</h1>", "text/html", "UTF-8", null)
// plus: keep JavaScript off unless needed, no JS interface on untrusted pages
```

References: [CWE-79 (MITRE)](https://cwe.mitre.org/data/definitions/79.html) | [Cross Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-524 - Use of Cache Containing Sensitive Information

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.

Vulnerable:

```kotlin
<EditText android:inputType="text" />   <!-- password-like field with suggestions on -->
```

Secure:

```kotlin
<EditText android:inputType="textPassword|textNoSuggestions" android:importantForAutofill="no" />
```

References: [CWE-524 (MITRE)](https://cwe.mitre.org/data/definitions/524.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-939 - Improper Authorization in Handler for Custom URL Scheme

OWASP: M3 Insecure Authentication/Authorization | MASVS: MASVS-PLATFORM

Risk: Any web page or app can fire the deep link. If the handler acts on its parameters (open URL, log in, pay) without checking them, the link becomes a remote control for the app.

Vulnerable:

```kotlin
val target = intent.data?.getQueryParameter("redirect"); webView.loadUrl(target!!)
```

Secure:

```kotlin
val target = intent.data?.getQueryParameter("redirect")?.let(Uri::parse)
if (target?.host == "app.example.com") open(target)     // allow-list; require user confirmation for sensitive actions
// prefer verified App Links (https + assetlinks.json) over custom schemes
```

References: [CWE-939 (MITRE)](https://cwe.mitre.org/data/definitions/939.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

#### CWE-922 - Insecure Storage of Sensitive Information

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.

Vulnerable:

```kotlin
File(Environment.getExternalStorageDirectory(), "export.json").writeText(json)
<application android:requestLegacyExternalStorage="true" ...>
```

Secure:

```kotlin
File(filesDir, "export.json").writeText(json)          // app-private storage
// to share: use a FileProvider with a narrow path and grant temporary URI permission
// scoped storage: remove requestLegacyExternalStorage; use MediaStore, the Storage Access Framework or getExternalFilesDir
```

References: [CWE-922 (MITRE)](https://cwe.mitre.org/data/definitions/922.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

## Third-Party Libraries & SCA

65 component(s) detected in the APK (META-INF version files, pom.properties, native .so strings, dex strings, package-path heuristics). **0 vulnerable / outdated, 6 with unknown version (NOT checked against CVEs).** Libraries detected only by package path have version `?`: presence is proven, the version is not - they cannot be matched against version-specific CVEs, so this is a lower bound, not proof that nothing else is bundled.

| Component | Version | Status | Known vulnerabilities | Fix | Source |
|---|---|---|---|---|---|
| androidx.activity:activity | 1.8.0 | OK | - | - | version file |
| androidx.activity:activity-ktx | 1.8.0 | OK | - | - | version file |
| androidx.annotation:annotation-experimental | 1.4.1 | OK | - | - | version file |
| androidx.appcompat:appcompat | 1.7.0 | OK | - | - | version file |
| androidx.appcompat:appcompat-resources | 1.7.0 | OK | - | - | version file |
| androidx.asynclayoutinflater:asynclayoutinflater | 1.0.0 | OK | - | - | version file |
| androidx.browser:browser | 1.8.0 | OK | - | - | version file |
| androidx.cardview:cardview | 1.0.0 | OK | - | - | version file |
| androidx.constraintlayout:constraintlayout | 2.2.1 | OK | - | - | version file |
| androidx.coordinatorlayout:coordinatorlayout | 1.1.0 | OK | - | - | version file |
| androidx.core:core | 1.13.0 | OK | - | - | version file |
| androidx.core:core-ktx | 1.13.0 | OK | - | - | version file |
| androidx.cursoradapter:cursoradapter | 1.0.0 | OK | - | - | version file |
| androidx.customview:customview | 1.1.0 | OK | - | - | version file |
| androidx.documentfile:documentfile | 1.0.0 | OK | - | - | version file |
| androidx.drawerlayout:drawerlayout | 1.1.1 | OK | - | - | version file |
| androidx.dynamicanimation:dynamicanimation | 1.0.0 | OK | - | - | version file |
| androidx.emoji2:emoji2 | 1.3.0 | OK | - | - | version file |
| androidx.emoji2:emoji2-views-helper | 1.3.0 | OK | - | - | version file |
| androidx.exifinterface:exifinterface | 1.4.0 | OK | - | - | version file |
| androidx.fragment:fragment | 1.6.2 | OK | - | - | version file |
| androidx.fragment:fragment-ktx | 1.6.2 | OK | - | - | version file |
| androidx.interpolator:interpolator | 1.0.0 | OK | - | - | version file |
| androidx.legacy:legacy-support-core-ui | 1.0.0 | OK | - | - | version file |
| androidx.legacy:legacy-support-core-utils | 1.0.0 | OK | - | - | version file |
| androidx.legacy:legacy-support-v4 | 1.0.0 | OK | - | - | version file |
| androidx.loader:loader | 1.0.0 | OK | - | - | version file |
| androidx.localbroadcastmanager:localbroadcastmanager | 1.0.0 | OK | - | - | version file |
| androidx.media:media | 1.0.0 | OK | - | - | version file |
| androidx.navigation:navigation-common | 2.8.9 | OK | - | - | version file |
| androidx.navigation:navigation-common-ktx | 2.8.9 | OK | - | - | version file |
| androidx.navigation:navigation-fragment | 2.8.9 | OK | - | - | version file |
| androidx.navigation:navigation-fragment-ktx | 2.8.9 | OK | - | - | version file |
| androidx.navigation:navigation-runtime | 2.8.9 | OK | - | - | version file |
| androidx.navigation:navigation-runtime-ktx | 2.8.9 | OK | - | - | version file |
| androidx.navigation:navigation-ui | 2.8.9 | OK | - | - | version file |
| androidx.navigation:navigation-ui-ktx | 2.8.9 | OK | - | - | version file |
| androidx.print:print | 1.0.0 | OK | - | - | version file |
| androidx.profileinstaller:profileinstaller | 1.4.0 | OK | - | - | version file |
| androidx.recyclerview:recyclerview | 1.1.0 | OK | - | - | version file |
| androidx.savedstate:savedstate | 1.2.1 | OK | - | - | version file |
| androidx.savedstate:savedstate-ktx | 1.2.1 | OK | - | - | version file |
| androidx.security:security-crypto | 1.1.0-alpha06 | OK | - | - | version file |
| androidx.slidingpanelayout:slidingpanelayout | 1.2.0 | OK | - | - | version file |
| androidx.startup:startup-runtime | 1.1.1 | OK | - | - | version file |
| androidx.swiperefreshlayout:swiperefreshlayout | 1.0.0 | OK | - | - | version file |
| androidx.tracing:tracing | 1.0.0 | OK | - | - | version file |
| androidx.transition:transition | 1.5.0 | OK | - | - | version file |
| androidx.vectordrawable:vectordrawable | 1.2.0 | OK | - | - | version file |
| androidx.vectordrawable:vectordrawable-animated | 1.2.0 | OK | - | - | version file |
| androidx.versionedparcelable:versionedparcelable | 1.1.1 | OK | - | - | version file |
| androidx.viewpager2:viewpager2 | 1.0.0 | OK | - | - | version file |
| androidx.viewpager:viewpager | 1.0.0 | OK | - | - | version file |
| androidx.window:window | 1.0.0 | OK | - | - | version file |
| com.google.android.gms:play-services | ? | UNKNOWN VERSION | - | - | package path |
| com.google.code.gson:gson | ? | UNKNOWN VERSION (CVEs exist for older releases) | CVE-2022-25647 | check version, fixed in 2.8.9 or newer | package path |
| com.google.firebase:firebase-common | ? | UNKNOWN VERSION | - | - | package path |
| com.google.guava:guava | ? | UNKNOWN VERSION (CVEs exist for older releases) | CVE-2023-2976 / CVE-2020-8908 | check version, fixed in 32.1.2-android or newer | package path |
| com.squareup.okhttp3:okhttp | 4.9.0 | OK | - | - | dex string |
| com.squareup.okio:okio | ? | UNKNOWN VERSION | - | - | package path |
| kotlinx:coroutines_android | 1.7.3 | OK | - | - | version file |
| kotlinx:coroutines_core | 1.7.3 | OK | - | - | version file |
| kotlinx:coroutines_play_services | 1.7.3 | OK | - | - | version file |
| androidx:androidx-libraries | ? | UNKNOWN VERSION | - | - | package path |
| com.google.android.material:material | 1.12.0 | OK | - | - | version file |

CycloneDX 1.5 (JSON):

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "group": "androidx.activity",
      "name": "activity-ktx",
      "version": "1.8.0",
      "purl": "pkg:maven\/androidx.activity\/activity-ktx@1.8.0"
    },
    {
      "type": "library",
      "group": "androidx.activity",
      "name": "activity",
      "version": "1.8.0",
      "purl": "pkg:maven\/androidx.activity\/activity@1.8.0"
    },
    {
      "type": "library",
      "group": "androidx.annotation",
      "name": "annotation-experimental",
      "version": "1.4.1",
      "purl": "pkg:maven\/androidx.annotation\/annotation-experimental@1.4.1"
    },
    {
      "type": "library",
      "group": "androidx.appcompat",
      "name": "appcompat-resources",
      "version": "1.7.0",
      "purl": "pkg:maven\/androidx.appcompat\/appcompat-resources@1.7.0"
    },
    {
      "type": "library",
      "group": "androidx.appcompat",
      "name": "appcompat",
      "version": "1.7.0",
      "purl": "pkg:maven\/androidx.appcompat\/appcompat@1.7.0"
    },
    {
      "type": "library",
      "group": "androidx.asynclayoutinflater",
      "name": "asynclayoutinflater",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.asynclayoutinflater\/asynclayoutinflater@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.browser",
      "name": "browser",
      "version": "1.8.0",
      "purl": "pkg:maven\/androidx.browser\/browser@1.8.0"
    },
    {
      "type": "library",
      "group": "androidx.cardview",
      "name": "cardview",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.cardview\/cardview@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.constraintlayout",
      "name": "constraintlayout",
      "version": "2.2.1",
      "purl": "pkg:maven\/androidx.constraintlayout\/constraintlayout@2.2.1"
    },
    {
      "type": "library",
      "group": "androidx.coordinatorlayout",
      "name": "coordinatorlayout",
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.coordinatorlayout\/coordinatorlayout@1.1.0"
    },
    {
      "type": "library",
      "group": "androidx.core",
      "name": "core-ktx",
      "version": "1.13.0",
      "purl": "pkg:maven\/androidx.core\/core-ktx@1.13.0"
    },
    {
      "type": "library",
      "group": "androidx.core",
      "name": "core",
      "version": "1.13.0",
      "purl": "pkg:maven\/androidx.core\/core@1.13.0"
    },
    {
      "type": "library",
      "group": "androidx.cursoradapter",
      "name": "cursoradapter",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.cursoradapter\/cursoradapter@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.customview",
      "name": "customview",
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.customview\/customview@1.1.0"
    },
    {
      "type": "library",
      "group": "androidx.documentfile",
      "name": "documentfile",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.documentfile\/documentfile@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.drawerlayout",
      "name": "drawerlayout",
      "version": "1.1.1",
      "purl": "pkg:maven\/androidx.drawerlayout\/drawerlayout@1.1.1"
    },
    {
      "type": "library",
      "group": "androidx.dynamicanimation",
      "name": "dynamicanimation",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.dynamicanimation\/dynamicanimation@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.emoji2",
      "name": "emoji2-views-helper",
      "version": "1.3.0",
      "purl": "pkg:maven\/androidx.emoji2\/emoji2-views-helper@1.3.0"
    },
    {
      "type": "library",
      "group": "androidx.emoji2",
      "name": "emoji2",
      "version": "1.3.0",
      "purl": "pkg:maven\/androidx.emoji2\/emoji2@1.3.0"
    },
    {
      "type": "library",
      "group": "androidx.exifinterface",
      "name": "exifinterface",
      "version": "1.4.0",
      "purl": "pkg:maven\/androidx.exifinterface\/exifinterface@1.4.0"
    },
    {
      "type": "library",
      "group": "androidx.fragment",
      "name": "fragment-ktx",
      "version": "1.6.2",
      "purl": "pkg:maven\/androidx.fragment\/fragment-ktx@1.6.2"
    },
    {
      "type": "library",
      "group": "androidx.fragment",
      "name": "fragment",
      "version": "1.6.2",
      "purl": "pkg:maven\/androidx.fragment\/fragment@1.6.2"
    },
    {
      "type": "library",
      "group": "androidx.interpolator",
      "name": "interpolator",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.interpolator\/interpolator@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.legacy",
      "name": "legacy-support-core-ui",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.legacy\/legacy-support-core-ui@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.legacy",
      "name": "legacy-support-core-utils",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.legacy\/legacy-support-core-utils@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.legacy",
      "name": "legacy-support-v4",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.legacy\/legacy-support-v4@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.loader",
      "name": "loader",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.loader\/loader@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.localbroadcastmanager",
      "name": "localbroadcastmanager",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.localbroadcastmanager\/localbroadcastmanager@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.media",
      "name": "media",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.media\/media@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-common-ktx",
      "version": "2.8.9",
      "purl": "pkg:maven\/androidx.navigation\/navigation-common-ktx@2.8.9"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-common",
      "version": "2.8.9",
      "purl": "pkg:maven\/androidx.navigation\/navigation-common@2.8.9"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-fragment-ktx",
      "version": "2.8.9",
      "purl": "pkg:maven\/androidx.navigation\/navigation-fragment-ktx@2.8.9"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-fragment",
      "version": "2.8.9",
      "purl": "pkg:maven\/androidx.navigation\/navigation-fragment@2.8.9"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-runtime-ktx",
      "version": "2.8.9",
      "purl": "pkg:maven\/androidx.navigation\/navigation-runtime-ktx@2.8.9"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-runtime",
      "version": "2.8.9",
      "purl": "pkg:maven\/androidx.navigation\/navigation-runtime@2.8.9"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-ui-ktx",
      "version": "2.8.9",
      "purl": "pkg:maven\/androidx.navigation\/navigation-ui-ktx@2.8.9"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-ui",
      "version": "2.8.9",
      "purl": "pkg:maven\/androidx.navigation\/navigation-ui@2.8.9"
    },
    {
      "type": "library",
      "group": "androidx.print",
      "name": "print",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.print\/print@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.profileinstaller",
      "name": "profileinstaller",
      "version": "1.4.0",
      "purl": "pkg:maven\/androidx.profileinstaller\/profileinstaller@1.4.0"
    },
    {
      "type": "library",
      "group": "androidx.recyclerview",
      "name": "recyclerview",
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.recyclerview\/recyclerview@1.1.0"
    },
    {
      "type": "library",
      "group": "androidx.savedstate",
      "name": "savedstate-ktx",
      "version": "1.2.1",
      "purl": "pkg:maven\/androidx.savedstate\/savedstate-ktx@1.2.1"
    },
    {
      "type": "library",
      "group": "androidx.savedstate",
      "name": "savedstate",
      "version": "1.2.1",
      "purl": "pkg:maven\/androidx.savedstate\/savedstate@1.2.1"
    },
    {
      "type": "library",
      "group": "androidx.security",
      "name": "security-crypto",
      "version": "1.1.0-alpha06",
      "purl": "pkg:maven\/androidx.security\/security-crypto@1.1.0-alpha06"
    },
    {
      "type": "library",
      "group": "androidx.slidingpanelayout",
      "name": "slidingpanelayout",
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.slidingpanelayout\/slidingpanelayout@1.2.0"
    },
    {
      "type": "library",
      "group": "androidx.startup",
      "name": "startup-runtime",
      "version": "1.1.1",
      "purl": "pkg:maven\/androidx.startup\/startup-runtime@1.1.1"
    },
    {
      "type": "library",
      "group": "androidx.swiperefreshlayout",
      "name": "swiperefreshlayout",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.swiperefreshlayout\/swiperefreshlayout@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.tracing",
      "name": "tracing",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.tracing\/tracing@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.transition",
      "name": "transition",
      "version": "1.5.0",
      "purl": "pkg:maven\/androidx.transition\/transition@1.5.0"
    },
    {
      "type": "library",
      "group": "androidx.vectordrawable",
      "name": "vectordrawable-animated",
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.vectordrawable\/vectordrawable-animated@1.2.0"
    },
    {
      "type": "library",
      "group": "androidx.vectordrawable",
      "name": "vectordrawable",
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.vectordrawable\/vectordrawable@1.2.0"
    },
    {
      "type": "library",
      "group": "androidx.versionedparcelable",
      "name": "versionedparcelable",
      "version": "1.1.1",
      "purl": "pkg:maven\/androidx.versionedparcelable\/versionedparcelable@1.1.1"
    },
    {
      "type": "library",
      "group": "androidx.viewpager2",
      "name": "viewpager2",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.viewpager2\/viewpager2@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.viewpager",
      "name": "viewpager",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.viewpager\/viewpager@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.window",
      "name": "window",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.window\/window@1.0.0"
    },
    {
      "type": "library",
      "group": "com.google.android.material",
      "name": "material",
      "version": "1.12.0",
      "purl": "pkg:maven\/com.google.android.material\/material@1.12.0"
    },
    {
      "type": "library",
      "group": "kotlinx",
      "name": "coroutines_android",
      "version": "1.7.3",
      "purl": "pkg:maven\/kotlinx\/coroutines_android@1.7.3"
    },
    {
      "type": "library",
      "group": "kotlinx",
      "name": "coroutines_core",
      "version": "1.7.3",
      "purl": "pkg:maven\/kotlinx\/coroutines_core@1.7.3"
    },
    {
      "type": "library",
      "group": "kotlinx",
      "name": "coroutines_play_services",
      "version": "1.7.3",
      "purl": "pkg:maven\/kotlinx\/coroutines_play_services@1.7.3"
    },
    {
      "type": "library",
      "group": "com.squareup.okhttp3",
      "name": "okhttp",
      "version": "4.9.0",
      "purl": "pkg:maven\/com.squareup.okhttp3\/okhttp@4.9.0"
    },
    {
      "type": "library",
      "group": "androidx",
      "name": "androidx-libraries",
      "properties": [
        {
          "name": "apkrelab:detection",
          "value": "package path; version unknown; artifact id is a best guess"
        }
      ],
      "purl": "pkg:maven\/androidx\/androidx-libraries"
    },
    {
      "type": "library",
      "group": "com.google.android.gms",
      "name": "play-services",
      "properties": [
        {
          "name": "apkrelab:detection",
          "value": "package path; version unknown; artifact id is a best guess"
        }
      ],
      "purl": "pkg:maven\/com.google.android.gms\/play-services"
    },
    {
      "type": "library",
      "group": "com.google.guava",
      "name": "guava",
      "properties": [
        {
          "name": "apkrelab:detection",
          "value": "package path; version unknown; artifact id is a best guess"
        }
      ],
      "purl": "pkg:maven\/com.google.guava\/guava"
    },
    {
      "type": "library",
      "group": "com.google.firebase",
      "name": "firebase-common",
      "properties": [
        {
          "name": "apkrelab:detection",
          "value": "package path; version unknown; artifact id is a best guess"
        }
      ],
      "purl": "pkg:maven\/com.google.firebase\/firebase-common"
    },
    {
      "type": "library",
      "group": "com.google.code.gson",
      "name": "gson",
      "properties": [
        {
          "name": "apkrelab:detection",
          "value": "package path; version unknown; artifact id is a best guess"
        }
      ],
      "purl": "pkg:maven\/com.google.code.gson\/gson"
    },
    {
      "type": "library",
      "group": "com.squareup.okio",
      "name": "okio",
      "properties": [
        {
          "name": "apkrelab:detection",
          "value": "package path; version unknown; artifact id is a best guess"
        }
      ],
      "purl": "pkg:maven\/com.squareup.okio\/okio"
    }
  ]
}
```

## Edited classes (0)

None.

## AI notes (this session)

None. Use Explain / Patterns / Review manifest first and they will be included.
