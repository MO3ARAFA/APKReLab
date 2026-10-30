# APK ReLab report: com.withsecure.example.sieve

> Educational static analysis. Use only on apps you own or are allowed to analyze.

## App info

```
Package: com.withsecure.example.sieve
Size: 7.2 MB | Files: 940
DEX: 1 (classes.dex 9.8 MB)
```

## AndroidManifest.xml

```xml
<?xml version='1.0' encoding='utf-8' ?>
<manifest android:versionCode="1"
          android:versionName="1.0"
          android:compileSdkVersion="34"
          android:compileSdkVersionCodename="14"
          package="com.withsecure.example.sieve"
          platformBuildVersionCode="34"
          platformBuildVersionName="14" xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-sdk android:minSdkVersion="17"
            android:targetSdkVersion="28" />
  <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
  <uses-permission android:name="android.permission.INTERNET" />
  <permission android:name="com.withsecure.example.sieve.READ_KEYS"
              android:protectionLevel="dangerous" />
  <permission android:name="com.withsecure.example.sieve.WRITE_KEYS"
              android:protectionLevel="dangerous" />
  <permission android:name="com.withsecure.example.sieve.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
              android:protectionLevel="signature" />
  <uses-permission android:name="com.withsecure.example.sieve.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" />
  <application android:theme="@style/Theme.Sieve"
               android:label="@string/app_name"
               android:icon="@mipmap/ic_launcher"
               android:debuggable="true"
               android:allowBackup="true"
               android:supportsRtl="true"
               android:extractNativeLibs="true"
               android:fullBackupContent="@xml/backup_rules"
               android:appComponentFactory="androidx.core.app.CoreComponentFactory"
               android:dataExtractionRules="@xml/data_extraction_rules">
    <activity android:label="@string/app_name"
              android:name="com.withsecure.example.sieve.activity.MainLoginActivity"
              android:exported="true"
              android:launchMode="singleTask"
              android:windowSoftInputMode="adjustResize|stateVisible">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <activity android:label="@string/title_activity_file_select"
              android:name="com.withsecure.example.sieve.activity.FileSelectActivity"
              android:exported="true"
              android:clearTaskOnLaunch="true" />
    <activity android:label="@string/title_activity_pwlist"
              android:name="com.withsecure.example.sieve.activity.PWList"
              android:exported="true"
              android:clearTaskOnLaunch="true" />
    <activity android:label="@string/title_activity_settings"
              android:name="com.withsecure.example.sieve.activity.SettingsActivity"
              android:clearTaskOnLaunch="true" />
    <activity android:label="@string/title_activity_add_entry"
              android:name="com.withsecure.example.sieve.activity.AddEntryActivity"
              android:clearTaskOnLaunch="true" />
    <activity android:label="@string/title_activity_short_login"
              android:name="com.withsecure.example.sieve.activity.ShortLoginActivity"
              android:clearTaskOnLaunch="true" />
    <activity android:label="@string/title_activity_welcome"
              android:name="com.withsecure.example.sieve.activity.WelcomeActivity"
              android:clearTaskOnLaunch="true" />
    <activity android:label="@string/title_activity_pin"
              android:name="com.withsecure.example.sieve.activity.PINActivity"
              android:clearTaskOnLaunch="true" />
    <service android:name="com.withsecure.example.sieve.service.AuthService"
             android:exported="true"
             android:process=":remote" />
    <service android:name="com.withsecure.example.sieve.service.CryptoService"
             android:exported="true"
             android:process=":remote" />
    <provider android:name="com.withsecure.example.sieve.provider.DBContentProvider"
              android:exported="true"
              android:multiprocess="true"
              android:authorities="com.withsecure.example.sieve.provider.DBContentProvider">
      <path-permission android:readPermission="com.withsecure.example.sieve.READ_KEYS"
                       android:writePermission="com.withsecure.example.sieve.WRITE_KEYS"
                       android:path="/Keys" />
      <path-permission android:readPermission="com.withsecure.example.sieve.READ_KEYS"
                       android:writePermission="com.withsecure.example.sieve.WRITE_KEYS"
                       android:path="/Keys/*" />
    </provider>
    <provider android:name="com.withsecure.example.sieve.provider.FileBackupProvider"
              android:exported="true"
              android:multiprocess="true"
              android:authorities="com.withsecure.example.sieve.provider.FileBackupProvider" />
    <provider android:name="androidx.startup.InitializationProvider"
              android:exported="false"
              android:authorities="com.withsecure.example.sieve.androidx-startup">
      <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer"
                 android:value="androidx.startup" />
      <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer"
                 android:value="androidx.startup" />
      <meta-data android:name="androidx.profileinstaller.ProfileInstallerInitializer"
                 android:value="androidx.startup" />
    </provider>
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

Exported components (reachable by other apps): **8** - requested permissions: **3**

| Component | Kind | Intent-filter actions |
|---|---|---|
| `com.withsecure.example.sieve.activity.MainLoginActivity` | activity | MAIN |
| `com.withsecure.example.sieve.activity.FileSelectActivity` | activity | - |
| `com.withsecure.example.sieve.activity.PWList` | activity | - |
| `com.withsecure.example.sieve.service.AuthService` | service | - |
| `com.withsecure.example.sieve.service.CryptoService` | service | - |
| `com.withsecure.example.sieve.provider.DBContentProvider` | provider | - |
| `com.withsecure.example.sieve.provider.FileBackupProvider` | provider | - |
| `androidx.profileinstaller.ProfileInstallReceiver` | receiver | INSTALL_PROFILE, SKIP_FILE, SAVE_PROFILE, BENCHMARK_OPERATION |

**Permissions:** INTERNET, POST_NOTIFICATIONS, com.withsecure.example.sieve.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION

## Security scan

Deep scan status: finished, 6580 / 6580 classes; SSA taint: no extra flow (taint losses real/param-only: callee not analysed 0/2, app method unresolved 0/111, library or outside group 2/173 (top owners of real drops: android/content/ContentUris 2); caps hit: sink refs 0, rounds 0 method(s), requeue 0 method(s), ~ sites 0; slowest methods: AddEntryActivity.onCreate(Landroid/os/Bundle;)V 8ms [83 insns, 2 rounds, 1 runs], SettingsActivity.onCreate(Landroid/os/Bundle;)V 4ms [144 insns, 1 rounds, 2 runs], NetBackupHandler$NetBackup.doInBackground([Ljava/lang/String;)Ljava/lang/Void; 3ms [66 insns, 2 rounds, 2 runs], SettingsActivity.getBackup()V 2ms [76 insns, 2 rounds, 2 runs], PWList.onCreate(Landroid/os/Bundle;)V 2ms [65 insns, 2 rounds, 2 runs])

Heuristic static scan - 38 finding(s) in total; 28 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| CRITICAL | 2 |
| HIGH | 4 |
| MEDIUM | 16 |
| LOW | 6 |

**OWASP Mobile Top 10 (2024) coverage**

- M8 Security Misconfiguration: 12
- M9 Insecure Data Storage: 9
- M4 Insufficient Input/Output Validation: 3
- M5 Insecure Communication: 2
- Not mapped: 2

### Findings

#### 1. [CRITICAL] TLS certificate validation disabled

- Location: `com.withsecure.example.sieve.util.NetBackupHandler$1`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: tls-trustmanager | Scope: APP
- Priority: 63/100 (P2)
- AI triage: NEEDS REVIEW - The checkServerTrusted implementation is empty, which unconditionally trusts all server certificates and enables Man-in-the-Middle attacks. Fix: Implement proper certificate validation logic inside checkServerTrusted by throwing a CertificateException for untrusted certificates or utilizing the default TrustManager. (confidence 70%) ⚖️ Council disagreed (downgraded to REVIEW): The empty checkServerTrusted is in an example package with no demonstrated path from exported components; attacker-controlled input is not shown to reach this code.
- Why flagged: This class implements X509TrustManager, and checkServerTrusted() returns right after its locals/param declarations with no verification call in between - it accepts ANY certificate, attacker's included.  (around line 53)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Remove the custom TrustManager and use the platform default (or pin to the real certificate/public key via a network security config); never ship a no-op trust manager.

#### 2. [CRITICAL] Debuggable build

- Location: `AndroidManifest.xml`
- CWE: CWE-489 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-RESILIENCE | Confidence: HIGH | Rule: manifest-debuggable
- Priority: 90/100 (P1)
- Why flagged: android:debuggable="true" is set. Anyone with the APK (or USB access to the device) can attach a debugger, set breakpoints, dump memory, or step through the logic - including past client-side checks.
- Risk scenario: A debuggable app lets anyone attach a debugger, run code inside the process and read its private data; WebView debugging exposes pages and JS state over USB. android:testOnly marks a test build that may carry relaxed checks and must not be shipped.
- Fix: Remove android:debuggable, or make sure it is only true in debug build variants and never in what you ship/test for release.

#### 3. [HIGH] Untrusted input reaches an SQL statement (x3)

- Location: `com.withsecure.example.sieve.provider.DBContentProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 60/100 (P2)
- Call path: Entry: exported provider com.withsecure.example.sieve.provider.DBContentProvider | Path: com.withsecure.example.sieve.provider.DBContentProvider.delete()
- AI triage: TRUE POSITIVE - The delete() method of an exported ContentProvider directly passes the untrusted selection and selectionArgs parameters to SQLiteDatabase.delete() without sanitization, allowing SQL injection if another application invokes this provider with malicious input. Fix: Validate or parameterize the selection and selectionArgs inputs, or restrict access to the ContentProvider using proper Android permissions. (confidence 70%) ⚖️ Council confirmed: The critic (Gemini/gemini-3.6-flash) agreed: The selection parameter from the exported ContentProvider method is passed directly as the whereClause to SQLiteDatabase.delete() without validation or sanitization, allowing arbitrary SQL manipulatio
- Why flagged: Data from a ContentProvider method parameter (other apps can call it when the provider is exported) reaches SQLiteDatabase.delete() in method delete(): the table or the WHERE clause contains the input. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way.  (around line 121)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 4. [HIGH] ContentProvider.openFile builds a path from the URI

- Location: `com.withsecure.example.sieve.provider.FileBackupProvider`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: provider-openfile-segment | Scope: APP | Reachable from an exported component
- Priority: 60/100 (P2)
- Call path: Entry: exported provider com.withsecure.example.sieve.provider.FileBackupProvider | Path: com.withsecure.example.sieve.provider.FileBackupProvider.openFile()
- AI triage: TRUE POSITIVE - The ContentProvider's openFile method directly uses uri.getPath() to construct a File object without canonicalization or validation, allowing path traversal (CWE-22) via malicious intents since the component is exported. Fix: Canonicalize the resulting file path and verify that it strictly resides within the intended base directory before opening the ParcelFileDescriptor. (confidence 70%) ⚖️ Council confirmed: The critic (OpenRouter/nvidia/nemotron-3-ultra-550b-a55b:free) agreed: Exported ContentProvider.openFile() uses uri.getPath() directly to create a File without canonicalization or path validation, allowing directory traversal via ../ sequences. Modes 'rw' and 'rwt' enabl
- Why flagged: openFile() creates a File from the URI (getPath) without canonicalising it. A caller can pass an encoded ../ in the URI to reach any file the app can open, and the mode argument is not restricted to read-only, so the same bug can overwrite files.  (around line 140)  Also matched by: androgoat-checks (merged).  Also matched by: taint-flow (merged).
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Resolve the file inside a fixed directory, call getCanonicalPath() and check it still starts with that directory, and reject modes other than "r" unless writing is intended.

#### 5. [HIGH] Exported provider without a permission: com.withsecure.example.sieve.provider.DBContentProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 70/100 (P1)
- Why flagged: This provider is exported (usable by other apps) and declares no android:permission. A ContentProvider exported with no permission can let any app on the device query/insert/update/delete its data; if it builds file paths or SQL from the incoming Uri, that's also a path-traversal / SQL-injection surface.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 6. [HIGH] Exported provider without a permission: com.withsecure.example.sieve.provider.FileBackupProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 70/100 (P1)
- Why flagged: This provider is exported (usable by other apps) and declares no android:permission. A ContentProvider exported with no permission can let any app on the device query/insert/update/delete its data; if it builds file paths or SQL from the incoming Uri, that's also a path-traversal / SQL-injection surface.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 7. [MEDIUM] Sensitive data stored in plain SQLite (x2)

- Location: `com.withsecure.example.sieve.util.PWDBHelper`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: sqlite-unencrypted | Scope: APP
- Priority: 31/100 (P3)
- AI triage: TRUE POSITIVE - The `onCreate` method initializes an unencrypted SQLite database (`Passwords` and `Key` tables) to store sensitive information like passwords and pins without applying any cryptographic protection. Fix: Use SQLCipher for Android to encrypt the SQLite database or store sensitive data securely using the Android Keystore system and EncryptedSharedPreferences. (confidence 90%) ⚖️ Council confirmed: The critic (OpenRouter/nvidia/nemotron-3-ultra-550b-a55b:free) agreed: The onCreate method defines a schema that stores master passwords and PINs in plaintext (TEXT columns) and passwords as BLOB without any encryption at the database level. The database uses standard SQ
- Why flagged: Private data is written to a plain (unencrypted) SQLite database: the column "Passwords" (CREATE TABLE). The database file sits in /data/data/<package>/databases and is readable on a rooted device, from an adb backup (allowBackup) or a forensic image. No hash or cipher call was seen on the value in this method (SSA backward slice; values from other methods are not followed).  (around line 39)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not keep credentials in a database at all (store a salted hash or a revocable token). For private data use SQLCipher (net.zetetic:sqlcipher-android) or encrypt the values with a key from the Android Keystore; set allowBackup=false or exclude the database from backups.

#### 8. [MEDIUM] Credentials may be written to the log

- Location: `com.withsecure.example.sieve.activity.MainLoginActivity`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: log-credential-object | Scope: APP | Reachable from an exported component
- Priority: 38/100 (P3)
- Call path: Entry: exported activity com.withsecure.example.sieve.activity.MainLoginActivity (launcher) | Path: com.withsecure.example.sieve.activity.MainLoginActivity.login()
- AI triage: TRUE POSITIVE - The login method explicitly reads the user-entered password into workingPassword and writes it directly to Logcat using Log.d, exposing sensitive credentials (CWE-532). Fix: Remove the logging statement that appends the workingPassword variable before building and outputting the log message. (confidence 95%) ⚖️ Council confirmed: The critic (OpenRouter/nvidia/nemotron-3-ultra-550b-a55b:free) agreed: The smali shows a direct, unguarded flow: user input from EditText is stored in workingPassword, appended to a StringBuilder, and passed to Log.d. The password is attacker-controlled, the logging call
- Why flagged: This method builds a log message with a StringBuilder and writes it with Log.d(). Credential-like field(s) read into the message: workingPassword. Logcat can be read over adb and, on older Android versions, by other apps.  (around line 379)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Remove the log call or log only a non-sensitive id; never put a login/credential object in a message, and strip debug logging from release builds (R8 -assumenosideeffects).

#### 9. [MEDIUM] Data copied to clipboard

- Location: `com.withsecure.example.sieve.activity.PWList`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP | Reachable from an exported component
- Priority: 45/100 (P2)
- Call path: Entry: exported activity com.withsecure.example.sieve.activity.PWList | Path: com.withsecure.example.sieve.activity.PWList.decryptionReturned()
- AI triage: TRUE POSITIVE - Decrypted password data is written directly to the global system clipboard inside sswitch_4, allowing any malicious app with clipboard access or third-party keyboard/clipboard managers to read sensitive credentials (CWE-200). Fix: Avoid copying sensitive credentials to the system clipboard; if necessary, use Android's sensitive content flags or automatically clear the clipboard after a short timeout. (confidence 90%)
- Why flagged: The app puts data on the system clipboard close to credential-like names. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 465)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 10. [MEDIUM] Untrusted input chooses the file or content URI the app opens

- Location: `com.withsecure.example.sieve.activity.SettingsActivity`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 38/100 (P3)
- Call path: Entry: exported activity com.withsecure.example.sieve.activity.FileSelectActivity | Path: com.withsecure.example.sieve.activity.FileSelectActivity.cancel() -> com.withsecure.example.sieve.activity.SettingsActivity.restoreFromFile()
- AI triage: NEEDS REVIEW - The parameter 'filename' is passed into restoreFromFile and appended to a Uri without validation, but its entry point and origin cannot be fully verified from the provided code snippet alone. Fix: Validate and sanitize the input string to ensure it contains only expected relative file names and does not allow path traversal before appending it to the Uri. (confidence 65%)
- Why flagged: Data from Intent.getStringExtra() reaches ContentResolver.openInputStream() in method restoreFromFile(): the caller picks the URI the app reads, so a file:// URI makes the app read its own private files. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.  (around line 1038)
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

#### 11. [MEDIUM] Sensitive value written to SQLite (plaintext)

- Location: `com.withsecure.example.sieve.util.PWDBHelper`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP
- Priority: 27/100 (P3)
- AI triage: TRUE POSITIVE - The method creates SQLite tables designed to store plaintext passwords and PINs without encryption, which violates CWE-312 on rooted or backup-enabled devices. Fix: Migrate from plaintext SQLite to EncryptedSharedPreferences or SQLCipher to ensure database contents are encrypted at rest. (confidence 90%)
- Why flagged: An SQL statement in this class creates or fills a table with a credential-like column. SQLite files are unencrypted and readable on rooted devices or from a backup.  (around line 37)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords in SQLite; if you must keep sensitive columns use SQLCipher or encrypt the values with a Keystore key.

#### 12. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_add_entry.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f08004c") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 17: devices below Android 12 do not block touches through overlays.  [res/layout/activity_add_entry.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 13. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_main_login.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f080101") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 17: devices below Android 12 do not block touches through overlays.  [res/layout/activity_main_login.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 14. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_pin.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f080173") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 17: devices below Android 12 do not block touches through overlays.  [res/layout/activity_pin.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 15. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_short_login.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f0801a5") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 17: devices below Android 12 do not block touches through overlays.  [res/layout/activity_short_login.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 16. [MEDIUM] Password screen not protected against tapjacking

- Location: `res/layout/activity_welcome.xml`
- CWE: CWE-1021 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: tapjacking-sensitive-layout
- Priority: 38/100 (P3)
- Why flagged: This layout has a password field ("@0x7f080218") and no view in it sets android:filterTouchesWhenObscured="true", so a malicious overlay can sit on top of the screen and the field still receives the taps (tapjacking). No code mitigation (setFilterTouchesWhenObscured, onFilterTouchEventForSecurity, setHideOverlayWindows) is referenced anywhere in the app's dex. minSdkVersion is 17: devices below Android 12 do not block touches through overlays.  [res/layout/activity_welcome.xml]
- Risk scenario: A malicious app draws a transparent or misleading overlay on top of a login or payment screen; the user's taps go through to the real buttons or the overlay captures what is typed.
- Fix: Set android:filterTouchesWhenObscured="true" on the root of this layout (or call setFilterTouchesWhenObscured(true) on it / getWindow().setHideOverlayWindows(true) on API 31+ in the Activity).

#### 17. [MEDIUM] Backup allowed (allowBackup)

- Location: `AndroidManifest.xml`
- CWE: CWE-530 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-allow-backup
- Priority: 45/100 (P2)
- Why flagged: android:allowBackup is not explicitly "false" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.
- Risk scenario: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.
- Fix: Set android:allowBackup="false", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.

#### 18. [MEDIUM] Exported activity without a permission: com.withsecure.example.sieve.activity.FileSelectActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 19. [MEDIUM] Exported activity without a permission: com.withsecure.example.sieve.activity.PWList

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 20. [MEDIUM] Exported service without a permission: com.withsecure.example.sieve.service.AuthService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 21. [MEDIUM] Exported service without a permission: com.withsecure.example.sieve.service.CryptoService

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This service is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 22. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/material_time_input.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/material_time_input.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 23. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/mtrl_picker_text_input_date.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (0x14) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/mtrl_picker_text_input_date.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 24. [LOW] Keyboard cache: sensitive input field

- Location: `res/layout/mtrl_picker_text_input_date_range.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (0x14) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/layout/mtrl_picker_text_input_date_range.xml]
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 25. [LOW] No network security config referenced

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: MEDIUM | Rule: manifest-network-security-config
- Priority: 17/100 (P4)
- Why flagged: No android:networkSecurityConfig is set. On devices running API < 28, cleartext HTTP is allowed by default unless a config says otherwise, so this app's real cleartext posture on older phones is unverified here.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Add a network_security_config.xml with cleartextTrafficPermitted="false" as the base config (and certificate pinning if the app always talks to the same backend).

#### 26. [LOW] Low minSdkVersion (17)

- Location: `AndroidManifest.xml`
- Confidence: LOW | Rule: manifest-min-sdk
- Priority: 12/100 (P4)
- Why flagged: Supporting API < 23 (Android 6) means the app can run on devices without runtime permission prompts and with older TLS/cipher defaults.
- Fix: Raise minSdkVersion if the user base allows it; otherwise double check that sensitive permissions and network calls are still handled safely on the oldest supported devices.

#### 27. [LOW] Old targetSdkVersion (28)

- Location: `AndroidManifest.xml`
- Confidence: LOW | Rule: manifest-target-sdk
- Priority: 12/100 (P4)
- Why flagged: The app targets API 28, so Android keeps legacy behaviour for it, components with an intent-filter are exported by default and PendingIntents are mutable by default, and newer privacy / storage protections do not apply to it.
- Fix: Raise targetSdkVersion to a current API level and re-test; this is the cheapest way to get many OS-level protections.

#### 28. [MEDIUM] Sensitive value written to log

- Location: `com.withsecure.example.sieve.service.AuthService$MessageHandler`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP | Reachable from an exported component
- Priority: 38/100 (P3)
- Call path: Entry: exported service com.withsecure.example.sieve.service.AuthService | Path: com.withsecure.example.sieve.service.AuthService$MessageHandler.handleMessage()
- AI triage: FALSE POSITIVE - The static analysis tool incorrectly flagged line 215 based on the presence of credential-like string constants ('com.withsecure.example.sieve.PIN'), but the actual log call in this method only logs static error messages and unrecognized command integers, not sensitive data. Fix: No fix is required as sensitive data is not actually being written to the logcat in this method. (confidence 90%)
- Why flagged: A log call is built from a credential-like label ("com.withsecure.example.sieve.P") plus an appended variable. Logcat can be read from a computer over ADB, and by other apps on some devices.  (around line 215)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Never log passwords, tokens, or personal data; strip such Log calls from release builds.

### Remediation guide

One entry per weakness type found above.

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

#### CWE-22 - Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE

Risk: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).

Vulnerable:

```kotlin
val out = File(dir, entry.name)            // entry.name may contain ../
```

Secure:

```kotlin
val out = File(dir, entry.name).canonicalFile
if (!out.path.startsWith(dir.canonicalPath + File.separator)) throw SecurityException("bad path")
```

References: [CWE-22 (MITRE)](https://cwe.mitre.org/data/definitions/22.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-73 - External Control of File Name or Path

OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE

Risk: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.

Vulnerable:

```kotlin
val uri = intent.getParcelableExtra<Uri>("uri"); contentResolver.openInputStream(uri!!)
```

Secure:

```kotlin
val uri = intent.getParcelableExtra<Uri>("uri")
if (uri?.scheme == "content" && uri.authority in ALLOWED_AUTHORITIES) contentResolver.openInputStream(uri)
```

References: [CWE-73 (MITRE)](https://cwe.mitre.org/data/definitions/73.html) | [Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

## Third-Party Libraries & SCA

38 component(s) detected in the APK (META-INF version files, pom.properties, native .so strings, dex strings, package-path heuristics). **0 vulnerable / outdated, 2 with unknown version (NOT checked against CVEs).** Libraries detected only by package path have version `?`: presence is proven, the version is not - they cannot be matched against version-specific CVEs, so this is a lower bound, not proof that nothing else is bundled.

| Component | Version | Status | Known vulnerabilities | Fix | Source |
|---|---|---|---|---|---|
| androidx.activity:activity | 1.8.0 | OK | - | - | version file |
| androidx.annotation:annotation-experimental | 1.3.0 | OK | - | - | version file |
| androidx.appcompat:appcompat | 1.6.1 | OK | - | - | version file |
| androidx.appcompat:appcompat-resources | 1.6.1 | OK | - | - | version file |
| androidx.cardview:cardview | 1.0.0 | OK | - | - | version file |
| androidx.coordinatorlayout:coordinatorlayout | 1.1.0 | OK | - | - | version file |
| androidx.core:core | 1.9.0 | OK | - | - | version file |
| androidx.core:core-ktx | 1.9.0 | OK | - | - | version file |
| androidx.cursoradapter:cursoradapter | 1.0.0 | OK | - | - | version file |
| androidx.customview:customview | 1.1.0 | OK | - | - | version file |
| androidx.databinding:viewbinding | 8.1.2 | OK | - | - | version file |
| androidx.documentfile:documentfile | 1.0.0 | OK | - | - | version file |
| androidx.drawerlayout:drawerlayout | 1.1.1 | OK | - | - | version file |
| androidx.dynamicanimation:dynamicanimation | 1.0.0 | OK | - | - | version file |
| androidx.emoji2:emoji2 | 1.2.0 | OK | - | - | version file |
| androidx.emoji2:emoji2-views-helper | 1.2.0 | OK | - | - | version file |
| androidx.fragment:fragment | 1.3.6 | OK | - | - | version file |
| androidx.interpolator:interpolator | 1.0.0 | OK | - | - | version file |
| androidx.legacy:legacy-support-core-utils | 1.0.0 | OK | - | - | version file |
| androidx.loader:loader | 1.0.0 | OK | - | - | version file |
| androidx.localbroadcastmanager:localbroadcastmanager | 1.0.0 | OK | - | - | version file |
| androidx.print:print | 1.0.0 | OK | - | - | version file |
| androidx.profileinstaller:profileinstaller | 1.3.0 | OK | - | - | version file |
| androidx.recyclerview:recyclerview | 1.1.0 | OK | - | - | version file |
| androidx.savedstate:savedstate | 1.2.1 | OK | - | - | version file |
| androidx.startup:startup-runtime | 1.1.1 | OK | - | - | version file |
| androidx.tracing:tracing | 1.0.0 | OK | - | - | version file |
| androidx.transition:transition | 1.2.0 | OK | - | - | version file |
| androidx.vectordrawable:vectordrawable | 1.1.0 | OK | - | - | version file |
| androidx.vectordrawable:vectordrawable-animated | 1.1.0 | OK | - | - | version file |
| androidx.versionedparcelable:versionedparcelable | 1.1.1 | OK | - | - | version file |
| androidx.viewpager2:viewpager2 | 1.0.0 | OK | - | - | version file |
| androidx.viewpager:viewpager | 1.0.0 | OK | - | - | version file |
| com.google.guava:guava | ? | UNKNOWN VERSION (CVEs exist for older releases) | CVE-2023-2976 / CVE-2020-8908 | check version, fixed in 32.1.2-android or newer | package path |
| kotlinx:coroutines_android | 1.6.4 | OK | - | - | version file |
| kotlinx:coroutines_core | 1.6.4 | OK | - | - | version file |
| androidx:androidx-libraries | ? | UNKNOWN VERSION | - | - | package path |
| com.google.android.material:material | 1.10.0 | OK | - | - | version file |

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
      "name": "activity",
      "version": "1.8.0",
      "purl": "pkg:maven\/androidx.activity\/activity@1.8.0"
    },
    {
      "type": "library",
      "group": "androidx.annotation",
      "name": "annotation-experimental",
      "version": "1.3.0",
      "purl": "pkg:maven\/androidx.annotation\/annotation-experimental@1.3.0"
    },
    {
      "type": "library",
      "group": "androidx.appcompat",
      "name": "appcompat-resources",
      "version": "1.6.1",
      "purl": "pkg:maven\/androidx.appcompat\/appcompat-resources@1.6.1"
    },
    {
      "type": "library",
      "group": "androidx.appcompat",
      "name": "appcompat",
      "version": "1.6.1",
      "purl": "pkg:maven\/androidx.appcompat\/appcompat@1.6.1"
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
      "group": "androidx.coordinatorlayout",
      "name": "coordinatorlayout",
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.coordinatorlayout\/coordinatorlayout@1.1.0"
    },
    {
      "type": "library",
      "group": "androidx.core",
      "name": "core-ktx",
      "version": "1.9.0",
      "purl": "pkg:maven\/androidx.core\/core-ktx@1.9.0"
    },
    {
      "type": "library",
      "group": "androidx.core",
      "name": "core",
      "version": "1.9.0",
      "purl": "pkg:maven\/androidx.core\/core@1.9.0"
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
      "group": "androidx.databinding",
      "name": "viewbinding",
      "version": "8.1.2",
      "purl": "pkg:maven\/androidx.databinding\/viewbinding@8.1.2"
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
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.emoji2\/emoji2-views-helper@1.2.0"
    },
    {
      "type": "library",
      "group": "androidx.emoji2",
      "name": "emoji2",
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.emoji2\/emoji2@1.2.0"
    },
    {
      "type": "library",
      "group": "androidx.fragment",
      "name": "fragment",
      "version": "1.3.6",
      "purl": "pkg:maven\/androidx.fragment\/fragment@1.3.6"
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
      "name": "legacy-support-core-utils",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.legacy\/legacy-support-core-utils@1.0.0"
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
      "group": "androidx.print",
      "name": "print",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.print\/print@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.profileinstaller",
      "name": "profileinstaller",
      "version": "1.3.0",
      "purl": "pkg:maven\/androidx.profileinstaller\/profileinstaller@1.3.0"
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
      "name": "savedstate",
      "version": "1.2.1",
      "purl": "pkg:maven\/androidx.savedstate\/savedstate@1.2.1"
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
      "group": "androidx.tracing",
      "name": "tracing",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.tracing\/tracing@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.transition",
      "name": "transition",
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.transition\/transition@1.2.0"
    },
    {
      "type": "library",
      "group": "androidx.vectordrawable",
      "name": "vectordrawable-animated",
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.vectordrawable\/vectordrawable-animated@1.1.0"
    },
    {
      "type": "library",
      "group": "androidx.vectordrawable",
      "name": "vectordrawable",
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.vectordrawable\/vectordrawable@1.1.0"
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
      "group": "com.google.android.material",
      "name": "material",
      "version": "1.10.0",
      "purl": "pkg:maven\/com.google.android.material\/material@1.10.0"
    },
    {
      "type": "library",
      "group": "kotlinx",
      "name": "coroutines_android",
      "version": "1.6.4",
      "purl": "pkg:maven\/kotlinx\/coroutines_android@1.6.4"
    },
    {
      "type": "library",
      "group": "kotlinx",
      "name": "coroutines_core",
      "version": "1.6.4",
      "purl": "pkg:maven\/kotlinx\/coroutines_core@1.6.4"
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
      "group": "com.google.guava",
      "name": "guava",
      "properties": [
        {
          "name": "apkrelab:detection",
          "value": "package path; version unknown; artifact id is a best guess"
        }
      ],
      "purl": "pkg:maven\/com.google.guava\/guava"
    }
  ]
}
```

## Edited classes (0)

None.

## AI notes (this session)

None. Use Explain / Patterns / Review manifest first and they will be included.
