# APK ReLab report: com.termux

> Educational static analysis. Use only on apps you own or are allowed to analyze.

## App info

```
Package: com.termux
Size: 1.5 MB | Files: 372
DEX: 1 (classes.dex 1.1 MB)
```

## AndroidManifest.xml

```xml
<?xml version='1.0' encoding='utf-8' ?>
<manifest android:versionCode="142"
          android:versionName="googleplay.2026.10.09"
          android:installLocation="internalOnly"
          android:compileSdkVersion="37"
          android:compileSdkVersionCodename="17"
          android:requiredSplitTypes="base__abi,base__density"
          android:splitTypes=""
          package="com.termux"
          platformBuildVersionCode="37"
          platformBuildVersionName="17" xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-sdk android:minSdkVersion="32"
            android:targetSdkVersion="37" />
  <uses-feature android:name="android.hardware.touchscreen"
                android:required="false" />
  <uses-feature android:name="android.hardware.microphone"
                android:required="false" />
  <uses-feature android:name="android.software.leanback"
                android:required="false" />
  <uses-feature android:name="android.hardware.usb.host"
                android:required="false" />
  <permission android:label="@string/permission_termux_internal_label"
              android:icon="@mipmap/ic_launcher"
              android:name="com.termux.permission.TERMUX_INTERNAL"
              android:protectionLevel="signature"
              android:description="@string/permission_termux_internal_description" />
  <permission android:name="com.termux.sharedfile.READ_WRITE"
              android:protectionLevel="signature" />
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.ACCESS_LOCAL_NETWORK" />
  <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
  <uses-permission android:name="android.permission.WAKE_LOCK" />
  <uses-permission android:name="android.permission.VIBRATE" />
  <uses-permission android:name="android.permission.RECORD_AUDIO" />
  <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
  <uses-permission android:name="android.permission.FOREGROUND_SERVICE_SPECIAL_USE" />
  <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
  <uses-permission android:name="android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS" />
  <uses-permission android:name="com.termux.permission.TERMUX_INTERNAL" />
  <uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE" />
  <queries>
    <package android:name="com.termux.x11" />
    <intent>
      <action android:name="android.speech.RecognitionService" />
    </intent>
  </queries>
  <permission android:name="com.termux.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
              android:protectionLevel="signature" />
  <uses-permission android:name="com.termux.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" />
  <application android:theme="@style/Theme.TermuxActivity.DayNight.NoActionBar"
               android:label="@string/application_name"
               android:icon="@mipmap/ic_launcher"
               android:supportsRtl="false"
               android:banner="@mipmap/banner"
               android:extractNativeLibs="true"
               android:fullBackupContent="@xml/backup"
               android:roundIcon="@mipmap/ic_launcher_round"
               android:appComponentFactory="androidx.core.app.CoreComponentFactory"
               android:requestLegacyExternalStorage="true"
               android:dataExtractionRules="@xml/backup"
               android:enableOnBackInvokedCallback="true">
    <activity android:theme="@style/Theme.TermuxActivity.DayNight.NoActionBar"
              android:name="com.termux.app.TermuxActivity"
              android:exported="true"
              android:launchMode="singleTask"
              android:configChanges="density|keyboard|keyboardHidden|navigation|orientation|screenLayout|screenSize|smallestScreenSize"
              android:resizeableActivity="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LEANBACK_LAUNCHER" />
      </intent-filter>
      <meta-data android:name="android.app.shortcuts"
                 android:resource="@xml/shortcuts" />
    </activity>
    <activity-alias android:name="com.termux.app.TermuxActivityInternal"
                    android:permission="com.termux.permission.TERMUX_INTERNAL"
                    android:exported="true"
                    android:targetActivity="com.termux.app.TermuxActivity" />
    <activity android:name="com.termux.app.TermuxFileReceiverActivity"
              android:exported="true"
              android:taskAffinity="com.termux.filereceiver"
              android:excludeFromRecents="true"
              android:noHistory="true"
              android:resizeableActivity="true">
      <intent-filter>
        <action android:name="android.intent.action.SEND" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="application/*" />
        <data android:mimeType="audio/*" />
        <data android:mimeType="image/*" />
        <data android:mimeType="message/*" />
        <data android:mimeType="multipart/*" />
        <data android:mimeType="text/*" />
        <data android:mimeType="video/*" />
      </intent-filter>
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="application/*" />
        <data android:mimeType="audio/*" />
        <data android:mimeType="image/*" />
        <data android:mimeType="text/*" />
        <data android:mimeType="video/*" />
      </intent-filter>
    </activity>
    <activity android:theme="@android:style/Theme.NoDisplay"
              android:name="com.termux.app.api.TermuxApiPermissionActivity"
              android:exported="false"
              android:excludeFromRecents="true"
              android:noHistory="true" />
    <receiver android:label="@string/title_shortcut_widget_name"
              android:name="com.termux.widget.TermuxWidgetProvider"
              android:exported="false">
      <intent-filter>
        <action android:name="android.appwidget.action.APPWIDGET_UPDATE" />
      </intent-filter>
      <meta-data android:name="android.appwidget.provider"
                 android:resource="@xml/termux_appwidget_info" />
    </receiver>
    <activity android:label="@string/title_single_shortcut_name"
              android:name="com.termux.widget.TermuxCreateShortcutActivity"
              android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.CREATE_SHORTCUT" />
        <category android:name="android.intent.category.DEFAULT" />
      </intent-filter>
    </activity>
    <service android:name="com.termux.widget.TermuxWidgetService"
             android:permission="android.permission.BIND_REMOTEVIEWS"
             android:exported="false" />
    <activity android:theme="@style/DialogTheme"
              android:name="com.termux.app.api.DialogAPI$DialogActivity"
              android:exported="false"
              android:excludeFromRecents="true"
              android:noHistory="true" />
    <activity android:theme="@style/TransparentTheme"
              android:name="com.termux.app.api.SAFAPI$SAFActivity"
              android:exported="false"
              android:excludeFromRecents="true" />
    <activity android:theme="@android:style/Theme.Translucent.NoTitleBar"
              android:name="com.termux.app.api.StorageGetAPI$StorageActivity"
              android:exported="false"
              android:excludeFromRecents="true" />
    <provider android:name="com.termux.app.TermuxDocumentsProvider"
              android:permission="android.permission.MANAGE_DOCUMENTS"
              android:exported="true"
              android:authorities="com.termux.documents"
              android:grantUriPermissions="true">
      <intent-filter>
        <action android:name="android.content.action.DOCUMENTS_PROVIDER" />
      </intent-filter>
    </provider>
    <provider android:name="com.termux.app.TermuxContentProvider"
              android:permission="com.termux.permission.TERMUX_INTERNAL"
              android:exported="true"
              android:authorities="com.termux.files"
              android:grantUriPermissions="true" />
    <provider android:name="com.termux.app.api.ShareAPI$ContentProvider"
              android:permission="com.termux.sharedfile.READ_WRITE"
              android:exported="true"
              android:authorities="com.termux.sharedfile"
              android:grantUriPermissions="true" />
    <receiver android:name="com.termux.app.TermuxOpenReceiver"
              android:exported="false" />
    <service android:name="com.termux.app.TermuxService"
             android:permission="com.termux.permission.TERMUX_INTERNAL"
             android:exported="true"
             android:foregroundServiceType="specialUse">
      <property android:name="android.app.PROPERTY_SPECIAL_USE_FGS_SUBTYPE"
                android:value="As a Linux environment Termux needs to ensure that running tasks are not killed or paused while the app is in the background.                 For example, a user might start a web server that serves HTML pages and then interact with that from the browser app while the Termux                 app is in the background. If the system were to interrupt or defer the Termux app while it is in the background the user                 experience would be negatively affected since the above described use case would be broken." />
    </service>
    <service android:name="com.termux.app.api.JobSchedulerAPI$JobSchedulerService"
             android:permission="android.permission.BIND_JOB_SERVICE" />
    <service android:name="com.termux.app.api.SpeechToTextAPI$SpeechToTextService"
             android:exported="false" />
    <service android:name="com.termux.app.api.MediaPlayerAPI$MediaPlayerService"
             android:exported="false" />
    <service android:name="com.termux.app.api.MicRecorderAPI$MicRecorderService"
             android:exported="false" />
    <receiver android:name="com.termux.app.TermuxBootReceiver"
              android:exported="false">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
      </intent-filter>
    </receiver>
    <meta-data android:name="android.max_aspect"
               android:value="10.0" />
    <meta-data android:name="com.samsung.android.keepalive.density"
               android:value="true" />
    <meta-data android:name="com.samsung.android.multidisplay.keep_process_alive"
               android:value="true" />
    <meta-data android:name="com.sec.android.support.multiwindow"
               android:value="true" />
    <provider android:name="androidx.startup.InitializationProvider"
              android:exported="false"
              android:authorities="com.termux.androidx-startup">
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
    <meta-data android:name="com.android.vending.splits.required"
               android:value="true" />
    <meta-data android:name="com.android.stamp.source"
               android:value="https://play.google.com/store" />
    <meta-data android:name="com.android.stamp.type"
               android:value="STAMP_TYPE_DISTRIBUTION_APK" />
    <meta-data android:name="com.android.vending.splits"
               android:resource="@xml/splits0" />
    <meta-data android:name="com.android.vending.derived.apk.id"
               android:value="3" />
  </application>
</manifest>
```

## Attack surface

Exported components (reachable by other apps): **9** - requested permissions: **13**

| Component | Kind | Intent-filter actions |
|---|---|---|
| `com.termux.app.TermuxActivity` | activity | MAIN |
| `com.termux.app.TermuxActivity` | activity-alias | - |
| `com.termux.app.TermuxFileReceiverActivity` | activity | SEND, VIEW |
| `com.termux.widget.TermuxCreateShortcutActivity` | activity | CREATE_SHORTCUT |
| `com.termux.app.TermuxDocumentsProvider` | provider | DOCUMENTS_PROVIDER |
| `com.termux.app.TermuxContentProvider` | provider | - |
| `com.termux.app.api.ShareAPI$ContentProvider` | provider | - |
| `com.termux.app.TermuxService` | service | - |
| `androidx.profileinstaller.ProfileInstallReceiver` | receiver | INSTALL_PROFILE, SKIP_FILE, SAVE_PROFILE, BENCHMARK_OPERATION |

**Permissions:** ACCESS_LOCAL_NETWORK, FOREGROUND_SERVICE, FOREGROUND_SERVICE_SPECIAL_USE, INTERNET, MANAGE_EXTERNAL_STORAGE, POST_NOTIFICATIONS, RECEIVE_BOOT_COMPLETED, RECORD_AUDIO, REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, VIBRATE, WAKE_LOCK, com.termux.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION, com.termux.permission.TERMUX_INTERNAL

## Security scan

Deep scan status: finished, 996 / 996 classes; SSA taint: +3 flow(s) (taint losses real/param-only: callee not analysed 0/2, app method unresolved 0/0, library or outside group 54/536 (top owners of real drops: android/content/Context 6, android/provider/DocumentsContract 5, android/app/DownloadManager$Request 4, android/app/NotificationManager 4, android/net/LocalSocketAddress 4); caps hit: sink refs 0, rounds 0 method(s), requeue 0 method(s), ~ sites 0; slowest methods: TermuxAppShell$$ExternalSyntheticLambda0.run()V 53ms [338 insns, 3 rounds, 2 runs], TerminalEmulator.processCodePoint(I)V 41ms [1354 insns, 4 rounds, 2 runs], TermuxActivity$1.onReceive(Landroid/content/Context;Landroid/content/Intent;)V 35ms [48 insns, 2 rounds, 2 runs], TermuxService.onStartCommand(Landroid/content/Intent;II)I 31ms [410 insns, 2 rounds, 3 runs], TerminalEmulator.doCsi(I)V 18ms [798 insns, 2 rounds, 2 runs])

Heuristic static scan - 34 finding(s) in total; 29 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

### Summary

| Severity | Count |
|---|---|
| HIGH | 3 |
| MEDIUM | 14 |
| LOW | 12 |

**OWASP Mobile Top 10 (2024) coverage**

- M4 Insufficient Input/Output Validation: 10
- M9 Insecure Data Storage: 10
- M8 Security Misconfiguration: 8
- M5 Insecure Communication: 1

### Findings

#### 1. [HIGH] Untrusted input is used as a file path

- Location: `com.termux.app.TermuxFileReceiverActivity`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 60/100 (P2)
- Call path: Entry: TermuxFileReceiverActivity.onResume()V | Path: TermuxFileReceiverActivity.onResume()V
- AI triage: TRUE POSITIVE - The activity reads a file path directly from an exported Intent's Uri (via getPath()) and passes it to FileInputStream without validation, allowing any caller to supply a file:// URI and read arbitrary files accessible to the app. Fix: Restrict the accepted URI scheme to content:// and use ContentResolver.openInputStream() to safely open the content, or validate that the resolved path stays within an allowed directory. (confidence 90%) ⚖️ Council confirmed: The critic (OpenRouter/nvidia/nemotron-3-super-120b-a12b:free) agreed: The activity is reachable from an exported component, does not validate the Uri scheme, and directly uses the path from Intent.getData() to open a FileInputStream, allowing an attacker to supply a fil
- Why flagged: Data from Intent.getData() reaches FileInputStream.<init>() in method TermuxFileReceiverActivity.onResume()V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.  (around line 1044)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 2. [HIGH] Untrusted input is used as a file path

- Location: `com.termux.app.api.KeystoreAPI$2`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow | Scope: APP
- Priority: 49/100 (P2)
- Note: Not reached from an exported component by method calls or explicit startActivity(new Intent(ctx, X.class)) hops. It can still be reached through implicit Intents with a framework action (VIEW, SEND), string-built ComponentNames or PendingIntents (the call graph follows explicit launches and custom-action implicit Intents only): check who launches this component.
- AI triage: NEEDS REVIEW - The file path is taken directly from an Intent extra without validation, but the Intent's origin is not shown in the provided code and the call graph did not find an exported entry point; further investigation is needed to determine if the component is exported or reachable via deep link. Fix: Validate the file path to prevent directory traversal (e.g., ensure it's within an allowed directory) and verify the component's export status in the manifest. (confidence 40%)
- Why flagged: Data from Intent.getStringExtra() reaches FileInputStream.<init>() in method writeResult(): a file chosen by the caller is read (../ reaches the app's private files). The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.  (around line 227)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 3. [HIGH] Untrusted input is used as a file path

- Location: `com.termux.app.api.StorageGetAPI$StorageActivity`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: HIGH | Rule: taint-flow | Scope: APP
- Priority: 49/100 (P2)
- Note: Not reached from an exported component by method calls or explicit startActivity(new Intent(ctx, X.class)) hops. It can still be reached through implicit Intents with a framework action (VIEW, SEND), string-built ComponentNames or PendingIntents (the call graph follows explicit launches and custom-action implicit Intents only): check who launches this component.
- AI triage: NEEDS REVIEW - The smali snippet shows the sink (FileOutputStream constructor) using the instance field outputFile, but the initialization of that field (likely from Intent extras in onCreate) is not present in the provided code. The static call graph found no exported component reaching this method within 6 hops, yet the component's exported status in the manifest is unknown. Fix: Inspect the onCreate method of StorageActivity to confirm the source of outputFile; if it comes from an Intent extra, validate the path (e.g., canonicalize and ensure it resides in an app-owned directory) before passing it to FileOutputStream. (confidence 50%)
- Why flagged: Data from Intent.getStringExtra() reaches FileOutputStream.<init>() in method onActivityResult(): a file chosen by the caller is written or overwritten. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.  (around line 203)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 4. [MEDIUM] Untrusted input is used as a file path

- Location: `com.termux.app.TermuxAppShell$$ExternalSyntheticLambda0`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 27/100 (P3)
- Call path: Entry: TermuxService.onCreate()V | Path: TermuxService.onCreate()V -> TermuxAppShell$$ExternalSyntheticLambda0.run()V
- AI triage: NEEDS REVIEW - The smali snippet shows FileOutputStream creation and writing but does not show how the zip entry name (v10) is obtained or how the destination File (v11) is constructed from it. The allowlist checks for "bin/", "libexec", "lib/apt/apt-helper" occur after the file is written, not before. Without seeing the path construction logic, exploitability cannot be confirmed. Fix: Review the full run() method to see how ZipEntry.getName() flows into the File path; add path traversal validation (normalize and ensure path stays within target directory) before creating FileOutputStream. (confidence 50%)
- Why flagged: Data from ZipEntry.getName() reaches FileOutputStream.<init>() in method TermuxAppShell$$ExternalSyntheticLambda0.run()V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value is the name of an archive entry. When the archive comes from outside the app (a download, a file another app shares) a name such as ../../x makes the extraction write outside the target folder (Zip Slip): the target path must be checked with getCanonicalPath() against the extraction folder. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.  (around line 1060)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 5. [MEDIUM] Untrusted input is used as a file path

- Location: `com.termux.app.TermuxContentProvider`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 27/100 (P3)
- Call path: Entry: exported provider com.termux.app.TermuxContentProvider | Path: com.termux.app.TermuxContentProvider.openFile()
- AI triage: NEEDS REVIEW - AI said false positive, but an exported component reaches this code (AI verdicts are not stable between runs): look at it yourself. AI reason: The openFile method resolves the requested URI to a canonical path and explicitly checks that it starts with either the app's internal data directory (/data/data/com.termux/files) or the external storage directory before opening the file descriptor, which prevents directory traversal. Fix: No fix required; the existing path validation using getCanonicalPath() and startsWith() against allowlisted base directories is sufficient to mitigate CWE-22. (confidence 80%)
- Why flagged: Data from a ContentProvider method parameter (other apps can call it when the provider is exported) reaches ParcelFileDescriptor.open() in method openFile(): a file chosen by the caller is handed out as a descriptor. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way. The method also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.  (around line 602)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 6. [MEDIUM] Untrusted input chooses the file or content URI the app opens

- Location: `com.termux.app.TermuxFileReceiverActivity`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 38/100 (P3)
- Call path: Entry: exported activity com.termux.app.TermuxFileReceiverActivity | Path: com.termux.app.TermuxFileReceiverActivity.handleContentUri()
- AI triage: TRUE POSITIVE - The exported TermuxFileReceiverActivity receives an attacker-controlled URI via Intent extra, passes it to handleContentUri, which calls ContentResolver.openInputStream without validating the URI scheme, allowing file:// URIs to read the app's private files. Fix: Add a scheme check (e.g., only allow content://) before calling openInputStream, and consider using FLAG_GRANT_READ_URI_PERMISSION with content URIs. (confidence 65%) ⚖️ Council confirmed: The critic (Gemini/gemini-3.5-flash-lite) agreed: The activity is exported and accepts URIs from external intents. Without checking if the URI points to private application files (e.g. file:// or arbitrary paths), opening the stream via ContentResolv
- Why flagged: Data from Intent.getParcelableExtra() reaches ContentResolver.openInputStream() in method handleContentUri(): the caller picks the URI the app reads, so a file:// URI makes the app read its own private files. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field.  (around line 329)
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

#### 7. [MEDIUM] Shell command execution

- Location: `com.termux.app.TermuxService`
- CWE: CWE-78 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: MEDIUM | Rule: shell-exec | Scope: APP | Reachable from an exported component
- Priority: 38/100 (P3)
- Call path: Entry: exported service com.termux.app.TermuxService | Path: com.termux.app.TermuxService.onStartCommand()
- AI triage: NEEDS REVIEW - The command executed via Runtime.exec is built from SAFAPI.setupShellCommandArguments which processes the incoming Intent; since the service is exported, an attacker could potentially influence the command, but the actual command construction logic is not visible in the provided snippet. Fix: Review SAFAPI.setupShellCommandArguments to ensure user-supplied Intent extras are not directly concatenated into the command array without validation; use allow-lists or avoid shell execution. (confidence 60%)
- Why flagged: The app runs an OS command via Runtime.exec/ProcessBuilder. If any part of that command comes from user input, an Intent extra, or a server response, this is a command-injection surface.  (around line 2604)
- Risk scenario: If any part of the command text is attacker-influenced, extra commands can be appended and run with the app's privileges (or root on a rooted device).
- Fix: Trace where the command string comes from; avoid building it from untrusted input, or use a fixed allow-list of arguments instead of a shell string.

#### 8. [MEDIUM] Untrusted input is used as a file path

- Location: `com.termux.app.api.SAFAPI`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-xclass | Scope: APP | Reachable from an exported component
- Priority: 27/100 (P3)
- Call path: Entry: exported service com.termux.app.TermuxService | Path: com.termux.app.TermuxService.createTermuxSession() -> com.termux.app.api.SAFAPI.setupShellCommandArguments()
- AI triage: NEEDS REVIEW - The static analysis points to an untrusted file path derived from Intent.getData() reaching FileInputStream, but the provided Smali snippet only shows the method receiving a File parameter without validating its source. Fix: Ensure that any file path received via Intent.getData() is validated against path traversal attacks (such as using getCanonicalPath() to restrict access within allowed directories) before passing it to FileInputStream. (confidence 50%)
- Why flagged: Data from Intent.getData() in TermuxService.onStartCommand() crosses 1 method call(s) between classes (TermuxService.onStartCommand() -> SAFAPI.setupShellCommandArguments()) and reaches FileInputStream.<init>() in SAFAPI.setupShellCommandArguments(): a file chosen by the caller is read (../ reaches the app's private files). Each hop is a per-method summary: calls are matched by the class named in the invoke (virtual / interface dispatch, lambdas, reflection and fields of other classes are not followed) and no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The sink method also contains validation-like calls (startsWith, matches, getHost, canonical path ...): verify that they really restrict this value.  (around line 8486)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 9. [MEDIUM] Untrusted input is used as a file path

- Location: `com.termux.app.api.ShareAPI$ContentProvider`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 27/100 (P3)
- Call path: Entry: exported provider com.termux.app.api.ShareAPI$ContentProvider | Path: com.termux.app.api.ShareAPI$ContentProvider.openFile()
- AI triage: TRUE POSITIVE - The exported ContentProvider's openFile() method uses the caller-supplied Uri path directly to create a File and open a ParcelFileDescriptor without validating that the resolved canonical path stays within an allowed directory, enabling path traversal by any app that calls the provider. Fix: Restrict file access to a specific safe directory (e.g., getFilesDir() or a dedicated shared folder) by checking that the canonical path starts with the allowed base path before calling ParcelFileDescriptor.open(). (confidence 70%) ⚖️ Council confirmed: The critic (Gemini/gemini-3.5-flash-lite) agreed: The code uses the path from the incoming Uri directly to instantiate a File and opens it via ParcelFileDescriptor without validating whether it resides within an intended safe directory, creating a pa
- Why flagged: Data from a ContentProvider method parameter (other apps can call it when the provider is exported) reaches ParcelFileDescriptor.open() in method openFile(): a file chosen by the caller is handed out as a descriptor. The value was followed through registers, fields and calls inside this class and no sanitizer was seen on the way. The method also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink.  (around line 177)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 10. [MEDIUM] Result of an implicit PICK/GET_CONTENT Intent is trusted

- Location: `com.termux.app.api.StorageGetAPI$StorageActivity`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: MEDIUM | Rule: pick-result-file | Scope: APP
- Priority: 27/100 (P3)
- Note: Not reached from an exported component by method calls or explicit startActivity(new Intent(ctx, X.class)) hops. It can still be reached through implicit Intents with a framework action (VIEW, SEND), string-built ComponentNames or PendingIntents (the call graph follows explicit launches and custom-action implicit Intents only): check who launches this component.
- AI triage: NEEDS REVIEW - The Uri is obtained from the onActivityResult parameter (p3) and used directly in openInputStream without validation. The code that launches the implicit Intent is not shown, so we cannot confirm the Intent type or whether the Uri is attacker-controlled. No mitigations (e.g., authority checks) are present in the snippet. Fix: Validate the returned Uri's authority and scheme against a trusted list before opening the stream, or restrict the launching Intent to specific trusted document providers. (confidence 50%)
- Why flagged: onActivityResult() opens the Uri returned by an implicit OPEN_DOCUMENT Intent (openInputStream). The app that answers the Intent is chosen by the system, so a malicious app can answer with a file:// or content:// Uri that points at this app's private files.  (around line 108)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Treat the returned Uri as untrusted: accept only content:// from the expected authority, never file://, copy through ContentResolver into a new file, and do not follow a Uri that resolves into your own data directory.

#### 11. [MEDIUM] Backup allowed (allowBackup)

- Location: `AndroidManifest.xml`
- CWE: CWE-530 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-allow-backup
- Priority: 45/100 (P2)
- Why flagged: android:allowBackup is not explicitly "false" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.
- Risk scenario: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.
- Fix: Set android:allowBackup="false", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.

#### 12. [MEDIUM] Exported activity without a permission: com.termux.widget.TermuxCreateShortcutActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 13. [MEDIUM] Provider grants URI permissions broadly: com.termux.app.TermuxDocumentsProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-exported-provider-grant-uri
- Priority: 38/100 (P3)
- Why flagged: android:grantUriPermissions="true" on the whole provider lets any Intent that carries a content:// Uri of it hand temporary access to the receiving app, for every path of the provider.
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Limit it with <grant-uri-permission android:path/pathPrefix=...> to only the paths that must be shared, and check the FileProvider paths XML does not expose root-path or the whole external storage.

#### 14. [MEDIUM] Provider grants URI permissions broadly: com.termux.app.TermuxContentProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-exported-provider-grant-uri
- Priority: 38/100 (P3)
- Why flagged: android:grantUriPermissions="true" on the whole provider lets any Intent that carries a content:// Uri of it hand temporary access to the receiving app, for every path of the provider.
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Limit it with <grant-uri-permission android:path/pathPrefix=...> to only the paths that must be shared, and check the FileProvider paths XML does not expose root-path or the whole external storage.

#### 15. [MEDIUM] Provider grants URI permissions broadly: com.termux.app.api.ShareAPI$ContentProvider

- Location: `AndroidManifest.xml`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: MEDIUM | Rule: manifest-exported-provider-grant-uri
- Priority: 38/100 (P3)
- Why flagged: android:grantUriPermissions="true" on the whole provider lets any Intent that carries a content:// Uri of it hand temporary access to the receiving app, for every path of the provider.
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Limit it with <grant-uri-permission android:path/pathPrefix=...> to only the paths that must be shared, and check the FileProvider paths XML does not expose root-path or the whole external storage.

#### 16. [MEDIUM] Powerful permissions requested (1)

- Location: `AndroidManifest.xml`
- CWE: CWE-250 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-powerful-permissions
- Priority: 45/100 (P2)
- Why flagged: - MANAGE_EXTERNAL_STORAGE: all-files access to shared storage
- Risk scenario: Extra privileges (debuggable, test-only, shared user id, legacy storage) widen what a compromise or a malicious app can reach. Powerful permissions (SMS, overlay, install packages) and an AccessibilityService give a compromised app, or overlay and banking malware, far more reach than the feature needs.
- Fix: Request only what the feature really needs, and prefer the narrower alternative (photo picker, SAF, SMS Retriever / User Consent API instead of READ_SMS).

#### 17. [LOW] Shared external storage used

- Location: `com.termux.app.TermuxContentProvider`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: external-storage | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: Files on shared storage can be read (and before scoped storage, replaced) by other apps.  (around line 522)
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Keep sensitive data in internal storage (filesDir) or getExternalFilesDir with encryption.

#### 18. [LOW] Shared external storage used

- Location: `com.termux.app.TermuxInstaller$$ExternalSyntheticLambda2`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: external-storage | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: Files on shared storage can be read (and before scoped storage, replaced) by other apps.  (around line 417)
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Keep sensitive data in internal storage (filesDir) or getExternalFilesDir with encryption.

#### 19. [LOW] Data copied to clipboard

- Location: `com.termux.app.api.ClipboardApi$1`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 53)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 20. [LOW] Dynamic receiver registered without export flag

- Location: `com.termux.app.api.SAFAPI$1`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1095)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 21. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `com.termux.app.api.SAFAPI`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 1119)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 22. [LOW] Data copied to clipboard

- Location: `com.termux.app.api.SAFAPI`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app puts data on the system clipboard. On many Android versions other apps can read the clipboard (and clipboard managers keep a history).  (around line 1524)
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: Do not copy secrets to the clipboard; if you must, mark the clip sensitive (ClipDescription.EXTRA_IS_SENSITIVE on API 33+) and clear it quickly.

#### 23. [LOW] Untrusted input chooses the file or content URI the app opens

- Location: `com.termux.app.api.StorageGetAPI$StorageActivity`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 8/100 (P4)
- Note: Not reached from an exported component by method calls or explicit startActivity(new Intent(ctx, X.class)) hops. It can still be reached through implicit Intents with a framework action (VIEW, SEND), string-built ComponentNames or PendingIntents (the call graph follows explicit launches and custom-action implicit Intents only): check who launches this component.
- Why flagged: Data from Intent.getData() in onActivityResult reaches ContentResolver.openInputStream() in method StorageGetAPI$StorageActivity.onActivityResult(IILandroid/content/Intent;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The Intent is the result that an activity this app started handed back to onActivityResult (a file picker, the camera, one of its own screens), not an input that another app sends to a component of this app. It is attacker-controlled only if the app starts an implicit Intent that another app can answer, or the activity it calls is untrusted (low confidence); check which activity is started and whether the Intent is explicit. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.  (around line 142)
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

#### 24. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `com.termux.app.api.UsbAPI`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 210)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 25. [LOW] PendingIntent without FLAG_IMMUTABLE

- Location: `com.termux.widget.TermuxWidgetProvider`
- CWE: CWE-927 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: pendingintent-mutable | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: A mutable PendingIntent can be filled in by another app that receives it (changing action/extras), and Android 12+ requires you to choose explicitly.  (around line 283)
- Risk scenario: A broadcast or PendingIntent without an explicit target can be received or filled in by a malicious app that registered a matching filter.
- Fix: Add PendingIntent.FLAG_IMMUTABLE unless the receiver truly needs to modify it.

#### 26. [LOW] No network security config referenced

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: MEDIUM | Rule: manifest-network-security-config
- Priority: 17/100 (P4)
- Why flagged: No android:networkSecurityConfig is set. On devices running API < 28, cleartext HTTP is allowed by default unless a config says otherwise, so this app's real cleartext posture on older phones is unverified here.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Add a network_security_config.xml with cleartextTrafficPermitted="false" as the base config (and certificate pinning if the app always talks to the same backend).

#### 27. [LOW] Exported activity without a permission: com.termux.app.TermuxFileReceiverActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: SEND, VIEW).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 28. [LOW] Legacy external storage requested

- Location: `AndroidManifest.xml`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-legacy-external-storage
- Priority: 20/100 (P4)
- Why flagged: android:requestLegacyExternalStorage="true" opts out of scoped storage, so files the app writes to shared storage stay readable (and replaceable) by other apps that hold the storage permission.
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Migrate to scoped storage (MediaStore / SAF / getExternalFilesDir) and remove the flag.

#### 29. [MEDIUM] Sensitive value saved to SharedPreferences (plaintext)

- Location: `com.termux.app.TermuxActivity`
- CWE: CWE-312 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: APP | Reachable from an exported component
- Priority: 38/100 (P3)
- Call path: Entry: exported activity-alias com.termux.app.TermuxActivity | Path: com.termux.app.TermuxActivity.onStop()
- AI triage: FALSE POSITIVE - The stored value is a terminal session handle (mHandle) used for session restoration, not a credential or sensitive secret. The key "current_session" indicates UI state persistence, not authentication material. Fix: No fix needed; this is normal app state persistence. If desired, exclude this key from backups via android:allowBackup="false" or a custom BackupAgent. (confidence 85%)
- Why flagged: putString() is called next to a credential-like name. SharedPreferences are stored as plain XML in the app's data directory; they are readable on rooted devices and in backups when allowBackup is on.  (around line 3774)
- Risk scenario: Anyone with the device in hand, a backup, a rooted phone or another app exploiting a file leak can read tokens, passwords or personal data stored in plain text.
- Fix: Do not store passwords/tokens in SharedPreferences. Use EncryptedSharedPreferences or the Android Keystore, and prefer short-lived tokens.

### Remediation guide

One entry per weakness type found above.

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

#### CWE-250 - Execution with Unnecessary Privileges

OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM

Risk: Extra privileges (debuggable, test-only, shared user id, legacy storage) widen what a compromise or a malicious app can reach. Powerful permissions (SMS, overlay, install packages) and an AccessibilityService give a compromised app, or overlay and banking malware, far more reach than the feature needs.

Vulnerable:

```kotlin
<application android:debuggable="true" android:testOnly="true" ...>
<uses-permission android:name="android.permission.READ_SMS" />
```

Secure:

```kotlin
<!-- ship release builds without debuggable / testOnly; request only the permissions you use -->
<!-- OTP codes: SMS Retriever or SMS User Consent API instead of READ_SMS; files: photo picker or the Storage Access Framework -->
```

References: [CWE-250 (MITRE)](https://cwe.mitre.org/data/definitions/250.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

## Third-Party Libraries & SCA

41 component(s) detected in the APK (META-INF version files, pom.properties, native .so strings, dex strings, package-path heuristics). **0 vulnerable / outdated, 1 with unknown version (NOT checked against CVEs).** Libraries detected only by package path have version `?`: presence is proven, the version is not - they cannot be matched against version-specific CVEs, so this is a lower bound, not proof that nothing else is bundled.

| Component | Version | Status | Known vulnerabilities | Fix | Source |
|---|---|---|---|---|---|
| androidx.activity:activity | 1.8.0 | OK | - | - | version file |
| androidx.annotation:annotation-experimental | 1.4.1 | OK | - | - | version file |
| androidx.appcompat:appcompat | 1.7.0 | OK | - | - | version file |
| androidx.appcompat:appcompat-resources | 1.7.0 | OK | - | - | version file |
| androidx.cardview:cardview | 1.0.0 | OK | - | - | version file |
| androidx.constraintlayout:constraintlayout | 2.2.1 | OK | - | - | version file |
| androidx.coordinatorlayout:coordinatorlayout | 1.1.0 | OK | - | - | version file |
| androidx.core:core | 1.19.1 | OK | - | - | version file |
| androidx.core:core-ktx | 1.19.1 | OK | - | - | version file |
| androidx.core:core-viewtree | 1.0.0 | OK | - | - | version file |
| androidx.cursoradapter:cursoradapter | 1.0.0 | OK | - | - | version file |
| androidx.customview:customview | 1.2.0 | OK | - | - | version file |
| androidx.dynamicanimation:dynamicanimation | 1.1.0 | OK | - | - | version file |
| androidx.emoji2:emoji2 | 1.3.0 | OK | - | - | version file |
| androidx.emoji2:emoji2-views-helper | 1.3.0 | OK | - | - | version file |
| androidx.fragment:fragment | 1.5.4 | OK | - | - | version file |
| androidx.graphics:graphics-shapes | 1.0.1 | OK | - | - | version file |
| androidx.interpolator:interpolator | 1.0.0 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-livedata | 2.10.0 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-livedata-core | 2.10.0 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-livedata-core-ktx | 2.10.0 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-process | 2.10.0 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-runtime | 2.10.0 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-viewmodel | 2.10.0 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-viewmodel-savedstate | 2.10.0 | OK | - | - | version file |
| androidx.loader:loader | 1.0.0 | OK | - | - | version file |
| androidx.profileinstaller:profileinstaller | 1.4.0 | OK | - | - | version file |
| androidx.recyclerview:recyclerview | 1.2.1 | OK | - | - | version file |
| androidx.savedstate:savedstate | 1.4.0 | OK | - | - | version file |
| androidx.startup:startup-runtime | 1.1.1 | OK | - | - | version file |
| androidx.tracing:tracing | 1.2.0 | OK | - | - | version file |
| androidx.transition:transition | 1.5.0 | OK | - | - | version file |
| androidx.vectordrawable:vectordrawable | 1.1.0 | OK | - | - | version file |
| androidx.vectordrawable:vectordrawable-animated | 1.1.0 | OK | - | - | version file |
| androidx.versionedparcelable:versionedparcelable | 1.1.1 | OK | - | - | version file |
| androidx.viewpager2:viewpager2 | 1.0.0 | OK | - | - | version file |
| androidx.viewpager:viewpager | 1.1.0 | OK | - | - | version file |
| kotlinx:coroutines_android | 1.9.0 | OK | - | - | version file |
| kotlinx:coroutines_core | 1.9.0 | OK | - | - | version file |
| androidx:androidx-libraries | ? | UNKNOWN VERSION | - | - | package path |
| com.google.android.material:material | 1.14.0 | OK | - | - | version file |

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
      "version": "1.19.1",
      "purl": "pkg:maven\/androidx.core\/core-ktx@1.19.1"
    },
    {
      "type": "library",
      "group": "androidx.core",
      "name": "core-viewtree",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.core\/core-viewtree@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.core",
      "name": "core",
      "version": "1.19.1",
      "purl": "pkg:maven\/androidx.core\/core@1.19.1"
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
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.customview\/customview@1.2.0"
    },
    {
      "type": "library",
      "group": "androidx.dynamicanimation",
      "name": "dynamicanimation",
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.dynamicanimation\/dynamicanimation@1.1.0"
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
      "group": "androidx.fragment",
      "name": "fragment",
      "version": "1.5.4",
      "purl": "pkg:maven\/androidx.fragment\/fragment@1.5.4"
    },
    {
      "type": "library",
      "group": "androidx.graphics",
      "name": "graphics-shapes",
      "version": "1.0.1",
      "purl": "pkg:maven\/androidx.graphics\/graphics-shapes@1.0.1"
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
      "group": "androidx.lifecycle",
      "name": "lifecycle-livedata-core-ktx",
      "version": "2.10.0",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-livedata-core-ktx@2.10.0"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-livedata-core",
      "version": "2.10.0",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-livedata-core@2.10.0"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-livedata",
      "version": "2.10.0",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-livedata@2.10.0"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-process",
      "version": "2.10.0",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-process@2.10.0"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-runtime",
      "version": "2.10.0",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-runtime@2.10.0"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-viewmodel-savedstate",
      "version": "2.10.0",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-viewmodel-savedstate@2.10.0"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-viewmodel",
      "version": "2.10.0",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-viewmodel@2.10.0"
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
      "group": "androidx.profileinstaller",
      "name": "profileinstaller",
      "version": "1.4.0",
      "purl": "pkg:maven\/androidx.profileinstaller\/profileinstaller@1.4.0"
    },
    {
      "type": "library",
      "group": "androidx.recyclerview",
      "name": "recyclerview",
      "version": "1.2.1",
      "purl": "pkg:maven\/androidx.recyclerview\/recyclerview@1.2.1"
    },
    {
      "type": "library",
      "group": "androidx.savedstate",
      "name": "savedstate",
      "version": "1.4.0",
      "purl": "pkg:maven\/androidx.savedstate\/savedstate@1.4.0"
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
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.tracing\/tracing@1.2.0"
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
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.viewpager\/viewpager@1.1.0"
    },
    {
      "type": "library",
      "group": "com.google.android.material",
      "name": "material",
      "version": "1.14.0",
      "purl": "pkg:maven\/com.google.android.material\/material@1.14.0"
    },
    {
      "type": "library",
      "group": "kotlinx",
      "name": "coroutines_android",
      "version": "1.9.0",
      "purl": "pkg:maven\/kotlinx\/coroutines_android@1.9.0"
    },
    {
      "type": "library",
      "group": "kotlinx",
      "name": "coroutines_core",
      "version": "1.9.0",
      "purl": "pkg:maven\/kotlinx\/coroutines_core@1.9.0"
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
    }
  ]
}
```

## Edited classes (0)

None.

## AI notes (this session)

None. Use Explain / Patterns / Review manifest first and they will be included.
