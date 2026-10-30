# APK ReLab report: io.github.quillpad

> Educational static analysis. Use only on apps you own or are allowed to analyze.

## App info

```
Package: io.github.quillpad
Size: 6.4 MB | Files: 618
DEX: 2 (classes.dex 5.2 MB, classes2.dex 173.7 KB)
```

## AndroidManifest.xml

```xml
<?xml version='1.0' encoding='utf-8' ?>
<manifest android:versionCode="57"
          android:versionName="1.5.15"
          android:compileSdkVersion="37"
          android:compileSdkVersionCodename="17"
          android:requiredSplitTypes="base__abi,base__density"
          android:splitTypes=""
          package="io.github.quillpad"
          platformBuildVersionCode="37"
          platformBuildVersionName="17" xmlns:android="http://schemas.android.com/apk/res/android">
  <uses-sdk android:minSdkVersion="32"
            android:targetSdkVersion="37" />
  <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
  <uses-permission android:name="android.permission.INTERNET" />
  <uses-permission android:name="android.permission.WAKE_LOCK" />
  <uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED" />
  <uses-permission android:name="android.permission.RECORD_AUDIO" />
  <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
  <uses-permission android:name="android.permission.SCHEDULE_EXACT_ALARM" />
  <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
  <uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC"
                   android:minSdkVersion="34" />
  <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MICROPHONE"
                   android:minSdkVersion="34" />
  <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK"
                   android:minSdkVersion="34" />
  <uses-permission android:name="android.permission.REORDER_TASKS" />
  <permission android:name="io.github.quillpad.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION"
              android:protectionLevel="signature" />
  <uses-permission android:name="io.github.quillpad.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION" />
  <queries>
    <intent>
      <action android:name="android.intent.action.SEND" />
      <data android:mimeType="message/rfc822" />
    </intent>
    <intent>
      <action android:name="android.intent.action.SEND_MULTIPLE" />
      <data android:mimeType="message/rfc822" />
    </intent>
    <intent>
      <action android:name="android.intent.action.SENDTO" />
    </intent>
  </queries>
  <application android:theme="@style/AppTheme"
               android:label="@string/app_name"
               android:icon="@mipmap/ic_launcher"
               android:name="org.qosp.notes.App"
               android:allowBackup="true"
               android:supportsRtl="true"
               android:extractNativeLibs="false"
               android:networkSecurityConfig="@xml/network_security_config"
               android:roundIcon="@mipmap/ic_launcher_round"
               android:appComponentFactory="androidx.core.app.CoreComponentFactory"
               android:localeConfig="@xml/locales_config">
    <activity android:name="org.qosp.notes.ui.MainActivity"
              android:exported="true"
              android:launchMode="singleTask">
      <intent-filter android:label="@string/shortcut_take_note">
        <action android:name="android.intent.action.SEND" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="text/plain" />
      </intent-filter>
      <intent-filter android:label="@string/shortcut_take_note">
        <action android:name="android.intent.action.SEND" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="image/*" />
      </intent-filter>
      <intent-filter android:label="@string/shortcut_take_note">
        <action android:name="android.intent.action.SEND" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="video/*" />
      </intent-filter>
      <intent-filter android:label="@string/shortcut_take_note">
        <action android:name="android.intent.action.SEND" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="audio/*" />
      </intent-filter>
      <intent-filter android:label="@string/shortcut_take_note">
        <action android:name="android.intent.action.SEND_MULTIPLE" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="image/*" />
      </intent-filter>
      <intent-filter android:label="@string/shortcut_take_note">
        <action android:name="android.intent.action.SEND_MULTIPLE" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="video/*" />
      </intent-filter>
      <intent-filter android:label="@string/shortcut_take_note">
        <action android:name="android.intent.action.SEND_MULTIPLE" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:mimeType="audio/*" />
      </intent-filter>
    </activity>
    <activity android:name="org.qosp.notes.ui.launcher.LauncherActivity"
              android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
      <meta-data android:name="android.app.shortcuts"
                 android:resource="@xml/shortcuts" />
    </activity>
    <activity android:name="org.qosp.notes.ui.media.MediaActivity" />
    <receiver android:name="org.qosp.notes.ui.widget.NotesWidgetProvider"
              android:exported="true">
      <intent-filter>
        <action android:name="android.appwidget.action.APPWIDGET_UPDATE" />
      </intent-filter>
      <meta-data android:name="android.appwidget.provider"
                 android:resource="@xml/notes_widget_info" />
    </receiver>
    <service android:name="org.qosp.notes.ui.widget.NotesWidgetService"
             android:permission="android.permission.BIND_REMOTEVIEWS"
             android:exported="false" />
    <provider android:name="androidx.core.content.FileProvider"
              android:exported="false"
              android:authorities="io.github.quillpad.provider"
              android:grantUriPermissions="true">
      <meta-data android:name="android.support.FILE_PROVIDER_PATHS"
                 android:resource="@xml/file_provider_paths" />
    </provider>
    <provider android:name="androidx.startup.InitializationProvider"
              android:exported="false"
              android:authorities="io.github.quillpad.androidx-startup">
      <meta-data android:name="androidx.emoji2.text.EmojiCompatInitializer"
                 android:value="androidx.startup" />
      <meta-data android:name="androidx.lifecycle.ProcessLifecycleInitializer"
                 android:value="androidx.startup" />
      <meta-data android:name="okhttp3.internal.platform.PlatformInitializer"
                 android:value="androidx.startup" />
      <meta-data android:name="androidx.profileinstaller.ProfileInstallerInitializer"
                 android:value="androidx.startup" />
    </provider>
    <receiver android:name="org.qosp.notes.ui.reminders.ReminderReceiver"
              android:exported="false">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
        <action android:name="android.app.action.SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED" />
      </intent-filter>
    </receiver>
    <service android:name="org.qosp.notes.ui.media.MusicService"
             android:exported="false"
             android:foregroundServiceType="mediaPlayback" />
    <service android:name="org.qosp.notes.ui.recorder.RecorderService"
             android:exported="false"
             android:foregroundServiceType="microphone" />
    <service android:name="org.qosp.notes.components.backup.BackupService"
             android:exported="false"
             android:foregroundServiceType="dataSync" />
    <activity android:theme="@style/WhiteBackgroundTheme"
              android:name="androidx.test.core.app.InstrumentationActivityInvoker$BootstrapActivity"
              android:exported="true">
      <intent-filter android:priority="-100">
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <activity android:theme="@style/WhiteBackgroundTheme"
              android:name="androidx.test.core.app.InstrumentationActivityInvoker$EmptyActivity"
              android:exported="true">
      <intent-filter android:priority="-100">
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <activity android:theme="@style/WhiteBackgroundDialogTheme"
              android:name="androidx.test.core.app.InstrumentationActivityInvoker$EmptyFloatingActivity"
              android:exported="true">
      <intent-filter android:priority="-100">
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <service android:name="androidx.work.impl.background.systemalarm.SystemAlarmService"
             android:enabled="@bool/enable_system_alarm_service_default"
             android:exported="false"
             android:directBootAware="false" />
    <service android:name="androidx.work.impl.background.systemjob.SystemJobService"
             android:permission="android.permission.BIND_JOB_SERVICE"
             android:enabled="@bool/enable_system_job_service_default"
             android:exported="true"
             android:directBootAware="false" />
    <service android:name="androidx.work.impl.foreground.SystemForegroundService"
             android:enabled="@bool/enable_system_foreground_service_default"
             android:exported="false"
             android:directBootAware="false" />
    <receiver android:name="androidx.work.impl.utils.ForceStopRunnable$BroadcastReceiver"
              android:enabled="true"
              android:exported="false"
              android:directBootAware="false" />
    <receiver android:name="androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryChargingProxy"
              android:enabled="false"
              android:exported="false"
              android:directBootAware="false">
      <intent-filter>
        <action android:name="android.intent.action.ACTION_POWER_CONNECTED" />
        <action android:name="android.intent.action.ACTION_POWER_DISCONNECTED" />
      </intent-filter>
    </receiver>
    <receiver android:name="androidx.work.impl.background.systemalarm.ConstraintProxy$BatteryNotLowProxy"
              android:enabled="false"
              android:exported="false"
              android:directBootAware="false">
      <intent-filter>
        <action android:name="android.intent.action.BATTERY_OKAY" />
        <action android:name="android.intent.action.BATTERY_LOW" />
      </intent-filter>
    </receiver>
    <receiver android:name="androidx.work.impl.background.systemalarm.ConstraintProxy$StorageNotLowProxy"
              android:enabled="false"
              android:exported="false"
              android:directBootAware="false">
      <intent-filter>
        <action android:name="android.intent.action.DEVICE_STORAGE_LOW" />
        <action android:name="android.intent.action.DEVICE_STORAGE_OK" />
      </intent-filter>
    </receiver>
    <receiver android:name="androidx.work.impl.background.systemalarm.ConstraintProxy$NetworkStateProxy"
              android:enabled="false"
              android:exported="false"
              android:directBootAware="false">
      <intent-filter>
        <action android:name="android.net.conn.CONNECTIVITY_CHANGE" />
      </intent-filter>
    </receiver>
    <receiver android:name="androidx.work.impl.background.systemalarm.RescheduleReceiver"
              android:enabled="false"
              android:exported="false"
              android:directBootAware="false">
      <intent-filter>
        <action android:name="android.intent.action.BOOT_COMPLETED" />
        <action android:name="android.intent.action.TIME_SET" />
        <action android:name="android.intent.action.TIMEZONE_CHANGED" />
      </intent-filter>
    </receiver>
    <receiver android:name="androidx.work.impl.background.systemalarm.ConstraintProxyUpdateReceiver"
              android:enabled="@bool/enable_system_alarm_service_default"
              android:exported="false"
              android:directBootAware="false">
      <intent-filter>
        <action android:name="androidx.work.impl.background.systemalarm.UpdateProxies" />
      </intent-filter>
    </receiver>
    <receiver android:name="androidx.work.impl.diagnostics.DiagnosticsReceiver"
              android:permission="android.permission.DUMP"
              android:enabled="true"
              android:exported="true"
              android:directBootAware="false">
      <intent-filter>
        <action android:name="androidx.work.diagnostics.REQUEST_DIAGNOSTICS" />
      </intent-filter>
    </receiver>
    <uses-library android:name="androidx.window.extensions"
                  android:required="false" />
    <uses-library android:name="androidx.window.sidecar"
                  android:required="false" />
    <service android:name="androidx.room.MultiInstanceInvalidationService"
             android:exported="false"
             android:directBootAware="true" />
    <activity android:theme="@android:style/Theme.Dialog"
              android:name="org.acra.dialog.CrashReportDialog"
              android:process=":acra"
              android:finishOnTaskLaunch="true"
              android:excludeFromRecents="true"
              android:launchMode="singleInstance" />
    <service android:name="org.acra.sender.LegacySenderService"
             android:enabled="@bool/acra_enable_legacy_service"
             android:exported="false"
             android:process=":acra" />
    <service android:name="org.acra.sender.JobSenderService"
             android:permission="android.permission.BIND_JOB_SERVICE"
             android:enabled="@bool/acra_enable_job_service"
             android:exported="false"
             android:process=":acra" />
    <provider android:name="org.acra.attachment.AcraContentProvider"
              android:exported="false"
              android:process=":acra"
              android:authorities="io.github.quillpad.acra"
              android:grantUriPermissions="true" />
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
               android:value="4" />
  </application>
</manifest>
```

## Attack surface

Exported components (reachable by other apps): **9** - requested permissions: **13**

| Component | Kind | Intent-filter actions |
|---|---|---|
| `org.qosp.notes.ui.MainActivity` | activity | SEND, SEND_MULTIPLE |
| `org.qosp.notes.ui.launcher.LauncherActivity` | activity | MAIN |
| `org.qosp.notes.ui.widget.NotesWidgetProvider` | receiver | APPWIDGET_UPDATE |
| `androidx.test.core.app.InstrumentationActivityInvoker$BootstrapActivity` | activity | - |
| `androidx.test.core.app.InstrumentationActivityInvoker$EmptyActivity` | activity | - |
| `androidx.test.core.app.InstrumentationActivityInvoker$EmptyFloatingActivity` | activity | - |
| `androidx.work.impl.background.systemjob.SystemJobService` | service | - |
| `androidx.work.impl.diagnostics.DiagnosticsReceiver` | receiver | REQUEST_DIAGNOSTICS |
| `androidx.profileinstaller.ProfileInstallReceiver` | receiver | INSTALL_PROFILE, SKIP_FILE, SAVE_PROFILE, BENCHMARK_OPERATION |

**Permissions:** ACCESS_NETWORK_STATE, FOREGROUND_SERVICE, FOREGROUND_SERVICE_DATA_SYNC, FOREGROUND_SERVICE_MEDIA_PLAYBACK, FOREGROUND_SERVICE_MICROPHONE, INTERNET, POST_NOTIFICATIONS, RECEIVE_BOOT_COMPLETED, RECORD_AUDIO, REORDER_TASKS, SCHEDULE_EXACT_ALARM, WAKE_LOCK, io.github.quillpad.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION

## Security scan

Deep scan status: finished, 5978 / 5978 classes; SSA taint: +8 flow(s) (taint losses real/param-only: callee not analysed 0/0, app method unresolved 9/84, library or outside group 233/4788 (top owners of real drops: android/os/Parcel 47, java/lang/Class 17, android/app/Activity 15, android/content/Context 14, java/lang/ref/Reference 11); caps hit: sink refs 0, rounds 0 method(s), requeue 0 method(s), ~ sites 0; slowest methods: yr1.N([BII)Lim2; 4.3s [212 insns, 2 rounds, 2 runs], yp.j(Ljava/lang/Object;)V 1.6s [18 insns, 2 rounds, 7 runs], yr1.M([BII)Lgm2; 1.6s [389 insns, 2 rounds, 2 runs], yr1.J(Lxe1;Lve1;)Ljava/lang/Object; 1.5s [68 insns, 2 rounds, 7 runs], yo.b(Lorg/qosp/notes/data/Backup;Lad0;)Ljava/lang/Object; 1.4s [657 insns, 3 rounds, 8 runs])

Heuristic static scan - 42 finding(s) in total; 28 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

Not covered by this scan: business-logic flaws (prices, limits, order flows), server-side bugs of the APIs the app calls, and native (C/C++) code; a large app is analysed in groups, so a data flow that crosses groups can be missed.

### Summary

| Severity | Count |
|---|---|
| CRITICAL | 1 |
| HIGH | 3 |
| MEDIUM | 9 |
| LOW | 15 |

**OWASP Mobile Top 10 (2024) coverage**

- M4 Insufficient Input/Output Validation: 10
- M8 Security Misconfiguration: 8
- M9 Insecure Data Storage: 5
- M5 Insecure Communication: 3
- M10 Insufficient Cryptography: 1
- Not mapped: 1

### Findings

#### 1. [HIGH] Possible Zip Slip (unsanitized zip entry path)

- Location: `ep`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: zip-slip | Scope: APP | Probably reachable from an exported component (approximate class-level path)
- Priority: 54/100 (P2)
- Call path: Entry: exported activity org.qosp.notes.ui.MainActivity | Approximate path (class level): org.qosp.notes.ui.MainActivity.w() -> dp.q() -> jb0.a() -> ep.q()
- AI triage: NEEDS REVIEW - The code snippet checks ZipEntry.getName() against 'backup.json' and reads it into memory, but the rest of the file extraction logic is cut off after cond_239. Fix: Ensure all extracted ZipEntry paths are canonicalized using getCanonicalPath() and checked to remain inside the target destination directory before writing to disk. (confidence 60%)
- Why flagged: This method reads ZipEntry.getName() while extracting an archive and builds a File/output path from it, with no getCanonicalPath()/normalize() check anywhere in the method. A crafted entry name containing "../" segments can write outside the intended extraction directory (e.g. overwrite app files or drop an executable in a sensitive location).  (around line 1282)  [Renamed by R8, but this is the app's own code: the class references the app's package.]
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Resolve the destination file, call getCanonicalPath() on it, and verify it still starts with the intended output directory before writing; reject/skip any entry that fails the check.

#### 2. [HIGH] Insecure TLS protocol requested: "SSL"

- Location: `eq2`
- CWE: CWE-327 | OWASP: M10 Insufficient Cryptography | MASVS: MASVS-CRYPTO | Confidence: HIGH | Rule: tls-protocol-version | Scope: OBF
- Priority: 42/100 (P3)
- AI triage: TRUE POSITIVE - The code explicitly requests the deprecated "SSL" protocol when calling SSLContext.getInstance(), which allows fallback to insecure protocol versions susceptible to downgrade attacks. Fix: Replace the hardcoded "SSL" string with "TLS" or a specific modern protocol like "TLSv1.3" in the SSLContext.getInstance() call. (confidence 95%)
- Why flagged: SSLContext.getInstance("SSL") is used. SSL/SSLv2/SSLv3 are broken (POODLE and other attacks let a network attacker decrypt or tamper with the connection).  (around line 134)
- Risk scenario: A network attacker can push the connection down to SSLv3 / TLSv1.0 / TLSv1.1, which have known attacks, and read or change the traffic.
- Fix: Use SSLContext.getInstance("TLSv1.3") (fall back to "TLSv1.2" only if you must support very old peers), or omit explicit protocol selection and rely on the platform default on modern API levels.

#### 3. [CRITICAL] TLS certificate validation disabled

- Location: `gq2`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: tls-trustmanager | Scope: OBF
- Priority: 54/100 (P2)
- Note: Restored one level: an obfuscated class, but a method of this app instantiates it and installs it (SSLContext.init, a hostname-verifier / socket-factory setter), so it is in use.
- AI triage: TRUE POSITIVE - The checkServerTrusted method performs no validation logic and throws no CertificateException, intrinsically accepting any certificate chain. Fix: Throw a CertificateException when validation fails or use the default system X509TrustManager implementation. (confidence 95%)
- Why flagged: This class implements X509TrustManager, and checkServerTrusted() returns right after its locals/param declarations with no verification call in between - it accepts ANY certificate, attacker's included.  (around line 27)
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Remove the custom TrustManager and use the platform default (or pin to the real certificate/public key via a network security config); never ship a no-op trust manager.

#### 4. [MEDIUM] Untrusted input is used as a file path

- Location: `ep`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 27/100 (P3)
- Call path: Entry: a70.onTrimMemory(I)V | Path: a70.onTrimMemory(I)V -> so3.hasNext()Z -> yp.j(Ljava/lang/Object;)V -> ep.q(Ljava/lang/Object;)Ljava/lang/Object;
- AI triage: NEEDS REVIEW - (the AI answer had no JSON)
- Why flagged: Data from Intent.getParcelableArrayListExtra() (through p40.d1(Ljava/util/List;)Ljava/lang/Object;) reaches FileOutputStream.<init>() in method ep.q(Ljava/lang/Object;)Ljava/lang/Object;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.  (around line 1734)  [Renamed by R8, but this is the app's own code: the class references the app's package.]
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 5. [MEDIUM] Untrusted input is used as a file path (x2)

- Location: `t51`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: MEDIUM | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 33/100 (P3)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Call path: Entry: MainActivity.onCreate(Landroid/os/Bundle;)V | Path: MainActivity.onCreate(Landroid/os/Bundle;)V -> pg4.getValue()Ljava/lang/Object; -> mf.a()Ljava/lang/Object;
- Why flagged: Data from Intent.getSerializableExtra() (through field se0.b:Ljava/io/File; (written in se0.<init>(Lorg/acra/dialog/CrashReportDialog;Landroid/content/Intent;)V)) reaches FileInputStream.<init>() in method t51.O0(Ljava/io/File;)Ljava/lang/String;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink. 2 flows of this kind end in this method.  (around line 32)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 6. [HIGH] Hostname verification disabled

- Location: `fq2`
- CWE: CWE-297 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: tls-hostname-verifier | Scope: OBF
- Priority: 60/100 (P2)
- Note: Restored one level: an obfuscated class, but a method of this app instantiates it and installs it (SSLContext.init, a hostname-verifier / socket-factory setter), so it is in use.
- Why flagged: A HostnameVerifier that accepts every hostname (ALLOW_ALL_HOSTNAME_VERIFIER, or a verify() that always returns a hardcoded true) is used - TLS stops confirming the server is who it claims to be.  (around line 10)
- Risk scenario: A valid certificate issued for ANY site is accepted for your server's name, so an attacker with a cheap certificate can sit between the app and the backend.
- Fix: Use the default HostnameVerifier, or a strict one that actually checks the certificate against the hostname.

#### 7. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `wf0`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 255)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 8. [MEDIUM] Java deserialization (ObjectInputStream.readObject)

- Location: `xb2`
- CWE: CWE-502 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-CODE | Confidence: HIGH | Rule: deserialization | Scope: OBF
- Priority: 38/100 (P3)
- Why flagged: Deserializing data that an attacker can influence (file, socket, Intent extra) can instantiate arbitrary classes and run gadget chains.  (around line 6231)
- Risk scenario: A crafted serialized object can instantiate unexpected classes while it is read (gadget chains) and lead to code execution, denial of service or tampered state.
- Fix: Prefer a data format (JSON/Protobuf) with an explicit schema; if Serializable is required, use an ObjectInputFilter allow-list.

#### 9. [MEDIUM] Backup allowed (allowBackup)

- Location: `AndroidManifest.xml`
- CWE: CWE-530 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-allow-backup
- Priority: 45/100 (P2)
- Why flagged: android:allowBackup is not explicitly "false" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.
- Risk scenario: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.
- Fix: Set android:allowBackup="false", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.

#### 10. [MEDIUM] Exported activity without a permission: androidx.test.core.app.InstrumentationActivityInvoker$BootstrapActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 11. [MEDIUM] Exported activity without a permission: androidx.test.core.app.InstrumentationActivityInvoker$EmptyActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 12. [MEDIUM] Exported activity without a permission: androidx.test.core.app.InstrumentationActivityInvoker$EmptyFloatingActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 13. [MEDIUM] Network Security Config: trusts user-installed CAs

- Location: `res/xml/network_security_config.xml`
- CWE: CWE-295 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: HIGH | Rule: res-nsc-user-ca
- Priority: 45/100 (P2)
- Why flagged: The config trusts certificates the user installed in: base-config (every domain). A proxy such as Burp/mitmproxy (or malware that installs a CA) can then decrypt this app's HTTPS traffic (MASVS-NETWORK).  [res/xml/network_security_config.xml]
- Risk scenario: On a shared Wi-Fi or a hostile network the attacker presents any certificate and the app accepts it, so passwords, tokens and API traffic can be read and changed (man-in-the-middle). In network_security_config.xml the same thing happens by configuration: a certificates entry with src=user (or overridePins=true) makes the app trust CAs that the user or malware installed, so a proxy such as Burp or mitmproxy can decrypt the traffic of a normal release build. Without a pin-set, any certificate signed by a trusted CA is accepted for your backend.
- Fix: Trust only the system CAs (src="system") in release builds; keep user CAs inside <debug-overrides> only.

#### 14. [LOW] Untrusted input chooses the file or content URI the app opens

- Location: `e82`
- CWE: CWE-73 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 12/100 (P4)
- Call path: Entry: a70.onTrimMemory(I)V | Path: a70.onTrimMemory(I)V -> so3.hasNext()Z -> yp.j(Ljava/lang/Object;)V -> e82.q(Ljava/lang/Object;)Ljava/lang/Object;
- Why flagged: Data from Intent.getParcelableArrayListExtra() (through br2.e0(Lxd0;Llf1;Lyc0;)Ljava/lang/Object;) reaches ContentResolver.openOutputStream() in method e82.q(Ljava/lang/Object;)Ljava/lang/Object;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.  (around line 6147)  [Renamed by R8, but this is the app's own code: the class references the app's package.]
- Risk scenario: A file:// or content:// URI chosen by the caller makes the app open its own private files (or another provider's data) and hand the bytes on.
- Fix: Accept only the content:// authorities you expect (reject file:// and your own FileProvider/app-private paths) before opening a URI that came from an Intent; copy with a fixed name and cap the size.

#### 15. [LOW] Temp file created

- Location: `uv0`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: APP
- Priority: 20/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 406)  [Renamed by R8, but this is the app's own code: the class references the app's package.]
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 16. [LOW] Possible SQL built by string concatenation

- Location: `fi3`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: MEDIUM | Rule: sql-concat | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: rawQuery/execSQL is called shortly after building a string with StringBuilder - a common pattern for SQL assembled from variables. If any part comes from outside input, it can be SQL-injectable.  (around line 1130)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use parameterized queries ('?' placeholders + selectionArgs) instead of concatenating values into the SQL text.

#### 17. [LOW] Dynamic receiver registered without export flag

- Location: `jm`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 333)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 18. [LOW] Dynamic receiver registered without export flag

- Location: `l3`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 1237)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 19. [LOW] Untrusted input reaches an SQL statement

- Location: `me1`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Call path: Entry: MainActivity.onCreate(Landroid/os/Bundle;)V | Path: MainActivity.onCreate(Landroid/os/Bundle;)V -> pg4.getValue()Ljava/lang/Object; -> mf.a()Ljava/lang/Object; -> gr4.c(Ljava/lang/String;)Lgj3; -> yh3.b(Lgj3;)V -> yh3.e(Lgj3;II)V -> rh2.a(Lme1;)V
- Why flagged: Data from Intent.getParcelableArrayListExtra() (through x51.next()Ljava/lang/Object;) reaches SQLiteDatabase.compileStatement() in method me1.n(Ljava/lang/String;)Lte1;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.  (around line 230)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 20. [LOW] Dynamic receiver registered without export flag

- Location: `nr`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 96)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 21. [LOW] Untrusted input is used as a file path

- Location: `ra`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Call path: Entry: MainActivity.onCreate(Landroid/os/Bundle;)V | Path: MainActivity.onCreate(Landroid/os/Bundle;)V -> pg4.getValue()Ljava/lang/Object; -> mf.a()Ljava/lang/Object; -> ra.run()V
- Why flagged: Data from Intent.getParcelableArrayListExtra() (through jj.get(I)Ljava/lang/Object;) reaches File.delete() in method ra.run()V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.  (around line 1628)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 22. [LOW] Dynamic receiver registered without export flag

- Location: `vp2`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: receiver-export-flag | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: registerReceiver(receiver, filter) without RECEIVER_NOT_EXPORTED is reachable by other apps, which can then send it crafted broadcasts.  (around line 81)
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Use registerReceiver(..., Context.RECEIVER_NOT_EXPORTED) (API 33+; ContextCompat on older) when only the app itself sends these broadcasts.

#### 23. [LOW] Untrusted input is used as a file path

- Location: `xb2`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: OBF | Reachable from an exported component
- Priority: 10/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Call path: Entry: MainActivity.onCreate(Landroid/os/Bundle;)V | Path: MainActivity.onCreate(Landroid/os/Bundle;)V -> pg4.getValue()Ljava/lang/Object; -> mf.a()Ljava/lang/Object; -> fy.run()V -> om2.A0(ZLandroid/os/Bundle;)V
- Why flagged: Data from Intent.getParcelableArrayListExtra() (through by0.b()[Ljava/io/File;) reaches File.delete() in method xb2.l(Ljava/io/File;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 3 methods. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The value passed an Object-typed field of an obfuscated class: R8 may have merged unrelated classes into one shared field there, so this flow can be a false positive (low confidence); check the chain before trusting it.  (around line 6130)
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 24. [LOW] Shared external storage used

- Location: `xp0`
- CWE: CWE-922 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: external-storage | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: Files on shared storage can be read (and before scoped storage, replaced) by other apps.  (around line 25)
- Risk scenario: Data in shared/external storage or world-accessible files can be read (or replaced) by other apps and by anyone who connects the phone. requestLegacyExternalStorage opts out of scoped storage and keeps that exposure on Android 10 and later.
- Fix: Keep sensitive data in internal storage (filesDir) or getExternalFilesDir with encryption.

#### 25. [LOW] Temp file created

- Location: `yu3`
- CWE: CWE-377 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: androgoat-checks | Scope: OBF
- Priority: 17/100 (P4)
- Why flagged: The app creates a temp file. If sensitive content is written and the file is not deleted (or sits in a shared directory) other code can read it.  (around line 123)
- Risk scenario: A predictable temp file in a shared folder can be pre-created or replaced by another app.
- Fix: Write temp data under the app's private cacheDir, delete it as soon as it is used, and never put secrets in it unencrypted.

#### 26. [LOW] Sensitive value written to log

- Location: `zh4`
- CWE: CWE-532 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: MEDIUM | Rule: androgoat-checks | Scope: OBF
- Priority: 14/100 (P4)
- Note: Lowered one level: heuristic finding inside obfuscated (likely third-party) code.
- Why flagged: A log call is built from a credential-like label ("Server rejected the credential") plus an appended variable. Logcat can be read from a computer over ADB, and by other apps on some devices.  (around line 687)
- Risk scenario: On older Android versions (and with adb or a bug-report) logs are readable; secrets that reach Log.d end up in files and crash reports.
- Fix: Never log passwords, tokens, or personal data; strip such Log calls from release builds.

#### 27. [LOW] Exported activity without a permission: org.qosp.notes.ui.MainActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: SEND, SEND_MULTIPLE).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 28. [LOW] Native code not in this APK (not analysed)

- Location: `lib/`
- Confidence: HIGH | Rule: native-coverage
- Priority: 20/100 (P4)
- Why flagged: The app's code loads native libraries and the manifest declares an ABI split (requiredSplitTypes), but this APK contains no lib/*.so: the native code ships in a separate split APK that was not scanned. Install-time splits (base__abi) must be extracted from the device or the store bundle to look at them.
- Fix: Review the native code separately (e.g. strings / imports of the .so, a disassembler) and check what the app passes to its JNI methods.

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

#### CWE-297 - Improper Validation of Certificate with Host Mismatch

OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK

Risk: A valid certificate issued for ANY site is accepted for your server's name, so an attacker with a cheap certificate can sit between the app and the backend.

Vulnerable:

```kotlin
HttpsURLConnection.setDefaultHostnameVerifier { _, _ -> true }
```

Secure:

```kotlin
// keep the default HostnameVerifier; if you must check, compare the real host
HostnameVerifier { host, session -> host == "api.example.com" && HttpsURLConnection.getDefaultHostnameVerifier().verify(host, session) }
```

References: [CWE-297 (MITRE)](https://cwe.mitre.org/data/definitions/297.html) | [Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

#### CWE-377 - Insecure Temporary File

OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE

Risk: A predictable temp file in a shared folder can be pre-created or replaced by another app.

Vulnerable:

```kotlin
File("/sdcard/tmp_" + id)
```

Secure:

```kotlin
File.createTempFile("tmp_", ".bin", cacheDir)   // app-private cache
```

References: [CWE-377 (MITRE)](https://cwe.mitre.org/data/definitions/377.html) | [Mobile Application Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html) | [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/) | [OWASP MASVS](https://mas.owasp.org/MASVS/) | [Android security tips](https://developer.android.com/privacy-and-security/security-tips)

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

## Third-Party Libraries & SCA

104 component(s) detected in the APK (META-INF version files, pom.properties, native .so strings, dex strings, package-path heuristics). **0 vulnerable / outdated, 2 with unknown version (NOT checked against CVEs).** Libraries detected only by package path have version `?`: presence is proven, the version is not - they cannot be matched against version-specific CVEs, so this is a lower bound, not proof that nothing else is bundled.

| Component | Version | Status | Known vulnerabilities | Fix | Source |
|---|---|---|---|---|---|
| androidx.activity:activity | 1.10.1 | OK | - | - | version file |
| androidx.activity:activity-compose | 1.10.1 | OK | - | - | version file |
| androidx.activity:activity-ktx | 1.10.1 | OK | - | - | version file |
| androidx.annotation:annotation-experimental | 1.4.1 | OK | - | - | version file |
| androidx.appcompat:appcompat | 1.7.1 | OK | - | - | version file |
| androidx.appcompat:appcompat-resources | 1.7.1 | OK | - | - | version file |
| androidx.autofill:autofill | 1.0.0 | OK | - | - | version file |
| androidx.cardview:cardview | 1.0.0 | OK | - | - | version file |
| androidx.compose.animation:animation | 1.8.3 | OK | - | - | version file |
| androidx.compose.animation:animation-core | 1.8.3 | OK | - | - | version file |
| androidx.compose.foundation:foundation | 1.8.3 | OK | - | - | version file |
| androidx.compose.foundation:foundation-layout | 1.8.3 | OK | - | - | version file |
| androidx.compose.material3:material3 | 1.3.2 | OK | - | - | version file |
| androidx.compose.material:material-icons-core | 1.7.8 | OK | - | - | version file |
| androidx.compose.material:material-ripple | 1.8.3 | OK | - | - | version file |
| androidx.compose.runtime:runtime | 1.8.3 | OK | - | - | version file |
| androidx.compose.runtime:runtime-saveable | 1.8.3 | OK | - | - | version file |
| androidx.compose.ui:ui | 1.8.3 | OK | - | - | version file |
| androidx.compose.ui:ui-geometry | 1.8.3 | OK | - | - | version file |
| androidx.compose.ui:ui-graphics | 1.8.3 | OK | - | - | version file |
| androidx.compose.ui:ui-text | 1.8.3 | OK | - | - | version file |
| androidx.compose.ui:ui-tooling-preview | 1.8.3 | OK | - | - | version file |
| androidx.compose.ui:ui-unit | 1.8.3 | OK | - | - | version file |
| androidx.compose.ui:ui-util | 1.8.3 | OK | - | - | version file |
| androidx.constraintlayout:constraintlayout | 2.2.1 | OK | - | - | version file |
| androidx.coordinatorlayout:coordinatorlayout | 1.3.0 | OK | - | - | version file |
| androidx.core:core | 1.16.0 | OK | - | - | version file |
| androidx.core:core-ktx | 1.16.0 | OK | - | - | version file |
| androidx.core:core-viewtree | 1.0.0 | OK | - | - | version file |
| androidx.cursoradapter:cursoradapter | 1.0.0 | OK | - | - | version file |
| androidx.customview:customview | 1.1.0 | OK | - | - | version file |
| androidx.customview:customview-poolingcontainer | 1.0.0 | OK | - | - | version file |
| androidx.databinding:viewbinding | 9.3.1 | OK | - | - | version file |
| androidx.datastore:datastore | 1.1.7 | OK | - | - | version file |
| androidx.datastore:datastore-core | 1.1.7 | OK | - | - | version file |
| androidx.datastore:datastore-preferences | 1.1.7 | OK | - | - | version file |
| androidx.datastore:datastore-preferences-core | 1.1.7 | OK | - | - | version file |
| androidx.documentfile:documentfile | 1.0.0 | OK | - | - | version file |
| androidx.drawerlayout:drawerlayout | 1.1.1 | OK | - | - | version file |
| androidx.dynamicanimation:dynamicanimation | 1.0.0 | OK | - | - | version file |
| androidx.emoji2:emoji2 | 1.4.0 | OK | - | - | version file |
| androidx.emoji2:emoji2-views-helper | 1.4.0 | OK | - | - | version file |
| androidx.exifinterface:exifinterface | 1.3.7 | OK | - | - | version file |
| androidx.fragment:fragment | 1.8.8 | OK | - | - | version file |
| androidx.fragment:fragment-ktx | 1.8.8 | OK | - | - | version file |
| androidx.graphics:graphics-path | 1.0.1 | OK | - | - | version file |
| androidx.interpolator:interpolator | 1.0.0 | OK | - | - | version file |
| androidx.legacy:legacy-support-core-utils | 1.0.0 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-livedata | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-livedata-core | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-livedata-core-ktx | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-livedata-ktx | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-process | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-runtime | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-runtime-compose | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-runtime-ktx | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-service | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-viewmodel | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-viewmodel-compose | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-viewmodel-ktx | 2.9.2 | OK | - | - | version file |
| androidx.lifecycle:lifecycle-viewmodel-savedstate | 2.9.2 | OK | - | - | version file |
| androidx.loader:loader | 1.0.0 | OK | - | - | version file |
| androidx.localbroadcastmanager:localbroadcastmanager | 1.0.0 | OK | - | - | version file |
| androidx.media:media | 1.7.0 | OK | - | - | version file |
| androidx.navigation:navigation-common | 2.9.3 | OK | - | - | version file |
| androidx.navigation:navigation-compose | 2.9.3 | OK | - | - | version file |
| androidx.navigation:navigation-fragment | 2.9.3 | OK | - | - | version file |
| androidx.navigation:navigation-fragment-ktx | 2.9.3 | OK | - | - | version file |
| androidx.navigation:navigation-runtime | 2.9.3 | OK | - | - | version file |
| androidx.navigation:navigation-ui | 2.9.3 | OK | - | - | version file |
| androidx.navigation:navigation-ui-ktx | 2.9.3 | OK | - | - | version file |
| androidx.palette:palette | 1.0.0 | OK | - | - | version file |
| androidx.palette:palette-ktx | 1.0.0 | OK | - | - | version file |
| androidx.print:print | 1.0.0 | OK | - | - | version file |
| androidx.profileinstaller:profileinstaller | 1.4.0 | OK | - | - | version file |
| androidx.recyclerview:recyclerview | 1.4.0 | OK | - | - | version file |
| androidx.room:room-ktx | 2.7.2 | OK | - | - | version file |
| androidx.room:room-runtime | 2.7.2 | OK | - | - | version file |
| androidx.savedstate:savedstate | 1.3.1 | OK | - | - | version file |
| androidx.savedstate:savedstate-compose | 1.3.1 | OK | - | - | version file |
| androidx.savedstate:savedstate-ktx | 1.3.1 | OK | - | - | version file |
| androidx.security:security-crypto | 1.1.0 | OK | - | - | version file |
| androidx.slidingpanelayout:slidingpanelayout | 1.2.0 | OK | - | - | version file |
| androidx.sqlite:sqlite | 2.5.1 | OK | - | - | version file |
| androidx.sqlite:sqlite-framework | 2.5.1 | OK | - | - | version file |
| androidx.startup:startup-runtime | 1.2.0 | OK | - | - | version file |
| androidx.swiperefreshlayout:swiperefreshlayout | 1.1.0 | OK | - | - | version file |
| androidx.tracing:tracing | 1.2.0 | OK | - | - | version file |
| androidx.tracing:tracing-ktx | 1.2.0 | OK | - | - | version file |
| androidx.transition:transition | 1.5.0 | OK | - | - | version file |
| androidx.vectordrawable:vectordrawable | 1.1.0 | OK | - | - | version file |
| androidx.vectordrawable:vectordrawable-animated | 1.1.0 | OK | - | - | version file |
| androidx.versionedparcelable:versionedparcelable | 1.1.1 | OK | - | - | version file |
| androidx.viewpager2:viewpager2 | 1.1.0-beta02 | OK | - | - | version file |
| androidx.viewpager:viewpager | 1.0.0 | OK | - | - | version file |
| androidx.window:window | 1.0.0 | OK | - | - | version file |
| androidx.work:work-runtime | 2.10.3 | OK | - | - | version file |
| androidx.work:work-runtime-ktx | 2.10.3 | OK | - | - | version file |
| com.squareup.okhttp3:okhttp | 5.1.0 | OK | - | - | dex string |
| kotlinx:coroutines_android | 1.10.2 | OK | - | - | version file |
| kotlinx:coroutines_core | 1.10.2 | OK | - | - | version file |
| androidx:androidx-libraries | ? | UNKNOWN VERSION | - | - | package path |
| com.github:jitpack-libraries | ? | UNKNOWN VERSION | - | - | package path |
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
      "name": "activity-compose",
      "version": "1.10.1",
      "purl": "pkg:maven\/androidx.activity\/activity-compose@1.10.1"
    },
    {
      "type": "library",
      "group": "androidx.activity",
      "name": "activity-ktx",
      "version": "1.10.1",
      "purl": "pkg:maven\/androidx.activity\/activity-ktx@1.10.1"
    },
    {
      "type": "library",
      "group": "androidx.activity",
      "name": "activity",
      "version": "1.10.1",
      "purl": "pkg:maven\/androidx.activity\/activity@1.10.1"
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
      "version": "1.7.1",
      "purl": "pkg:maven\/androidx.appcompat\/appcompat-resources@1.7.1"
    },
    {
      "type": "library",
      "group": "androidx.appcompat",
      "name": "appcompat",
      "version": "1.7.1",
      "purl": "pkg:maven\/androidx.appcompat\/appcompat@1.7.1"
    },
    {
      "type": "library",
      "group": "androidx.autofill",
      "name": "autofill",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.autofill\/autofill@1.0.0"
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
      "group": "androidx.compose.animation",
      "name": "animation-core",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.animation\/animation-core@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.animation",
      "name": "animation",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.animation\/animation@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.foundation",
      "name": "foundation-layout",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.foundation\/foundation-layout@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.foundation",
      "name": "foundation",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.foundation\/foundation@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.material3",
      "name": "material3",
      "version": "1.3.2",
      "purl": "pkg:maven\/androidx.compose.material3\/material3@1.3.2"
    },
    {
      "type": "library",
      "group": "androidx.compose.material",
      "name": "material-icons-core",
      "version": "1.7.8",
      "purl": "pkg:maven\/androidx.compose.material\/material-icons-core@1.7.8"
    },
    {
      "type": "library",
      "group": "androidx.compose.material",
      "name": "material-ripple",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.material\/material-ripple@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.runtime",
      "name": "runtime-saveable",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.runtime\/runtime-saveable@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.runtime",
      "name": "runtime",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.runtime\/runtime@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.ui",
      "name": "ui-geometry",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.ui\/ui-geometry@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.ui",
      "name": "ui-graphics",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.ui\/ui-graphics@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.ui",
      "name": "ui-text",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.ui\/ui-text@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.ui",
      "name": "ui-tooling-preview",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.ui\/ui-tooling-preview@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.ui",
      "name": "ui-unit",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.ui\/ui-unit@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.ui",
      "name": "ui-util",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.ui\/ui-util@1.8.3"
    },
    {
      "type": "library",
      "group": "androidx.compose.ui",
      "name": "ui",
      "version": "1.8.3",
      "purl": "pkg:maven\/androidx.compose.ui\/ui@1.8.3"
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
      "version": "1.3.0",
      "purl": "pkg:maven\/androidx.coordinatorlayout\/coordinatorlayout@1.3.0"
    },
    {
      "type": "library",
      "group": "androidx.core",
      "name": "core-ktx",
      "version": "1.16.0",
      "purl": "pkg:maven\/androidx.core\/core-ktx@1.16.0"
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
      "version": "1.16.0",
      "purl": "pkg:maven\/androidx.core\/core@1.16.0"
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
      "name": "customview-poolingcontainer",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.customview\/customview-poolingcontainer@1.0.0"
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
      "version": "9.3.1",
      "purl": "pkg:maven\/androidx.databinding\/viewbinding@9.3.1"
    },
    {
      "type": "library",
      "group": "androidx.datastore",
      "name": "datastore-core",
      "version": "1.1.7",
      "purl": "pkg:maven\/androidx.datastore\/datastore-core@1.1.7"
    },
    {
      "type": "library",
      "group": "androidx.datastore",
      "name": "datastore-preferences-core",
      "version": "1.1.7",
      "purl": "pkg:maven\/androidx.datastore\/datastore-preferences-core@1.1.7"
    },
    {
      "type": "library",
      "group": "androidx.datastore",
      "name": "datastore-preferences",
      "version": "1.1.7",
      "purl": "pkg:maven\/androidx.datastore\/datastore-preferences@1.1.7"
    },
    {
      "type": "library",
      "group": "androidx.datastore",
      "name": "datastore",
      "version": "1.1.7",
      "purl": "pkg:maven\/androidx.datastore\/datastore@1.1.7"
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
      "version": "1.4.0",
      "purl": "pkg:maven\/androidx.emoji2\/emoji2-views-helper@1.4.0"
    },
    {
      "type": "library",
      "group": "androidx.emoji2",
      "name": "emoji2",
      "version": "1.4.0",
      "purl": "pkg:maven\/androidx.emoji2\/emoji2@1.4.0"
    },
    {
      "type": "library",
      "group": "androidx.exifinterface",
      "name": "exifinterface",
      "version": "1.3.7",
      "purl": "pkg:maven\/androidx.exifinterface\/exifinterface@1.3.7"
    },
    {
      "type": "library",
      "group": "androidx.fragment",
      "name": "fragment-ktx",
      "version": "1.8.8",
      "purl": "pkg:maven\/androidx.fragment\/fragment-ktx@1.8.8"
    },
    {
      "type": "library",
      "group": "androidx.fragment",
      "name": "fragment",
      "version": "1.8.8",
      "purl": "pkg:maven\/androidx.fragment\/fragment@1.8.8"
    },
    {
      "type": "library",
      "group": "androidx.graphics",
      "name": "graphics-path",
      "version": "1.0.1",
      "purl": "pkg:maven\/androidx.graphics\/graphics-path@1.0.1"
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
      "group": "androidx.lifecycle",
      "name": "lifecycle-livedata-core-ktx",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-livedata-core-ktx@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-livedata-core",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-livedata-core@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-livedata-ktx",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-livedata-ktx@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-livedata",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-livedata@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-process",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-process@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-runtime-compose",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-runtime-compose@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-runtime-ktx",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-runtime-ktx@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-runtime",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-runtime@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-service",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-service@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-viewmodel-compose",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-viewmodel-compose@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-viewmodel-ktx",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-viewmodel-ktx@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-viewmodel-savedstate",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-viewmodel-savedstate@2.9.2"
    },
    {
      "type": "library",
      "group": "androidx.lifecycle",
      "name": "lifecycle-viewmodel",
      "version": "2.9.2",
      "purl": "pkg:maven\/androidx.lifecycle\/lifecycle-viewmodel@2.9.2"
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
      "version": "1.7.0",
      "purl": "pkg:maven\/androidx.media\/media@1.7.0"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-common",
      "version": "2.9.3",
      "purl": "pkg:maven\/androidx.navigation\/navigation-common@2.9.3"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-compose",
      "version": "2.9.3",
      "purl": "pkg:maven\/androidx.navigation\/navigation-compose@2.9.3"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-fragment-ktx",
      "version": "2.9.3",
      "purl": "pkg:maven\/androidx.navigation\/navigation-fragment-ktx@2.9.3"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-fragment",
      "version": "2.9.3",
      "purl": "pkg:maven\/androidx.navigation\/navigation-fragment@2.9.3"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-runtime",
      "version": "2.9.3",
      "purl": "pkg:maven\/androidx.navigation\/navigation-runtime@2.9.3"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-ui-ktx",
      "version": "2.9.3",
      "purl": "pkg:maven\/androidx.navigation\/navigation-ui-ktx@2.9.3"
    },
    {
      "type": "library",
      "group": "androidx.navigation",
      "name": "navigation-ui",
      "version": "2.9.3",
      "purl": "pkg:maven\/androidx.navigation\/navigation-ui@2.9.3"
    },
    {
      "type": "library",
      "group": "androidx.palette",
      "name": "palette-ktx",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.palette\/palette-ktx@1.0.0"
    },
    {
      "type": "library",
      "group": "androidx.palette",
      "name": "palette",
      "version": "1.0.0",
      "purl": "pkg:maven\/androidx.palette\/palette@1.0.0"
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
      "version": "1.4.0",
      "purl": "pkg:maven\/androidx.recyclerview\/recyclerview@1.4.0"
    },
    {
      "type": "library",
      "group": "androidx.room",
      "name": "room-ktx",
      "version": "2.7.2",
      "purl": "pkg:maven\/androidx.room\/room-ktx@2.7.2"
    },
    {
      "type": "library",
      "group": "androidx.room",
      "name": "room-runtime",
      "version": "2.7.2",
      "purl": "pkg:maven\/androidx.room\/room-runtime@2.7.2"
    },
    {
      "type": "library",
      "group": "androidx.savedstate",
      "name": "savedstate-compose",
      "version": "1.3.1",
      "purl": "pkg:maven\/androidx.savedstate\/savedstate-compose@1.3.1"
    },
    {
      "type": "library",
      "group": "androidx.savedstate",
      "name": "savedstate-ktx",
      "version": "1.3.1",
      "purl": "pkg:maven\/androidx.savedstate\/savedstate-ktx@1.3.1"
    },
    {
      "type": "library",
      "group": "androidx.savedstate",
      "name": "savedstate",
      "version": "1.3.1",
      "purl": "pkg:maven\/androidx.savedstate\/savedstate@1.3.1"
    },
    {
      "type": "library",
      "group": "androidx.security",
      "name": "security-crypto",
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.security\/security-crypto@1.1.0"
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
      "group": "androidx.sqlite",
      "name": "sqlite-framework",
      "version": "2.5.1",
      "purl": "pkg:maven\/androidx.sqlite\/sqlite-framework@2.5.1"
    },
    {
      "type": "library",
      "group": "androidx.sqlite",
      "name": "sqlite",
      "version": "2.5.1",
      "purl": "pkg:maven\/androidx.sqlite\/sqlite@2.5.1"
    },
    {
      "type": "library",
      "group": "androidx.startup",
      "name": "startup-runtime",
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.startup\/startup-runtime@1.2.0"
    },
    {
      "type": "library",
      "group": "androidx.swiperefreshlayout",
      "name": "swiperefreshlayout",
      "version": "1.1.0",
      "purl": "pkg:maven\/androidx.swiperefreshlayout\/swiperefreshlayout@1.1.0"
    },
    {
      "type": "library",
      "group": "androidx.tracing",
      "name": "tracing-ktx",
      "version": "1.2.0",
      "purl": "pkg:maven\/androidx.tracing\/tracing-ktx@1.2.0"
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
      "version": "1.1.0-beta02",
      "purl": "pkg:maven\/androidx.viewpager2\/viewpager2@1.1.0-beta02"
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
      "group": "androidx.work",
      "name": "work-runtime-ktx",
      "version": "2.10.3",
      "purl": "pkg:maven\/androidx.work\/work-runtime-ktx@2.10.3"
    },
    {
      "type": "library",
      "group": "androidx.work",
      "name": "work-runtime",
      "version": "2.10.3",
      "purl": "pkg:maven\/androidx.work\/work-runtime@2.10.3"
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
      "version": "1.10.2",
      "purl": "pkg:maven\/kotlinx\/coroutines_android@1.10.2"
    },
    {
      "type": "library",
      "group": "kotlinx",
      "name": "coroutines_core",
      "version": "1.10.2",
      "purl": "pkg:maven\/kotlinx\/coroutines_core@1.10.2"
    },
    {
      "type": "library",
      "group": "com.squareup.okhttp3",
      "name": "okhttp",
      "version": "5.1.0",
      "purl": "pkg:maven\/com.squareup.okhttp3\/okhttp@5.1.0"
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
      "group": "com.github",
      "name": "jitpack-libraries",
      "properties": [
        {
          "name": "apkrelab:detection",
          "value": "package path; version unknown; artifact id is a best guess"
        }
      ],
      "purl": "pkg:maven\/com.github\/jitpack-libraries"
    }
  ]
}
```

## Edited classes (0)

None.

## AI notes (this session)

None. Use Explain / Patterns / Review manifest first and they will be included.
