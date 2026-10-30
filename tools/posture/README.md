# Defense posture (0.91.0)

`PostureScanner.kt` reads, per class of the FULL deep scan, 13 signals of what an app does to resist tampering and interception, and the report prints them as a table (section
"Defense posture"), apart from the vulnerabilities. Two findings only: an INFO summary and a LOW one for the retired SafetyNet API.

Signals: certificate pinning (OkHttp `CertificatePinner.Builder.add`, TrustKit, a custom X509TrustManager that compares a key or digest, the network_security_config `<pin-set>`), root detection
(su paths / root-manager packages in string constants; a RootBeer / JailMonkey call), anti-debugging (`Debug.isDebuggerConnected`, `waitingForDebugger`, `TracerPid`), emulator detection (Build
properties together with at least two emulator names), Frida / Xposed / Substrate detection, signing-certificate read, installer check, Play Integrity, SafetyNet, FLAG_SECURE (0x2000 in the same
method as `Window.addFlags` / `setFlags`, or `SurfaceView.setSecure`), plus the share of renamed classes and of classes that keep `.source` / `.line`.

**Where a hit is** decides what the table says: in the app's own code (under its code package, or a renamed class that refers to it), in code of UNKNOWN origin (renamed without a reference to the app, or a
readable class outside the app's package: it may be an SDK such as Sentry or NetCipher), or LIBRARY only. A root check inside an SDK must not give the feeling that the app is protected.

## Validation (no oracle exists for this, unlike readelf for ELF)
The 37 real APKs: the posture of each (`results-37-apps-0.91.0.tsv`) and the evidence behind every hit that landed in "app code" read in the smali. What reading found and fixed:
"frida" matched FRIDAY (`DayOfWeek` enums) in 10 of 37 apps (now a word-boundary regex: 0 real); root / emulator checks in renamed SDK classes with no reference to the app (Ivy, Infinity) were counted
as the app's (now "origin unknown"); RootBeer's own `Const` class and NetCipher's `TorServiceUtils` (Monerujo) were counted as app code (library / outside the app's package now). Verified as real:
Allsafe's `CertificatePinning` and `RootDetection` (RootBeer call), Termux's `ro.boot.qemu` emulator check, Syncthing-Fork's list of emulator models (`sdk_gphone_x86_arm`, `Android SDK built for x86`:
my first grep missed the second string and I doubted the hit; the detector was right), ProtonMail's TrustKit.
Final map (37 apps): pinning in app code 2 (OkHttp 1, TrustKit 1); root by su paths 0 in app code; RootBeer 2; debugger 1; emulator 2; Frida / Xposed 0; signature read 9; installer 5; Play Integrity 0; SafetyNet 0;
FLAG_SECURE 15 (9 apps have none). These are open-source apps: a missing control is not a flaw there.
Limits: the RECALL of the posture is not measured (an app with a control the signals do not see is not in this table); only Java / Kotlin is read; "in app code" depends on the library list being complete.
Not covered: Magisk / Zygisk via /proc/self/maps, Build.TAGS, the list of Activities that set FLAG_SECURE by name.
