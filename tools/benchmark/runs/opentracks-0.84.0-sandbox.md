# APK ReLab report: de.dennisguse.opentracks.playstore

(sandbox scan, no AI triage)

## Security scan

Heuristic static scan - 118 finding(s) in total; 21 listed below (app/unknown code; INFO and known-library findings left out). Findings are leads: verify manually before relying on any of this.

Not covered by this scan: business-logic flaws (prices, limits, order flows), server-side bugs of the APIs the app calls, and native (C/C++) code; a large app is analysed in groups, so a data flow that crosses groups can be missed.

### Summary

| Severity | Count |
|---|---|
| MEDIUM | 15 |
| LOW | 6 |

**OWASP Mobile Top 10 (2024) coverage**

- M4 Insufficient Input/Output Validation: 11
- M8 Security Misconfiguration: 6
- M9 Insecure Data Storage: 3
- M5 Insecure Communication: 1

### Findings

#### 1. [MEDIUM] Backup allowed (allowBackup)

- Location: `AndroidManifest.xml`
- CWE: CWE-530 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: HIGH | Rule: manifest-allow-backup
- Priority: 45/100 (P2)
- Why flagged: android:allowBackup is not explicitly "false" (it defaults to true). Via `adb backup` (no root needed on many OS versions) or a cloud backup, the app's private data - databases, SharedPreferences, saved tokens - can be extracted.
- Risk scenario: With allowBackup=true, adb backup or a cloud restore can copy the app's private files (databases, preferences) off the device.
- Fix: Set android:allowBackup="false", or if backups are wanted, add a dataExtractionRules/fullBackupContent file that explicitly excludes anything sensitive.

#### 2. [LOW] No network security config referenced

- Location: `AndroidManifest.xml`
- CWE: CWE-319 | OWASP: M5 Insecure Communication | MASVS: MASVS-NETWORK | Confidence: MEDIUM | Rule: manifest-network-security-config
- Priority: 17/100 (P4)
- Why flagged: No android:networkSecurityConfig is set. On devices running API < 28, cleartext HTTP is allowed by default unless a config says otherwise, so this app's real cleartext posture on older phones is unverified here.
- Risk scenario: Plain HTTP can be read and modified by anyone on the path (Wi-Fi owner, ISP, rogue hotspot): session cookies, credentials and downloaded code or config can be stolen or replaced. Without a network security config, devices below API 28 allow cleartext by default. cleartextTrafficPermitted=true in base-config opens every domain; in a domain-config it opens that host only, which is smaller but still readable by anyone on the path.
- Fix: Add a network_security_config.xml with cleartextTrafficPermitted="false" as the base config (and certificate pinning if the app always talks to the same backend).

#### 3. [MEDIUM] Exported activity without a permission: de.dennisguse.opentracks.publicapi.StartRecording

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 4. [MEDIUM] Exported activity without a permission: de.dennisguse.opentracks.publicapi.StopRecording

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 5. [MEDIUM] Exported activity without a permission: de.dennisguse.opentracks.publicapi.CreateMarker

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 6. [LOW] Exported activity without a permission: de.dennisguse.opentracks.io.file.importer.ImportActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 20/100 (P4)
- Note: Lowered to LOW: exported by design (public entry action: SEND, SEND_MULTIPLE, VIEW).
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 7. [MEDIUM] Exported activity without a permission: de.dennisguse.opentracks.publicapi.ShowMarkerActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 8. [MEDIUM] Exported activity without a permission: de.dennisguse.opentracks.publicapi.CreateMarkerActivity

- Location: `AndroidManifest.xml`
- CWE: CWE-926 | OWASP: M8 Security Misconfiguration | MASVS: MASVS-PLATFORM | Confidence: HIGH | Rule: manifest-exported-components
- Priority: 45/100 (P2)
- Why flagged: This activity is exported (usable by other apps) and declares no android:permission. Any other app on the device can start it directly (e.g. to jump past a login screen, trigger a broadcast handler, or bind a service) unless the component itself double-checks the caller.
- Risk scenario: Any installed app can start an exported activity, send to an exported receiver or bind an exported service. Without a permission this exposes internal screens, actions or data (a broken access control). A permission with protectionLevel normal or dangerous does not help: any app can request it, only signature ties it to your signing key. A provider that protects only reads or only writes leaves the other direction open.
- Fix: Add android:permission="..." (a signature-level permission for same-app-only access is often right), or set android:exported="false" if other apps never need to use it.

#### 9. [MEDIUM] ContentProvider.query() may build SQL by string concatenation

- Location: `de.dennisguse.opentracks.data.CustomContentProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: LOW | Rule: provider-sql-injection | Scope: APP
- Priority: 27/100 (P3)
- Note: Lowered one level: this provider is not exported by the manifest, so another app cannot call it directly (only this app, or a URI it grants with grantUriPermissions).
- Why flagged: This provider's query() both concatenates strings (StringBuilder/concat) and runs rawQuery/execSQL. If any part of the SQL comes from the incoming Uri (path segments, a query parameter) or the caller-supplied selection/projection, another app can inject SQL through this exported entry point.  (around line 1179)
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use SQLiteDatabase.query()'s own selection + selectionArgs (parameterized), or rawQuery(sql, selectionArgs) with '?' placeholders; never concatenate caller-controlled text into the SQL string.

#### 10. [MEDIUM] FileProvider shares too much (<external-files-path path="/">)

- Location: `res/8K.xml`
- CWE: CWE-200 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE / MASVS-PLATFORM | Confidence: LOW | Rule: res-fileprovider-paths
- Priority: 27/100 (P3)
- Why flagged: These FileProvider paths cover a whole directory tree (the root of the file system or the app's private data: databases, shared_prefs, tokens). Any content:// URI the app hands out, or lets a caller choose, can then point at files that were never meant to be shared.  [res/8K.xml]
- Risk scenario: Information reaches a party that should not see it (another app, a web page loaded in a WebView, a log, a backup). A provider with grantUriPermissions on the whole provider lets any Intent carrying one of its content:// URIs hand temporary access to every path.
- Fix: List only the specific sub-folder to share (for example path="shared/"), never root-path or path=".", and keep the provider exported="false" with grantUriPermissions="true".

#### 11. [LOW] Keyboard cache: sensitive input field (x3)

- Location: `res/66.xml`
- CWE: CWE-524 | OWASP: M9 Insecure Data Storage | MASVS: MASVS-STORAGE | Confidence: LOW
- Priority: 12/100 (P4)
- Why flagged: The field "(id not resolved)" looks sensitive or is the main input of this screen, but its inputType (not set) does not disable suggestions. The keyboard may learn and cache what is typed (autocorrect dictionary, predictive text).  [res/66.xml]  The same applies to 2 more layout(s): res/J7.xml, res/fu.xml.
- Risk scenario: The keyboard dictionary, screenshots in the recents list, and caches can keep what the user typed.
- Fix: Use android:inputType="textPassword" (or textNoSuggestions|textVisiblePassword) and consider importantForAutofill="no" for secrets.

#### 12. [MEDIUM] Untrusted input is used as a file path

- Location: `de.dennisguse.opentracks.io.file.importer.KMZTrackImporter`
- CWE: CWE-22 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-STORAGE | Confidence: LOW | Rule: taint-flow | Scope: APP | Reachable from an exported component
- Priority: 27/100 (P3)
- Why flagged: Data from ZipEntry.getName() reaches FileOutputStream.<init>() in method KMZTrackImporter.readAndSaveImageFile(Ljava/util/zip/ZipInputStream;Lde/dennisguse/opentracks/data/models/Track$Id;Ljava/lang/String;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. The value travels through 2 methods. A step on the path takes the base name of the value (substring after the last '/'), which removes directory parts: low confidence, check that it covers this value. The value is the name of an archive entry. When the archive comes from outside the app (a download, a file another app shares) a name such as ../../x makes the extraction write outside the target folder (Zip Slip): the target path must be checked with getCanonicalPath() against the extraction folder.
- Risk scenario: A name such as ../../databases/app.db escapes the intended folder, so an exported provider or a zip entry can read or overwrite the app's private files (Zip Slip).
- Fix: Reduce the input to a bare file name (File(name).name), resolve it against a fixed directory, call canonicalFile and check it still starts with that directory.

#### 13. [MEDIUM] Untrusted Intent is launched by this app (intent redirection)

- Location: `de.dennisguse.opentracks.TrackRecordedActivity`
- CWE: CWE-940 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 19/100 (P4)
- Why flagged: Data from Intent.getParcelableExtra() (through field TrackRecordedActivity.trackId:Lde/dennisguse/opentracks/data/models/Track$Id; (written in TrackRecordedActivity.handleIntent(Landroid/content/Intent;)V)) reaches Context.startActivity() in method TrackRecordedActivity.lambda$onOptionsItemSelected$2(Lde/dennisguse/opentracks/services/TrackRecordingService;Lde/dennisguse/opentracks/services/TrackRecordingServiceConnection;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The Intent is read in a component that the manifest does not export (or in a receiver for system broadcasts), so an outside app cannot normally supply this value; it matters only when an exported component forwards an Intent to it (low confidence). No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: An Intent object received from another app is launched as it is, so the attacker chooses which component runs (even a non-exported one) with this app's identity, permissions and URI grants.
- Fix: Do not launch an Intent you received from a caller. Build a new Intent for a fixed component of your own and copy over only the extras you need, or check getComponent() / getPackage() against an allow-list and clear the URI-permission flags before launching.

#### 14. [MEDIUM] Untrusted Intent is launched by this app (intent redirection)

- Location: `de.dennisguse.opentracks.TrackRecordedActivity`
- CWE: CWE-940 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 19/100 (P4)
- Why flagged: Data from Intent.getParcelableExtra() (through field TrackRecordedActivity.trackId:Lde/dennisguse/opentracks/data/models/Track$Id; (written in TrackRecordedActivity.handleIntent(Landroid/content/Intent;)V)) reaches Context.startActivity() in method TrackRecordedActivity.onOptionsItemSelected(Landroid/view/MenuItem;)Z. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The Intent is read in a component that the manifest does not export (or in a receiver for system broadcasts), so an outside app cannot normally supply this value; it matters only when an exported component forwards an Intent to it (low confidence). No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow. 2 flows of this kind end in this method.
- Risk scenario: An Intent object received from another app is launched as it is, so the attacker chooses which component runs (even a non-exported one) with this app's identity, permissions and URI grants.
- Fix: Do not launch an Intent you received from a caller. Build a new Intent for a fixed component of your own and copy over only the extras you need, or check getComponent() / getPackage() against an allow-list and clear the URI-permission flags before launching.

#### 15. [MEDIUM] Untrusted Intent is launched by this app (intent redirection)

- Location: `de.dennisguse.opentracks.TrackRecordingActivity`
- CWE: CWE-940 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 19/100 (P4)
- Why flagged: Data from Intent.getParcelableExtra() (through field TrackRecordingActivity.trackId:Lde/dennisguse/opentracks/data/models/Track$Id; (written in TrackRecordingActivity.onCreate(Landroid/os/Bundle;)V)) reaches Context.startActivity() in method TrackRecordingActivity.lambda$onCreate$3(Landroid/view/View;)Z. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The Intent is read in a component that the manifest does not export (or in a receiver for system broadcasts), so an outside app cannot normally supply this value; it matters only when an exported component forwards an Intent to it (low confidence). No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: An Intent object received from another app is launched as it is, so the attacker chooses which component runs (even a non-exported one) with this app's identity, permissions and URI grants.
- Fix: Do not launch an Intent you received from a caller. Build a new Intent for a fixed component of your own and copy over only the extras you need, or check getComponent() / getPackage() against an allow-list and clear the URI-permission flags before launching.

#### 16. [MEDIUM] Untrusted Intent is launched by this app (intent redirection)

- Location: `de.dennisguse.opentracks.TrackRecordingActivity`
- CWE: CWE-940 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 19/100 (P4)
- Why flagged: Data from Intent.getParcelableExtra() (through field TrackRecordingActivity.trackId:Lde/dennisguse/opentracks/data/models/Track$Id; (written in TrackRecordingActivity.onCreate(Landroid/os/Bundle;)V)) reaches Context.startActivity() in method TrackRecordingActivity.onOptionsItemSelected(Landroid/view/MenuItem;)Z. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The Intent is read in a component that the manifest does not export (or in a receiver for system broadcasts), so an outside app cannot normally supply this value; it matters only when an exported component forwards an Intent to it (low confidence). No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow. 3 flows of this kind end in this method.
- Risk scenario: An Intent object received from another app is launched as it is, so the attacker chooses which component runs (even a non-exported one) with this app's identity, permissions and URI grants.
- Fix: Do not launch an Intent you received from a caller. Build a new Intent for a fixed component of your own and copy over only the extras you need, or check getComponent() / getPackage() against an allow-list and clear the URI-permission flags before launching.

#### 17. [MEDIUM] Untrusted Intent is launched by this app (intent redirection)

- Location: `de.dennisguse.opentracks.TrackStoppedActivity`
- CWE: CWE-940 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 19/100 (P4)
- Why flagged: Data from Intent.getParcelableExtra() (through field TrackStoppedActivity.trackId:Lde/dennisguse/opentracks/data/models/Track$Id; (written in TrackStoppedActivity.onCreate(Landroid/os/Bundle;)V)) reaches Context.startActivity() in method TrackStoppedActivity.lambda$resumeTrackAndFinish$6(Lde/dennisguse/opentracks/services/TrackRecordingService;Lde/dennisguse/opentracks/services/TrackRecordingServiceConnection;)V. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The Intent is read in a component that the manifest does not export (or in a receiver for system broadcasts), so an outside app cannot normally supply this value; it matters only when an exported component forwards an Intent to it (low confidence). No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: An Intent object received from another app is launched as it is, so the attacker chooses which component runs (even a non-exported one) with this app's identity, permissions and URI grants.
- Fix: Do not launch an Intent you received from a caller. Build a new Intent for a fixed component of your own and copy over only the extras you need, or check getComponent() / getPackage() against an allow-list and clear the URI-permission flags before launching.

#### 18. [LOW] Untrusted input reaches an SQL statement

- Location: `de.dennisguse.opentracks.data.CustomContentProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 8/100 (P4)
- Why flagged: Data from a ContentProvider method parameter reaches SQLiteDatabase.delete() in method CustomContentProvider.delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. This ContentProvider is not exported by the manifest (no exported=true, no intent filter), so another app cannot call it directly: it is reached only by this app itself or through a URI the app grants (grantUriPermissions): low confidence, check how the app uses its provider; No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.  Also matched by: taint-flow (merged).
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 19. [LOW] Untrusted input reaches an SQL statement

- Location: `de.dennisguse.opentracks.data.CustomContentProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 8/100 (P4)
- Why flagged: Data from a ContentProvider method parameter reaches SQLiteQueryBuilder.appendWhere() in method CustomContentProvider.query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. This ContentProvider is not exported by the manifest (no exported=true, no intent filter), so another app cannot call it directly: it is reached only by this app itself or through a URI the app grants (grantUriPermissions): low confidence, check how the app uses its provider; The chain also contains validation-like calls (startsWith, matches, getHost, canonical path, allow-list contains ...): verify that they really restrict this value before the sink. No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow. 4 flows of this kind end in this method.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 20. [LOW] Untrusted input reaches an SQL statement

- Location: `de.dennisguse.opentracks.data.CustomContentProvider`
- CWE: CWE-89 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM / MASVS-CODE | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 8/100 (P4)
- Why flagged: Data from a ContentProvider method parameter reaches SQLiteDatabase.update() in method CustomContentProvider.update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. This ContentProvider is not exported by the manifest (no exported=true, no intent filter), so another app cannot call it directly: it is reached only by this app itself or through a URI the app grants (grantUriPermissions): low confidence, check how the app uses its provider; No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: Input such as ' OR '1'='1 changes the meaning of the query: an attacker (or another app calling an exported ContentProvider) can read other rows, bypass a login check or modify data.
- Fix: Use selection arguments (?) or Room parameters for every value; never concatenate input into SQL. Allow-list table, column and ORDER BY names.

#### 21. [MEDIUM] Untrusted Intent is launched by this app (intent redirection)

- Location: `de.dennisguse.opentracks.ui.markers.MarkerListActivity`
- CWE: CWE-940 | OWASP: M4 Insufficient Input/Output Validation | MASVS: MASVS-PLATFORM | Confidence: LOW | Rule: taint-flow | Scope: APP
- Priority: 19/100 (P4)
- Why flagged: Data from Intent.getParcelableExtra() (through field MarkerListActivity.trackId:Lde/dennisguse/opentracks/data/models/Track$Id; (written in MarkerListActivity.onCreate(Landroid/os/Bundle;)V)) reaches Context.startActivity() in method MarkerListActivity.onOptionsItemSelected(Landroid/view/MenuItem;)Z. Found by the SSA data-flow engine, which follows values through registers, fields and calls between methods and classes and keeps reused registers apart; no sanitizer was seen on the way. An Intent is controlled by the caller when the component is exported or opened through a deep link; check the manifest and the reachability field. The Intent is read in a component that the manifest does not export (or in a receiver for system broadcasts), so an outside app cannot normally supply this value; it matters only when an exported component forwards an Intent to it (low confidence). No exported component reaches this method in the call graph: it may be internal-only, or reached through an implicit Intent, reflection or a lambda the graph does not follow.
- Risk scenario: An Intent object received from another app is launched as it is, so the attacker chooses which component runs (even a non-exported one) with this app's identity, permissions and URI grants.
- Fix: Do not launch an Intent you received from a caller. Build a new Intent for a fixed component of your own and copy over only the extras you need, or check getComponent() / getPackage() against an allow-list and clear the URI-permission flags before launching.

### Remediation guide

One entry per weakness type found above.

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


