# Real-app precision study (0.68.5, sandbox, 15 open-source apps, no deliberate vulnerabilities)

Harness: `MeasureBig` with entries = EXPORTED components only (same rule as `SecurityScanner.exportedComponents`; before 0.68.5 the harness used every component, so old `reach=Y` numbers were too optimistic). APKs came from the GitHub releases of each project; flows were reviewed by reading the smali and the manifest.

| app | flows | not LOW | note |
|---|---|---|---|
| Aegis 3.4.3 | 1 | 1 | internal activity (not exported) |
| Amaze 3.11.3 | 1 | 1 | guarded by a flag + path validator |
| Fossify Gallery 1.14.0 | 7 | 2 | 5 are SharedPreferences sources |
| KeePassDX 4.5.5 | 0 | 0 | |
| Markor 2.16.1 | 7 | 5 | editor opens/saves the file of a VIEW/EDIT intent (by design) |
| Mifos | 0 | 0 | |
| Mihon 0.20.4 | 3 | 1 | system package broadcast |
| Simplenote 2.39 | 1 | 0 | |
| Termux 0.118.3 | 8 | 7 | RUN_COMMAND is permission-gated by design |
| Focus 108.1.0 | 3 | 2 | GeckoView crash handler (not exported) |
| FairEmail 1.2338 | 12 | 11 | |
| Nextcloud 35.0.1 | 15 | 13 | one shared-field root cause |
| DuckDuckGo 5.297.1 | 1 | 0 | |
| K-9 24.0 | 0 | 0 | |
| Element X 26.09.4 | 0 | 0 | |
| **total** | **59** | **43** | |

Reviewed by hand (code or manifest read): 14 of the 43 not-LOW flows; **all 14 are false positives or by-design behaviour, none a confirmed vulnerability.** The other 29 were not individually verified.

## False-positive causes found (ordered by how many flows they explain)
1. **Source in a component an attacker cannot reach.** Any `Intent.getXxxExtra/getData` is a level-2 source, even when the component is NOT exported (Aegis `ImportEntriesActivity`, Nextcloud `ExternalSiteWebView` / `ErrorsWhileCopyingHandlerActivity`, Focus `CrashHandlerService`), when the Intent is built by the app itself (result intents), or when it is a protected system broadcast (Mihon package removed). Fix idea: a source counts as attacker data only when the component that READS it is exported (or reachable from an exported component through an Intent that the caller controls); otherwise lower the level.
2. **Field-based taint on shared data-class fields.** Nextcloud `OCFile.remotePath` is written once from an Intent extra, so every read (`getDefaultSavePathFor`, 8 verified flows, 3 more by similarity) is tainted. Same root cause as the Bitwarden merged `Object` field, but on a normal field. Fix idea: per-object / per-allocation-site heap for small value classes, or keep the taint only when the writer and the reader are the same component.
3. **Application guards not understood.** Amaze `DatabaseViewerActivity`: the file is deleted only when a private `delete` flag is set (root copy), after `sanitizeInput` + `isValidPath`. Fix idea: treat a boolean field guard as a barrier; recognise project-local validators (a method whose name contains validate/sanitize/isValid and that returns a boolean tested before the sink).
4. **Permission-gated by-design features.** Termux `RunCommandService` (exported, `com.termux.permission.RUN_COMMAND`): the flow to the shell is real and intended. The scanner shows CRITICAL without the permission. Fix idea: read `android:permission` of the entry component and lower the severity when the permission is `dangerous`/`signature`, and say so in the detail.
5. **SharedPreferences sources** (already LOW) and the user-configured server URL (Gemini / OpenAI / LanguageTool in FairEmail, WordPress in Simplenote) are settings, not attacker input.
6. R8 merged classes are still not always weak: FairEmail `Class.forName` flow (`gt.next()`) stayed MEDIUM.

## Plausible, needs a human (not confirmed)
FairEmail `ActivityAMP` (exported VIEW, data of the Intent is loaded into a WebView with JavaScript on; the AMP host list `cdn.ampproject.org` is checked), Markor/Termux file receivers (exported editors/receivers that write where the Intent points), Fossify `fillExtraOutput`.

## Reading of the numbers
- On deliberately vulnerable apps the tool finds almost everything (OVAA 19/19, InsecureBankv2 11/11, AndroGoat 29/30).
- On real apps the headline cards are mostly not vulnerabilities (0 of 14 verified). The taint engine itself is mostly right about the data flow; what is wrong is the SOURCE model (cause 1), the heap model (cause 2) and the missing guard / permission context (3, 4).
- Recall on real apps is unknown (no ground truth): 4 of the 15 apps have 0 flows, which can mean "clean" or "missed".

## Next steps by value / risk
1. Cause 1 (source only counts when the reading component is exported), pure `ir` change, testable here, expected to lower 15-20 of the 43 flows.
2. Cause 4 (permission of the entry component into severity/detail), small and safe.
3. Cause 2 (shared data-class field), bigger change in the taint heap, needs a measured twin test set.

## Update 0.68.6 (cause 1 tried)
Rule: an Intent read in an unexported activity / service is shown as LOW unless an exported (or already reached) component that reads Intent data launches it with an explicit Intent, or an intent-redirection pattern exists in the app (details in HANDOFF). Result: benchmark apps (OVAA, InsecureBankv2, AndroGoat, InjuredAndroid, InsecureShop, DVBank) identical; real apps 43 -> 40 not-LOW flows (Aegis 1, Nextcloud 2; all hand-verified false positives). The broader first version lowered 15 flows but also lowered real vulnerabilities in OVAA, InsecureShop and InjuredAndroid, so it was rejected. Lesson: judge every precision change on the deliberate-vulnerability benchmarks first; the engine's "every Intent getter is a source" is what finds intent-redirection bugs.
