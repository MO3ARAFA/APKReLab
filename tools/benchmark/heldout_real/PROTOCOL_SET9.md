# Real-app set 9: three closed-source financial apps supplied by the owner (frozen 2026-10-16, BEFORE the first scan)

Source: the three APKs were uploaded by the owner (not downloaded by the assistant), so the hashes below are of the files as received. Closed source: there is no repository to cross-check, every verdict comes from reading the smali / manifest. The owner is the developer of the scanner, not of these apps: any finding that looks real is for the vendor (report it privately), it is NOT to be exploited or published.
Tool version at freezing: 0.85.0 working tree (0.84.0 + trust-all severity restore), `SandboxScanReach` (reach-aware). Nothing is changed after freezing; a fix made because of one of these apps makes that app a tuning app.
| app | file | sha256 | dex / classes | .so |
|---|---|---|---|---|
| Axis Pay consumer wallet 3.0.1 | com_axispay_consumer_wallet_3_0_1.apk | cee951a89400ab360b5d73850fe53e4892056c058b32ee78452d2d912e2f4dac | 2 / 18,093 | 0 |
| InstaPay (Egyptian banks) 1.12.0 | com_egyptianbanks_instapay_1_12_0.apk | 0e6cb20568c3bcb5ceab708f5d62634195366c5a37f5e1c8020e6eec631a4644 | 5 / 36,761 | 0 |
| MyFawry 6.9.3 | com_fawry_myfawry_6_9_3.apk | ca4a849616497eda7060cdcb6f117aa1112d3621a2eb93d0e56b61cd31c97ab6 | 15 / 128,594 | 0 |
No .so in any of the three: split APKs, the native libraries (if any) are in a split the scanner never saw: the native-code card is expected. MyFawry is more than twice the size of JustMarkets (59,667 classes): the sandbox (4 GB RAM, 3.4 GB disk) may not hold it; if it cannot be scanned, that is reported as such and not replaced by a smaller app.
Scoring as PROTOCOL_SET4.md. No recall list exists for these apps. Expectation written before scanning: apps of this kind are R8-obfuscated, so most HIGH / CRITICAL candidates will be in obfuscated code; the owner's question is whether "few HIGH" is honest, as it was for JustMarkets.

## FIRST RUN (frozen) on the 0.85.0 working tree, reach-aware sandbox: Axis Pay and InstaPay
Reports: the two first-run reports of Axis Pay and InstaPay (0.85.0) were MOVED OUT of the repository in 0.101.1 (they list findings of company apps): they live in the owner's private archive `PRIVATE-company-run-reports.zip`. MyFawry: NOT scanned yet (129k classes; the sandbox keeps every class text in memory: it needs a streaming mode first).
Cards: Axis Pay 85 (4 HIGH), InstaPay 55 (7 HIGH). The verdicts below are PRELIMINARY: only the manifest / package facts named in the "evidence" column were read; the smali of the code behind each card was not read yet.

| app | card(s) | preliminary verdict | evidence read |
|---|---|---|---|
| Axis Pay | Zip Slip, `com.braze.support.WebContentUtils` | library, BY-DESIGN / FP | Braze SDK (not in the library list: scope empty); the archive is the SDK's own in-app-message package from its servers |
| Axis Pay | Intent extras -> WebView.loadUrl, `BrazeWebViewActivity` | FP (probable) | manifest: exported=false (SDK component, started by the SDK itself) |
| Axis Pay | Intent extras -> WebView.loadUrl, `MoEActivity` | FP (probable) | manifest: exported=false (MoEngage SDK) |
| Axis Pay | Intent extras -> Class.forName, `u5` (OBF) via `PushClickDialogTracker.extras` | FP (probable) | MoEngage `PushClickDialogTracker`: exported=false (check of the code NOT done) |
| InstaPay | JS bridge reaches reflection, `com.dynatrace.android.agent.JavascriptAgentInterface` | library, BY-DESIGN | Dynatrace OneAgent SDK (not in the library list) registers its own bridge on WebViews |
| InstaPay | 6 ECB / 3DES `crypto-cipher` cards in `meezapaysl.input.SecureLibrary`, `meezapaysl.TR31`, `skb.SkbManager` | TRUE OBSERVATION, probably BY-DESIGN (payment scheme) | the classes are the Meeza payment SDK (`DESede/ECB/NoPadding`, `TR31` = ANSI X9.143 key blocks): 3DES ECB NoPadding on 8-byte blocks is the PIN-block / key-wrap format of card schemes, but 3DES is deprecated by NIST (2023): a real weakness of the scheme, not a bug of the app; the call sites were NOT read |
Counting: Axis Pay 0 TP / 4, InstaPay 0 TP / 7 (as preliminary). New FP family: well-known SDKs missing from the library list (Braze, MoEngage, Dynatrace, Airbridge), and non-exported SDK components with an Intent source.
Pending: the real findings of these apps are probably not in the HIGH list (financial apps are obfuscated; "few HIGH" must be argued as it was for JustMarkets): read the MEDIUM cards of each app and the manifest attack surface (exported components, deep links), and scan MyFawry.


## STOPPED at the owner's request (2026-10-17)
The owner asked to exclude the apps he supplied from the further work. Nothing more is done on Axis Pay, InstaPay or MyFawry: MyFawry was never scanned, the smali behind the cards was not read, no verdict is final. The two first-run reports and the preliminary table above stay as the record of what was run; they are NOT precision data and are not counted in any running total. The only thing that came out of this set is a scanner defect (Axml, see HANDOFF 0.85.0), found from the decoded manifest of InstaPay, without analysing the app's code.
