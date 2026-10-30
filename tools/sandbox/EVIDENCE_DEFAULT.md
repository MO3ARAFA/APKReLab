# Is evidence = 0.6 honest for HIGH+ cards without an SSA flow? (1.2.0 QA, 2026-10-25)

Question (Item 2 of 1.2.0): a card with no traced data flow gets evidence 0.6 (a rule's pattern match) or 0.8 (the class-level taint rule). If those cards are mostly real, 0.6 is too low; if mostly false, too high.
Sample: every HIGH / CRITICAL card WITHOUT an SSA flow in the 1.2.0 sandbox reports of the apps that could be scanned (the brief asked for up to 10 per app; there were fewer). Each was read in the smali / manifest.

| App | Card | Rule (evidence) | Judgement | Why (from the code) |
|---|---|---|---|---|
| K-9 24.0 | #7 SettingsProvider exported, no permission | manifest-exported-components (0.6) | FP | data methods throw; openFile checks the caller's signing certificate |
| Nextcloud 35.0.1 | #9 FileContentProvider exported, no permission | manifest-exported-components (0.6) | TP-low | isCallerNotAllowed guards URI codes 4-8, 10, 11 only; the rest is open to any app |
| Nextcloud 35.0.1 | #49 RichDocuments JS bridge reaches startActivity | webview-js-bridge-method (0.6) | BY-DESIGN | non-exported editor WebView on the user's own server |
| KeePassDX 4.5.6 | #8 AES/ECB | crypto-cipher (0.6) | BY-DESIGN | KDBX AES-KDF key transformation |
| Paperless 244 | #3 ClipboardFileProvider exported, no permission | manifest-exported-components (0.6) | TP-low | read-only files under the clipboard root, readable by any app |
| Nextcloud 35.0.1 | #44 Intent extra -> WebView.loadUrl | class-level taint (0.8) | FP | ExternalSiteWebView is exported="false": the Intent is the app's own |
| Nextcloud 35.0.1 | #58 provider parameter -> FileOutputStream | class-level taint (0.8) | FP | the provider requires MANAGE_DOCUMENTS (signature / system) |

Result: evidence 0.6 bucket 2 TP-low of 5 (40%); evidence 0.8 bucket 0 of 2. AntennaPod and NewPipe have no HIGH+ card at all; K-9 1, KeePassDX 1.
Decision: **0.6 and 0.8 are kept.** With n = 5 and n = 2 neither rate is "clearly" different (the brief's bar: 8/10 or 2/10). Note that every non-TP here was a protection the rule did not see (a caller-certificate check in code, a signature permission, a non-exported component): the
right fix is in the rules / FindingPolish (device lowering exists for some of these: K-9's provider check is lowered on the device since 0.94.0 per HANDOFF, NOT verified here), not in the evidence constant.
Not measured: the Group A apps (blocked); more than 7 cards; the device's reach / lowering passes on these cards.
