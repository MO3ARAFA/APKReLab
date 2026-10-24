# Company apps: the targets the scanner is tested on (set up 2026-10-18)

These are the apps the owner's company ships. They are the REAL goal of the tool: find the weaknesses before an attacker does. They are not a blind accuracy benchmark: every fix made because of what they showed
contaminates them as a measure (the blind sets are the numbered protocol sets and the permanent held-out set H).

| key | package | version | sha256 (APK as received) | what limits the scanner on it |
|---|---|---|---|---|
| wewallet | com.TE.WEWallet | 1.0.72.3 | 5eb09c73...0ceeb | commercial obfuscator (90% renamed, string encryption, reflection); native code in a config split |
| axispay | com.axispay.consumer.wallet | 3.0.1 | cee951a8...f4dac | Flutter (Dart code invisible), every string decrypted by one native method, 99% renamed into the root package; native code in a config split |

Excluded by the owner's earlier instruction until he lifts it: InstaPay, MyFawry (the closed set 9 of the benchmark).

## Protocol (after every release of the scanner and after every release of a company app)
1. Scan the APK (device or sandbox) and keep the Markdown report OUTSIDE the repository.
2. `python3 tools/company/check_baseline.py <report.md> <key>`: lists every NEW HIGH / CRITICAL card (exit code 1) and the change in counts and scenarios. Read each new card in the code before believing it.
3. After reading every difference: `... --write` to move the baseline. `baselines.json` holds counts and hashes only.
4. Keep the private review memo of each app next to the reports, not in the repository (class names of unfixed findings do not belong in a zip that travels).
5. Compare like with like: the sandbox report has no SCA cards and no AI triage; the device report has both.

## What a clean result does NOT mean on these two apps
Strings that a protector decrypts at run time, Dart code, and native libraries in a split are invisible. "0 findings" of any kind that reads strings is not a pass: dump the strings on a test device (the report prints the Frida snippet)
and give the scanner the config split.
