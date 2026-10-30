# Held-out benchmark (0.73.0; PIVAA moved to the tuning set in 0.74.0, Vuldroid in 0.75.0: Allsafe in 0.75.2: held-out now = Sieve only)

Apps the scanner was NEVER tuned on: PIVAA (com.htbridge.pivaa), Allsafe (infosecadventures.allsafe), Vuldroid (com.vuldroid.application).
The tuning set (do not use for accuracy claims): OVAA, InsecureBankv2, AndroGoat, InjuredAndroid, InsecureShop, DVBank.
DIVA was dropped: the project publishes no APK on GitHub and there is no Android SDK to build it.

Rules of the game
- Each list was written from the app's OWN README (vulnerability list) BEFORE the first scan of that app (`independent: true`).
- A rule or title match is a PRESENCE check: it does not prove the finding points at the right class. Entries that accept several rules are lenient on purpose (the README names a family, not a rule), so recall here is an upper bound.
- `out_of_scope` entries (dynamic bypass tasks, iOS text, undefined list, native code) are listed but are not in the recall denominator.
- Do NOT tune the scanner on these apps. If a fix is made for a miss found here, the app moves to the tuning set and a new held-out app must replace it.
- Precision: only HIGH/CRITICAL code findings that match nothing are counted as UNREVIEWED; they become FP or TP only after the smali is read.

    python3 tools/benchmark/bench.py report.md --expected tools/benchmark/expected_heldout/<package>.json --measure
