# Real-app held-out set 4 (frozen 2026-10-13, BEFORE the first scan, tool version 0.79.0)

Purpose: measure precision on apps never seen, after the fixes of sets 1-3 (0.76.0 - 0.79.0 were all tuned on seen apps).
Never scanned by APKReLab before (not in the 15-app study, sets 1-3, the vulnerable-app benchmarks or the tuning set). Java / Kotlin apps.
| app | source | sha256 |
|---|---|---|
| Mihon 0.21.2 arm64-v8a (manga reader: loads EXTENSION APKs = dynamic code, deep links, backups) | github.com/mihonapp/mihon releases | dcfe07027cb000fac92f10303e4bc98feca3e6a4aeb026aaafce8fbe9e5c423f |
| Catima 2.45.1 foss (loyalty cards: file import / export, share intents, barcodes) | github.com/CatimaLoyalty/Android releases | 271980b62f73137db2d843fb4fc35f103c4126d769f816d365206c5c1adff3a9 |
| Breezy Weather 6.2.2 arm64-v8a standard (many weather APIs: keys, location, widgets, network) | github.com/breezy-weather/breezy-weather releases | 829175ceb23d0e539f99b27d22ff10e06ba8d446ac070b28585a36316fd295d5 |

Scoring: as PROTOCOL.md: precision only; every HIGH / CRITICAL (app scope + manifest) read in the smali / manifest and classified TP /
TP-1CLICK / BY-DESIGN / FP; library cards apart; MEDIUM only as a sample. Precision is given by card AND by distinct issue.
First run frozen in runs/ before any change. A fix made because of one of these apps makes it a tuning app.

## FIRST RUN (frozen), 0.79.0 sandbox
Reports: `runs/catima-0.79.0-sandbox-FIRST.md`, `runs/breezy-0.79.0-sandbox-FIRST.md`, `runs/mihon-0.79.0-sandbox-FIRST.md`.
Cards: Catima 17 (1 HIGH), Breezy Weather 58 (4 HIGH), Mihon 34 (2 HIGH). No library card among the HIGH.

| app | card | verdict | why |
|---|---|---|---|
| Catima | SQL from provider parameters, CardsContentProvider.query | BY-DESIGN | the caller's `selection` / `sortOrder` go into `SQLiteDatabase.query` unparameterised (standard provider pattern), but the provider is guarded by `READ_CARDS` (dangerous, user-granted), is off unless the user enables it in settings, and the database only holds the cards / groups the permission already exposes |
| Breezy | Hardcoded credential: JWT (a9) | **TP** | AEMET API token issued to `api@breezyweather.org` (the project's own key) in the code: anyone can extract it and use the project's quota |
| Breezy | Hardcoded credential: JWT (kv3) | **TP** (secrecy unverified) | Met Eireann token (`iss met-jwt`, expires 2218); whether the agency treats it as public was not verified |
| Breezy | Hardcoded credential: JWT (g10) | **TP** (secrecy unverified) | BMKG / Canadian weather client token in the code; same caveat |
| Breezy | file path, MainActivity.onCreate (Parcel source through `o02.next()`) | FP | onCreate deletes the old `<dataDir>/files/objectbox/` tree; the "Parcel" source came through an R8-renamed iterator class (`o02`, not in the default package, so not marked weak) |
| Mihon | NSC cleartext permitted | BY-DESIGN | sources / self-hosted servers over plain HTTP |
| Mihon | NSC trusts user CAs | BY-DESIGN | self-hosted servers with their own CA (same as DAVx5) |

**Precision by card: 3 TP / 4 = 75%; by distinct issue: 1 (hardcoded tokens) / 2 = 50%.** 3 BY-DESIGN. n = 7 HIGH, small.
This is the first set measured AFTER the fixes of sets 1-3 on apps never seen. First runs so far: set 1 1/19 (before any real-app fix),
set 2 3/6, set 3 1/9, set 4 3/4.
Remaining FP family, seen twice now (Ivy `m.r`, Breezy `o02`): taint through R8-renamed classes outside the default package.
