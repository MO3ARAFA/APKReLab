# Real-app set 11 (frozen 2026-10-28 BEFORE the first scan; tool 0.93.0, `SandboxScanReach`)

Purpose: a larger blind look before calling the tool ready for daily use: 9 open-source apps never scanned by APKReLab, chosen for variety (mail, VPN, browser, maps with a big native core,
Matrix messenger, gallery, authenticator, map editor, a Flutter chat app), plus InjuredAndroid (an intentionally vulnerable app with published challenges) as a recall check.
Sources: the latest GitHub release of each (k9mail 24.0, ProtonVPN 5.20.74.0 vanilla-direct, DuckDuckGo 5.298.1, Organic Maps 2026.09.29-32, Element X 26.09.4 fdroid arm64, Fossify Gallery 1.14.0,
Bitwarden Authenticator 2025.1.0, StreetComplete 63.4, Zulip (Flutter) 30.0.274, InjuredAndroid 1.0.12). Hashes are recorded in s11_hashes.txt when downloaded.
Rule: first-run cards are frozen; every HIGH / CRITICAL card is read; fixes are allowed (this is a tuning set), the counts of the FIRST run are the blind measure.
