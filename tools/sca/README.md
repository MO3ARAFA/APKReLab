# SCA database (0.87.0)

`app/src/main/assets/vulns.json` = the 32 hand-checked entries + 1,240 entries generated from the GitHub Advisory Database (reviewed advisories, Maven ecosystem,
CC-BY 4.0) for packages an Android app can plausibly bundle (`PREFIXES` in gen_vulns.py). Regenerate: `git clone --depth 1 --filter=blob:none --sparse
https://github.com/github/advisory-database.git && git sparse-checkout set advisories/github-reviewed`, then `python3 tools/sca/gen_vulns.py <checkout> app/src/main/assets/vulns.json <out>`.
Entries with `src: "ghsa"` are generated; a generated advisory whose CVE is already in a hand-checked entry of the same coordinate is skipped.

Checks (tools/sca):
- `oracle.py` + `ScaOracle.kt`: boundary versions (introduced, fixed, last_affected and their neighbours) of every generated range: the app's matcher against a separate implementation of
  the OSV range semantics on the raw data: 6,926 of 6,968 pairs identical; the 42 that differ are server-side libraries with exotic version suffixes (jetty `v20190403`, jgit `202109080827-r`,
  xerces, spring); 0 differences in okhttp, jackson, bouncycastle, protobuf, guava, gson, netty, commons, jsoup, grpc.
- `ScaApps.kt`: the library scanner on real APKs. results-37-apks-*.txt: baseline (hand-checked list only) flagged 2 libraries with a known version, BOTH false positives (grpc-java-okhttp/1.62.2 read
  as OkHttp 1.62.2); with the database: 5 flagged, all true (okhttp 4.9.0, 3.14.9; bcprov-jdk18on 1.78; bcprov-jdk15on 1.70 x2).
Limits: a version is only known when the APK says so (META-INF, pom.properties, strings); path-only libraries keep version "?" and get a list of advisories that exist for older releases.
Version order is Maven-like but not Maven's full algorithm (unknown suffixes count as a release). "Affected" is by version only: whether the app uses the vulnerable code is not checked.
