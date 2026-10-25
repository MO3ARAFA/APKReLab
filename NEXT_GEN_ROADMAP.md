# APKReLab: next-generation roadmap (written 2026-10-24, at 0.102.0)

A plan, not a promise. Every item names the evidence it rests on, the measurement that has to come first, and the test that says "done". The rules of
`CLAUDE.md` apply to every line: measure before building, compare the flow SET (not the count), negative twins, mutation checks, no tuning to app names,
measure at `-Xmx1000m` before holding more in memory. Sources read for this plan: `BLUEPRINT.md`, `HANDOFF.md`, `tools/sandbox/PERF.md`, the `ir` package
(`TaintIr`, `ScopePlanner`, `CallSkeleton`, `SsaGroups`, `CallGraph`), `Agent.kt`, `NativeScanner.kt`, `ScanRulesResources.kt`.

## 0. Corrections to the brief this plan was asked from (checked against the code and the logs)

| claim in the brief | what the repository says | consequence |
|---|---|---|
| "Parcel cross-class taint is missing" | `Parcel.read*` has been a taint source since 0.74.0 inside unmarshalling methods (`TaintIr` ~l.272-279, ~l.1309); a value read in one method and used in another is deliberately WEAK since 0.83.0 (FairEmail: 9 HIGH false positives from Parcelables that only travel inside the app). | Not a gap to "implement". The open question is narrower: Parcelables that DO cross a process boundary (exported components) - see B2. |
| "`Method.invoke` propagation is missing" | True: `TaintIr` states "no reflection". But the 6,424 real taint drops on Axis Pay have renamed classes as top owners; nobody has shown one hidden flow behind reflection (HANDOFF 0.100.0). | Measure first (B3). |
| "80k+ classes cause OOMs" | The recorded OOM was in the sandbox harness `SandboxScanReach` that holds every class; the device path already reads class text on demand and keeps parsed IR behind soft references (`SsaGroups`, PERF.md "Streaming"). No 80k-class device run is recorded. | "On-demand streaming" exists. What is missing is a device measurement of a big app and the cost of re-parsing when soft references are cleared (A2). |
| "cross-group method summary caching" | Measured in 0.101.1 (`MeasureReuse`): 64% of method instances repeat, but weighted by call-graph edges only 17% do. The call graph is 45% of CPU, so the ceiling is about 8% of total time. Not built for that reason. | Not in this plan unless a new idea changes the measurement. A1 is a different cache (whole-group results across scans). |
| "20 minutes down to 3 minutes" | The 20 minutes (Axis Pay, 1,185 s, 2 threads, 0.99.0) predate 0.101.x (sandbox -28% to -43%; device not re-timed). Device timings vary about 36% run to run. GC was 43-47% of a 1 GB run. | No number is promised. Target metric: device wall time of two Deep-scan runs, before and after each step. |
| "string decryption overlay (Frida)" | Done in 0.102.0 (`StringOverlay`), tested on synthetic smali only. | B1 is its validation on a real dump. |
| "Dagger/Hilt fan-out hubs are unchecked" | `ScopePlanner.HUB_CALLEES = 100` (0.101.1): flow sets identical on 5 apps, analysis CPU -10% to -20%. `CallSkeleton.MAX_DESCENDANTS = 64`. | Done. |

## 1. Where the engine stands (measured, from PERF.md / HANDOFF)

- Pipeline: smali text -> `SmaliParser` -> CFG -> SSA -> per-group RTA call graph -> inter-procedural taint with method summaries, field-based heap
  (`HeapKey` already has an object slot, always `GLOBAL` today), SharedPreferences keys, depth 6.
- Big apps: `ScopePlanner` marks source/sink classes and the entry slice, then covers them in groups of up to 3,000 classes (`MainActivity.ssaFindings`; one run up to 6,000). Axis Pay (18,093 classes):
  26 groups since the hub cap, each unique class analysed about 10 times across groups (70,814 slots for 7,173 classes before the cap).
- CPU (sandbox, 3 GB): call graph about 45%, taint about 20%, parse about 1%. At 1 GB, GC is about 45% of wall time. 57% of sampled allocation is
  strings / byte arrays under regex code in the parser. **The phone is memory-bound, not CPU-bound.**
- Test assets: `ir` 287 tests, Kotlin 293, recall kit 43 must-cases + probes, 37+ decoded real apps (not in this container), held-out set H.

## Phase A: performance, aimed at memory and repeated work

Gate for every A item: flows (set, with drop owners) identical on Axis Pay, WE Wallet, Fossify, Jellyfin, OVAA; `-Xmx1000m` measurement before / after;
two device runs.

**A0. Device baseline (first, everything else depends on it).** Two Deep-scan runs of Axis Pay on 0.102.0; the status line already prints plan time,
group time, threads, heap, cores, parse vs analysis CPU and "groups re-run for memory". Without this, no A item can claim a gain.

**A1. Incremental re-scan: a group-result cache across scans (new idea, not the rejected one). DONE in 0.104.0 (see HANDOFF; unchanged rescan: 19 of 19 groups reused on the sandbox corpus; device cost unmeasured).** The owner re-scans the SAME app after every scanner or app
release, and after importing a strings dump. A group's result depends only on its class texts, the entry set and the engine version. Key =
hash(engine version, entry types, sorted hashes of the group's class texts); value = the group's picked items + stats (a few KB). Stored on disk, not in RAM.
Expected effect: an identical re-scan skips every group (plan only); a strings overlay re-runs only groups that contain an affected class. Cost: one hash per
class text (already read by the planner). Risk: a stale key. Test: change one class -> only its groups re-run; flip the engine version -> nothing is reused;
mutation: drop the entry set from the key -> a test that changes entries must fail.

**A2. Less garbage in the parser.** (0.103.0: hand-written scanner; 0.104.3: instruction strings shared, edge / phi lists compact: peak live -19..-27%, see PERF.md.) 57% of allocation sits under regex in `SmaliParser` / `CallSkeleton`. A hand-written line scanner for the hot patterns
(invoke, const-string, field refs) plus interning of type / method descriptors. Measure first: JFR allocation profile at `-Xmx1000m` on Axis Pay; target
metric = GC time and full GCs, then wall time. Same output required byte for byte: `ClassIr` dump of 1,000 classes before / after.

**A3. Soft-reference churn.** At 1 GB the GC clears the parsed-IR soft cache and classes are parsed again. Count re-parses per class (a counter, no
behaviour change). If they are significant, try a compact binary IR on disk (`workspaces/p1/ir/`) read instead of re-parsing. Only if A3's counter shows it.

**A4. Threads by measured memory, not by heap size alone.** Today `min(cores - 1, heap / 1000 MB)`. After A0, adjust from the device's own numbers
("re-run for memory" > 0 means fewer threads). No guess without A0.

Not in Phase A: a bigger group size (changes the flow set, no gain at 1 GB, measured), the method-summary cache (ceiling about 8%, measured).

## Phase B: engine fidelity, each item measured on real apps first

**B1. Validate the strings overlay on a real dump (0.102.0 feature).** Axis Pay: dump with the report's Frida snippet, import, Deep scan. Report: call
sites replaced / unresolved, new cards by rule, each new HIGH read in the smali. If "unresolved" is large, look at WHY (index computed, passed as a
parameter) before extending the resolver. Same check on WE Wallet's DexGuard-style `([I[BZ[Ljava/lang/Object;)V` decryptor: a different shape, needs its own
dump format.

**B2. Parcelables that cross a process boundary.** Narrow version of the brief's Parcel item: a Parcelable read from an Intent extra of an EXPORTED
component (`getParcelableExtra` in an exported entry), whose `createFromParcel` fields reach a sink. Census first on the 37 decoded apps: how many
exported entries read a Parcelable extra at all. Build only if the census finds candidates; negative twin = the same class used only internally (the
FairEmail shape stays weak).

**B3. Reflection.** Census first: add `Method.invoke` / `Constructor.newInstance` to the taint-loss counters (measurement only), rescan the 37 apps, read the
top sites. Model only the shape that appears: `Class.forName(<const>).getMethod(<const>)` resolved to a call edge when both names are constants (or
overlay-decoded). A computed name stays unresolved (it is a `T_REFL` sink already).

**B4. Object-sensitive heap.** Infrastructure exists (`HeapKey.obj`). The 0.79.0 census found 1 of the judged HIGH false positives caused by field
conflation; postponed twice for lack of data. Re-run the FlowDump census on the current tuning sets; build allocation-site keys only if conflation explains
at least several judged FPs, with the flow set compared on the reference apps.

**B5. Taint-loss budget per app.** The `Stats` line already names the top owners of real drops. Promote it to a report section ("where the engine lost
taint, and why") so B2 / B3 / B4 are chosen by data from every scan the owner sends.

## Phase C: the AI Hub as an agent that reads the engine, with deterministic fixes

What exists (`Agent.kt`): 27 tools (classes, search, Java view, findings, manifest, entry points, scan, propose / revert edits, build, install, manifest
quick fixes, report). What is missing is the engine's own knowledge.

**C1. Graph tools for the agent.** `callers(method)`, `callees(method)`, `flow_path(findingId)` (source -> sink chain with the SSA steps),
`why_weak(findingId)` (the lowering reason), all read from the call index / `SsaBridge` items the scan already built (no new analysis, no AI in the
answer). Test: tool output equals the card's chain on the recall-kit classes.

**C2. Deterministic fixes first, AI patches second.** Fix templates where the right change is known and local: manifest flags (done:
`queue_manifest_fix`), `FLAG_SECURE`, `setAllowFileAccess(false)`, trust-all `TrustManager` -> platform default, `MODE_WORLD_READABLE` -> private, ECB ->
GCM is NOT a template (data format change). Each template = a smali patch, rebuilt and re-scanned: the card must disappear and no new card may appear
(the check that turns a patch into evidence). AI-generated patches stay proposals with the same rebuild + re-scan check.

**C3. "PR" where there is source.** APKReLab works on APKs. A pull request needs the app's source; for the owner's own apps the agent can emit a source-level
diff suggestion next to the smali fix, labelled as unverified until built.

**C4. Triage by rules before AI.** 0.102.0 replaced two AI verdicts with deterministic guards (CMAC zero block, fixed shell arguments). Continue with
every AI "false positive" verdict that repeats on two apps: turn it into a guard with a negative twin, measure the card count before / after.

## Phase D: hybrid apps

Measured gap: **`assets/` is not read by any rule** (`ResourceScanner` reads `res/*.xml` and `resources.arsc` only). React Native, Cordova / Capacitor and
many config files live there.

**D1. Assets text scan (cheap, first).** `assets/**/*.js|json|html|properties|xml|txt` under a size cap, streamed: the secret formats (`SecretFormats`,
206 formats), cleartext URLs, Firebase / Google config keys. A plain JS bundle is text. Negative twins: minified library code, documentation hosts (the
deny list `native-flutter` already uses).

**D2. Hermes bytecode (`index.android.bundle` with the HBC magic). DONE for version 96 in 0.104.0 (string table only, validated on 3 real bundles; other versions are reported, not guessed).** Parse the header and the string table only (string kinds, offsets, the small /
overflow tables), feed the strings to D1's rules. The format is versioned (the bytecode version is in the header): support the versions found in real
APKs, validate against a reference disassembler on those files, and print "unsupported HBC version N" otherwise. No function decoding in the first step.

**D3. Flutter.** Already: `libapp.so` strings scanned (secrets, hosts), Flutter card, split support, installed-apps picker (0.102.0) to get the split
without a PC. Next: F of the current task list (read a real `libapp.so` through the split) and record what the strings show. Object-pool / Dart-version
specific decoding (blutter-style) is version-locked and heavy: only after D3's first reading shows what is missing.

**D4. Cross-layer edges.** JS bridge methods are already judged by their exposed methods (`webview-js-bridge-method`). For React Native, list the
`@ReactMethod` methods of native modules as entry points of the taint (they receive JS data): a source definition, one rule, twins.

## Order and acceptance

1. A0 (device timing), B1 (real dump), D1 (assets), F (splits): evidence that decides the rest, mostly owner-side runs.
2. A1, C1, B5: low risk, testable here, no change to existing results.
3. A2, D2, C2: medium, each with byte-identical / flow-identical checks.
4. B2, B3, B4, D4: only after their census shows candidates.

"Done" for any item: tests with negative twins, a mutation check for engine changes, flow set identical where nothing should change, numbers before and
after in the commit message and `HANDOFF.md`, and a plain list of what was not measured.

## Recorded by the 1.2.0 QA round (not built; each needs its own measurement first)
- **Sanitizer in a callee reached through an interface** (Paperless 244, expo ClipboardFileProvider): openFile hands the Uri to a path strategy (`ClipboardFileProvider$b.a`, implemented by `$c.a`) that does File(root, path) -> getCanonicalFile -> "still under root" else SecurityException. The SSA flow to ParcelFileDescriptor.open is reported (HIGH, MUST FIX, CRITICAL PATH) although the traversal is blocked; the chain's validation sentence is not added either (the check is not in a method of the reported path). Census first: how many provider / file flows in the corpus pass a getCanonicalFile + startsWith + throw in a callee.
- **Code-level caller checks of exported providers** (K-9 SettingsProvider: signing-certificate check in openFile, other methods throw; Nextcloud FileContentProvider: per-URI uid check): the manifest rule stays HIGH in the sandbox. HANDOFF says K-9's case is lowered on the device since 0.94.0: verify the device report before any change.
- **Hybrid code**: Dart (libapp.so) and JavaScript / Hermes code are read as strings only; NOT SEEN says so since 1.2.0. No analysis planned without a measurement of what the strings miss.
