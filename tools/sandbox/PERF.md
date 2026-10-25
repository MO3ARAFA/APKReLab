# Speed of the grouped taint analysis (measured 2026-10-31, 0.101.0)

Tools: `MeasureBig` (the device's pipeline: ScopePlanner.groups + SsaGroups.run; `-Dmax=<classes per group>`, thread count as 3rd argument; prints PLAN, RETRIED, TIME, FLOWS, STATS),
`tools/perf/MeasurePlan.java` (the plan only: class slots against unique classes). Profile with `java -XX:StartFlightRecording=...` and `java -m jdk.jfr/jdk.jfr.internal.tool.Main print --events jdk.ExecutionSample rec.jfr` (the `jfr` launcher is not installed in the sandbox).
Sandbox: ONE core, so thread counts cannot show a parallel gain there; GC and memory effects are real.

## What was measured (Axis Pay, 18,093 classes, 10,586 outside libraries)
- The plan: 31 groups, 70,814 class slots for 7,173 unique classes: every class is analysed about 10 times (x9.87; 64 classes are in all 31 groups).
- CPU profile (4,958 samples): 44.7% `CallGraph.build` (rebuilt per group), 19.6% `TaintIr.analyze`, parse about 1%, SSA build about 1%. Hot lines: `CallGraph.addEdge` (the "caller|insn|callee" string, 9%) and `CallGraph.dispatch` (18%).
- At a 1 GB heap (a phone-like regime) 43 to 47% of the run time is garbage collection (63 full GCs). The device report of a smaller app said "2 group(s) re-run for memory": the phone is in that regime. Run-to-run variance on the phone: the same code took 1,185 s and 1,613 s for the groups of the same app.

## Changes that keep the result identical (flows, plan, taint-loss counters and drop owners compared on 5 apps; `ir` tests 285)
| change | 3 GB heap, 2 threads | 1 GB heap |
|---|---|---|
| dispatch memo + edge keys as ints in a compact long set (`LongSet`) | wall -28% to -34% (Axis 116 s to 76 s, WE 46 to 33, Fossify 31 to 22, Jellyfin 52 to 36) | 2 threads 138 s to 117 s; 1 thread 102 s to 78 s |
| a first version with a HashSet per (caller, callee) pair | -13% to -34% | NO gain (138 s vs 139 s) and more GC: it kept more memory alive |
| threads by heap (1 per 1000 MB instead of 256 MB) | not measurable on one core | 2 threads -> 1 thread: 117 s to 78 s (GC 59 s to 23 s) |

## What changes the result (not adopted)
Group size on Axis (flows: 18 in every case but one flow differs): 5000 classes = 8 groups, analysis CPU 137 s to 96 s at 3 GB, NO gain at 1 GB (250 s); 8000 = 3 groups, 55 s at 3 GB, does not finish at 1 GB. The phone is memory-bound, so a bigger group is out.

## Not done
The x10 redundancy itself (a shared call-graph skeleton or method summaries across groups would change what a group sees), the allocation sources inside the parser (57% of the sampled allocation is strings and byte arrays, most of it under regex code in the parser), on-device measurement.

## 0.101.1: callee hubs and the reuse question (Axis Pay unless said)
- **Fan-out cap** (`ScopePlanner.HUB_CALLEES`, default 100, `-Dapkrelab.hubCallees=0` = off): an unmarked class that calls 100 or more classes is a callee but its own callees are not pulled into the group at the second hop. Flow sets compared against the same engine without it:
| threshold | Axis groups | Axis analysis CPU | Axis flows | wallet / Fossify / Jellyfin / OVAA |
|---|---|---|---|---|
| off | 31 | 116 s | 18 | (baseline) |
| 400 | 31 | 118 s | identical | - |
| **100 (adopted)** | 26 | 103 s (-11%) | **identical** | identical; CPU wallet 44 to 35 s, Fossify 16 to 14, Jellyfin 52 to 41 |
| 200 | 29 | 116 s | +1 flow | identical |
| 50 | 22 | 99 s | +1 / -1 (a flow swapped) | - |
  The set of flows is not monotonic in the threshold (200 found one more, 50 lost one and found another): the choice rests on 5 apps, not on a law. Tests: a 120-callee helper is not expanded, a 40-callee one and a MARKED 150-callee class still are; switching the feature off makes the positive test fail.
- **Can a cache be shared between groups?** `MeasureReuse` records, for every method of every group's finished call graph, the hash of its resolved call sites. On Axis Pay (137,013 method-in-group instances, 17,467 distinct methods): 64% of the instances resolve exactly like in an earlier group, but weighted by edges (the real work) only **17%** do. The heavy methods are the ones whose virtual / interface calls resolve against the classes instantiated INSIDE the group, so their result differs from group to group. A summary cache keyed by method alone would be wrong for them; a cache keyed by the resolution would reuse at most about 17% of the call-graph edge work (the call graph is 45% of the CPU), i.e. at most about 8% of the total, before the taint part. NOT implemented: the measured ceiling does not pay for the risk.
- **Streaming**: the device path already reads class text on demand (`Source.text(i)`, soft-referenced IR). The OOM of 80k-class apps was in the sandbox harness `SandboxScanReach`, which keeps every class and finding in memory; it was NOT changed or re-measured here (no 80k-class decode fits in the 1.5 GB of free disk of this sandbox).

## 0.103.0: where the parser's allocation really was (measured 2026-10-24, `tools/perf/ParseBench.java`, -Xmx1000m)
Corpus: Paperless (a React Native app), 8,389 classes, 52 MB of baksmali text, baksmali of a real F-Droid APK. Exact per-thread allocation (`ThreadMXBean`), three passes, last pass shown.
- **The earlier note "57% of the sampled allocation is regex code in the parser" did not hold for `SmaliParser`**: it has no regex on its hot path. The 4 regexes of `CallSkeleton` (the planner's pass over every class) allocate 30 MB for the whole corpus, `SmaliParser.parse` allocated **610 MB** (12 bytes per byte of text). JFR object-allocation samples: 40% `splitOperands` substrings (including a full copy of the method reference of every invoke whose operand list was then never used), 16% the per-line `line` substring (also for `.line` / `.local` / comments), 9% the directive `head`, 14% `op` / `rest`, 9.5% single-register `int[]`.
- **Done (output identical)**: no String for lines that change nothing, operands read in place (a String only for refs / labels), opcode strings shared through an allocation-free table (with the Kind cached), shared one-register arrays, no operand split for invokes. Result: parse allocation **610 -> 230 MB (-62%)**, parse wall time about 380 -> 200-250 ms (3 passes of 2 runs each; the sandbox box is not the phone), GC collections 4 -> 1 per pass; a parsed class keeps **21% less heap** (3,000 classes: 61.9 -> 49.1 MB).
- **Identical-output evidence**: a checksum over every field of every method and instruction (`ParseBench` IRHASH) is equal before / after on three real corpora (8,389 + 1,829 + 774 classes); `ir` 287 tests unchanged; a frozen copy of the old parser (`SmaliParserRef`, test sources) is compared with the new one on hand-written awkward inputs, 4,000 seeded mutations of a rich class and four threads at once (new test `SmaliParserEquivalenceTest`; 7 of 8 mutants killed, the eighth is an equivalent mutant); MeasureBig on a real app (gh4a, 1,034 non-library classes): the same 8 flows and the same taint-loss counters.
- **Not measured**: the effect on a big grouped scan (no 18k-class decode here: the gain per class is real, but parse was about 1% of the CPU and the allocation share of a whole scan is unknown), anything on the phone, GC share at -Xmx1000m of a full Deep scan before / after. The planner's text reading (109 MB per pass for this corpus, the index file -> String path in `agentIndexedText`) and `CallSkeleton` (30 MB) are the next allocation candidates; nothing was changed there.

## 0.104.2: attacking the GC share (the phone: GC 59% of the group time on 1 thread, 72% blocking on 2)
Corpus: Paperless (8,389 classes run as app code with `MeasureBig -Dall=true`), 1 thread; the Axis Pay APK was not in the sandbox. Every row: flow SET checksum compared.
- **Where the heap goes** (`jcmd GC.class_histogram`, live objects at peak, 512 MB, cap 3000): 291 MB live; 1.13 M `ArrayList` + `Object[]` 64 MB, `byte[]` / `String` 98 MB, `Insn` 22 MB, SSA `Value` / `Value[]` 30 MB, CFG blocks / edges 11 MB; 32,767 `Cfg` + `SsaForm` alive.
- **Headroom curve** (cap 3000, before the change): 160 MB 13.9 s, 176 MB 11.9 s, 192 MB 9.4 s, 208 MB 8.4 s, 224 MB 7.2 s, 256 MB 7.1 s: a cliff between 176 and 192 MB. Near the edge, 10-20% more free heap is worth about a third of the time: the phone is evidently on that edge.
- **Rejected, measured**: (1) smaller groups: 3000 -> 2000 is 30% faster at 160 MB but the same flow LOSES its entry path (reach=Y -> N); 1000 loses 2 of 9 flows: it changes results, not adopted. (2) Holding each group's SSA forms strongly and dropping them at the end of the group (instead of soft per-method references): at 160 MB the cap-3000 group no longer fit and the run found ZERO flows; no gain at 256 / 512 MB; slower at cap 1000 (no reuse across groups). Reverted: the soft references are what lets a big group survive. (3) No class cache: less GC but more parsing, no wall-time gain.
- **Adopted (identical results)**: after the engine builds a method's SSA form (`SsaForm.buildCached`), the dominator-tree children and the dominance frontiers (two lists of boxed ids per block, read only during construction) are released and the edge / phi lists trimmed. Peak live set 278-291 MB -> 252-264 MB (-9%); wall at cap 3000: 160 MB 13.9 -> 11.1 s (-20%), 176 MB 11.9 -> 9.6 s (-19%), 192 MB 9.4 -> 7.3 s (-22%), 208 MB 8.4 -> 7.3 s (-13%); GC -20 to -30%; flow set identical at every heap, and flows + taint-loss counters identical on gh4a and Logger. NOT measured: ART (not G1), the phone, Axis Pay.
- **Next candidates (same rule: identical results, measure the live set first)**: the remaining per-block / per-method lists (edge lists as arrays), `Insn.text` (every instruction keeps its source line), boxed `Integer` lists elsewhere.

## 0.104.3: instruction text and edge lists (the next two items of the 0.104.2 list)
Same corpus and method as 0.104.2 (Paperless 8,389 classes, `MeasureBig -Dall=true -Dmax=3000`, 1 thread unless said; "before" = the 0.104.2 classes, byte-identical to the committed build).
- **Census first** (`Insn` strings over the whole app, 544,423 instructions): the source line kept by every instruction about 46.6 MB, its reference (a second copy of the line's tail) about 29.3 MB. Only 42,141 distinct "line before the reference" (2.6 MB) and 81,689 distinct references (7.1 MB). The line ENDS with the reference in every case (1.06 M instructions on Paperless + gh4a, 0 exceptions). CFG edge lists: about 7 MB, much less than the strings.
- **Change**: `Insn` keeps (head, ref) and rebuilds `text()` = head + ref on demand (readers: two SsaBridge heuristics on chain methods, IrStress, tests); head, ref and labels go through `Canon`, a fixed 65,536-slot table that returns the earlier equal string (lock-free, lossy, bounded). The engine's cached SSA form replaces its edge / phi lists with read-only compact lists (shared empty list, a 16-byte singleton for one element, an array view otherwise). A raw `Edge[]` was NOT used: for one edge it is bigger (24 bytes) than the singleton (16), and most blocks have one predecessor.
- **Rejected, measured**: `String.intern()` instead of the table: same live-set gain, but parsing 2.6x slower and the whole run 3-9% slower at 1 GB (a global lock).
- **IR identical**: ParseBench IRHASH equal on Paperless and gh4a (`text()` hashed); `SmaliParserEquivalenceTest` passes.
- **Live heap at peak** (512 MB, sampled every 0.5 s): 246 MB -> 180-199 MB (-19% to -27%): `byte[]` 67.8 -> 29.0 MB, `String` 29.9 -> 14.4 MB, `ArrayList` 18.1 -> 9.2 MB (+3.6 MB singletons).
- **Heap curve** (wall / GC pause sum, mean of 2 runs, before -> after): 128 MB 43.5 s / 57.1 s -> 9.8 s / 8.8 s; 144 MB 17.7 / 19.9 -> 8.5 / 5.7; 160 MB 11.5 / 10.6 -> 8.3 / 5.3; 176 MB 10.9 / 9.3 -> 7.6 / 4.0; 192 MB 8.9 / 6.0 -> 7.9 / 3.4; 208 MB 8.0 / 4.8 -> 6.7 / 2.8. The cliff moved from about 150-176 MB to below 128 MB. 2 threads: 256 MB 9.0 -> 6.8 s, 384 MB 7.2 -> 6.9 s. With a 1 GB heap (no memory pressure): 5.86 -> 5.72 s (mean of 3): no CPU cost left in the end-to-end run. ParseBench parse alone (warm): 250 -> about 440 ms per 8,389 classes (hashing + the extra substring).
- **Flows**: Paperless flow set cc321fb3 in all 36 runs (every heap, both thread counts); flows + taint-loss counters identical on gh4a, Logger, GraphHopper, Listen1.
- **NOT measured**: ART (its GC and its String hashing), the phone, Axis Pay groups. The table keeps at most 65,536 strings reachable after a scan (not cleared; its size was NOT measured: an estimate from the census averages is 4-6 MB).

## 0.105.0 L3: the plan of a warm re-scan reads no class text (planner digests kept on disk)
Device evidence (report 9, Axis Pay 3.0.4, warm group cache): `plan 21s + groups 8s`. Sandbox, Axis Pay 3.0.1 (the APK in `./private/`, 10,586 non-library classes, 24 groups, 2 threads): the plan is 1.5 s on the JVM with texts read from plain files. So the phone's plan time is dominated by getting 10,586 class texts (gzip index or disassembly, plus the strings overlay) and running 4 regexes over each, and the warm "groups 8 s" is the same texts read AGAIN only to hash them for the group cache keys.
- **Change**: `CallSkeleton.Digest` = everything the planner takes from one text (source / weak-source / sink bits, super + interfaces, invoked and const-class types, the text's FNV hash). `DigestStore` keeps them in one file per (engine, dex CRCs, strings overlay); edited classes are never stored. `ScopePlanner.Source.digest` and `SsaGroups.Host.textHash` serve them.
- **Axis Pay 3.0.1** (`MeasureBig -Ddigest -Dcache`): no store 27.4 s, 10,586 texts read; cold (writes the 1.8 MB store) 24.4 s, plan 1.55 -> 1.83 s; warm: **0 texts read**, plan 0.73 s, whole run 1.6 s, 24 of 24 groups from cache. Flow set 74ad96f7 in all three and with the 0.104.3 classes. Paperless (-Dall, 8,389 classes): flows + PLAN line identical to 0.104.3.
- **Group overlap** (why editing 3 classes re-ran 8 of 19 groups): 58,784 slots for 6,977 classes; 3,719 classes are in 6 or more of the 24 groups (the supertypes / callees every seed's closure needs). Re-packing was not tried: 0.104.2 measured that changing group composition changes flows.
- **NOT measured**: the phone (expected: plan and the warm group time drop to the cost of reading one 1.8 MB file; to be confirmed by the owner's status line `plan digests: N of M reused`).

## 0.105.0 L2: R8 field conflation and the top taint-drop owners (Axis Pay 3.0.1, the sandbox APK)
- The 3.0.1 APK in `./private/` keeps the class names of the owner's 3.0.4 reports (m42, n62, g34, fo6, np2 ...), so the cards could be read in its smali. Engine on 3.0.1: 17 flows (set 74ad96f7).
- **Cards #15/#16 (`m42.c:Object`, written in `n62.a`)**: `m42` is an R8 class-merged class (`synthetic b:I`, a `packed-switch` in the constructor). `n62` is Firebase Installations (FID states NOT_GENERATED / ATTEMPT_MIGRATION / REGISTERED); the value written is the cached FID from SharedPreferences. The reader `m13.c()` / `j45` / `g34` is Crashlytics' user-metadata / file store, and it casts `m42.c` to **String**: the two uses are two different INSTANCES of the merged class, both holding Strings. A type check cannot separate them; an object-sensitive heap (allocation-site keys, roadmap B4) could. The cards stay LOW (already marked "Object field of an obfuscated class").
- **Built anyway, sound and measured**: a cast guard. When every tainted write to a field stored a value statically known to be a String, a read whose every use (through moves) is a check-cast to a type no String has carries no taint. Axis Pay: 0 cards change, real taint drops 5,661 -> 5,443 (taint no longer pushed down impossible casts). gh4a, Logger, GraphHopper, Listen1, Paperless: flows and counters identical. 2 tests (positive + 4 twins), 5 mutants killed.
- **Top drop owners** (`library or outside group`, real): fo6 234 = an R8-merged Kotlin lambda class (`Function0.invoke()`, 16-way switch); v86 137 = an executor wrapper; np2 131 = BouncyCastle `HMac` (init / update / doFinal([BI) / getMacSize, a block-size Hashtable in `<clinit>`); `Executor` 128; dw5 121 = coroutine machinery (Continuation parameters); yl0 = protobuf `CodedOutputStream` (static computeXxxSize). All are drops INTO classes outside the group; a MAC or a serializer of tainted data is not a path to a sink worth following. No model was added; no name rule.

## Device result of 0.104.3 + 0.105.0 (owner's phone, Axis Pay 3.0.4, 512 MB heap, 8 cores, 2 threads)
- Cold Deep scan: 0.104.2 (report 8) `plan 25s + groups 743s`, GC 620,158 ms in 2,141 collections, **538,329 ms blocking** -> 0.105.0 `plan 15s + groups 211s`, GC 124,048 ms in 1,026 collections, **31,133 ms blocking** (cpu 410 s summed over 2 threads in 211 s wall). Same 16 SSA flows.
- Warm re-scan (0.105.0): `plan 4s + groups 0s`, 25 of 25 groups and 10,586 of 10,586 plan digests reused, GC 42 ms. 0.104.2's warm run was `plan 21s + groups 8s`.

## 0.106.0 T3: SDK attribution of renamed classes (measured; the SSA exclusion was rejected)
- Rule: a root-package class named by kept classes of exactly ONE library family (plus 3 hops through classes named only by attributed ones) is that library's. Guards from measured failures: R8 class-id discriminator (`synthetic` :I/:S/:B), static class merger (>= 10 statics, no instance fields), naming the app's package or named by an app-package class, two families.
- Precision (5 R8-repackaged F-Droid apps whose own readable classes are known: unitto, webviewkiosk, Keep It, QtLab, Flowit): 36 of 2,482 unguarded attributions named the app's package; 0 with the guards. Coverage with guards: Axis Pay 3.0.1 2,165 of 9,500 root classes; unitto 379, webviewkiosk 793, Keep It 186.
- Rejected: strict attribution (any unattributed namer blocks): Axis 2,201 -> 642, aq8 / xq8 / u5 lost.
- Rejected: leaving attributed classes out of the SSA step. Axis: 28.8 -> 17.1 s, 24 -> 11 groups, 7 SDK-only flows gone (#15/#16, #50 among them), but on the repackaged corpus apps app flows changed (Keep It lost a HIGH/HIGH file-path flow and an SQL flow; webviewkiosk its WebView-from-preferences flows): renamed library code (DataStore, Room, Compose) sits on the app's own data paths. The SSA input is unchanged in 0.106.0.
- Adopted: cards re-scoped to library (rule cards by class; flow cards only when source and sink are in the same SDK) and posture hits counted as library. Axis 0.105 report replayed with T3 + T5: 60 -> 40 cards, 15 to library scope.

## 0.107.0: measurements behind each target
- Corpus: + 5 APKs from F-Droid (NewPipe 1015, K-9 39046, Thunderbird 33, KeePassDX 45600, AntennaPod 3120395; SHA-256 checked against the F-Droid index). The GitHub API is refused by the sandbox proxy (403); APKCombo / APKPure were not used. Local R8 8.13.25 in `tools/bin/` (git-ignored, SHA-1 checked against Google Maven); not yet used for a generated corpus.
- T1 (R8-merged fields): flows that pass an Object field of a renamed class: unitto 4 of 6, webviewkiosk 10 of 19, Keep It 11 of 13, Axis Pay 9 of 18 (K-9, NewPipe, KeePassDX, AntennaPod: 0 or 1 flow in all). Separating them needs the original class of the object at both the write and the read (interprocedural, over R8's class-id field): not built in 0.107.0; the next engine item.
- T2 (constant evaluation): argument origins at Cipher.getInstance / SecretKeySpec / IvParameterSpec / Class.forName / Uri.parse in 11 decoded apps: 0 from Base64.decode; 27 in-place arrays at IvParameterSpec / SecretKeySpec, 0 of them filled with constants (runtime buffers); Axis Pay's "helper" arguments are its native decryptor. A constant IV from a literal or a constant array was already detected (ScanRulesLegacy). Evaluator not built: nothing in the corpus to evaluate.
- T3 (native): root / hooking / TracerPid strings in .so data sections -> posture table. 0 hits in 39 APKs (27 with native libraries). JNI_OnLoad with no Java_ export is the normal binding style (22 libraries: Flutter, React Native, Conscrypt, ffmpeg, MapLibre): not used as a signal.
- T4: QR/barcode rule 10 -> 0 cards on K-9 / Thunderbird (R8 name reuse); other HIGH / MEDIUM cards of the 5 new apps judged (see HANDOFF).

## 0.108.0: verification numbers
- Gradle (AGP 9.3.1, Gradle 9.8.2, JDK 21): assembleDebug about 2.5 min cold; testDebugUnitTest 648 tests / 0 failures; lintDebug 0 errors, 198 warnings.
- Corrupted-APK fuzz (6 F-Droid APKs x 40 variants, 6 components, 30 s limit per call): 1,440 calls, 0 exceptions, 0 timeouts. Mangled-smali fuzz (600 classes from Axis Pay, K-9, AntennaPod, gh4a, 3 variants each): scanSmali + SSA + planner digest, 5,400 calls, 0 exceptions.
- Device (owner, Axis Pay, 0.107.0 warm re-scan): plan 3 s + groups 0 s, 25 / 25 groups and 9,725 / 9,725 digests reused. WE Wallet cold: plan 16 s + groups 192 s, GC 175 s (160 s blocking) on 512 MB: the next memory target.

## 1.0.0: measurements behind each pillar
- **P1, R8 merged classes (MergeTags / MergeFacts)**, flow sets before -> after (MeasureBig, 4 threads, 2 GB):
  | app | flows | change |
  |---|---|---|
  | Axis Pay 3.0.1 | 18 -> 15 | the 3 Crashlytics flows through m42.c removed: the writer (Firebase Installations, n62.a) holds a class-id 2 object from dr.a(), the reader (m13.b) a class-id 14 object (its m42.d is cast to g34). Read in the smali. |
  | Keep It | 13 -> 11 | 2 flows through sw1.j removed: the reader's object is op0.a (class id 0xf), the tainted writes are ids 20 / 26. Read in the smali. 3 other sinks kept, with another representative source. |
  | unitto, webviewkiosk, NewPipe | 6, 19, 1 | identical |
  | Flowit, K-9, KeePassDX, QtLab, AntennaPod | 0 | identical |
  Thunderbird: no manifest.xml in its decode folder, so the harness produced nothing for either engine (not an engine result). Real R8 8.13.25 fixture (tools/benchmark/r8_merge_fixture): negative 1 -> 0, positive 1 -> 1. Mutants: 10 of 10 killed (tests ir/IrMergeTagsTest). CPU: Keep It 12 -> 13 s, unitto 43 -> 49 s, Axis about the same. Axis needs 1,233 merged classes known from the digests; about 1,500 class texts are read again on demand for the facts (a phone cost NOT measured).
- **P2, allocation** (JFR allocation samples, Axis Pay, 512 MB, 2 threads): 21.5 -> 12.4 GB sampled allocation (-42%), GC collections 296 -> 186. The call-site facts (owner, name, descriptor, argument layout, sink candidates) were re-parsed on every pass of every analysis: now one fixed lossy table of 16,384 slots shared by all threads (TaintIr.Call, like Canon). Also: invokeKind without a substring, sinkOwners built once (was once per class digest), the taint-only edge dedupe per call site (was one "caller|insn|callee" string per edge). Flow checksum and the taint-loss counters identical. Mutants 8 of 8 killed (ir/IrCallInfoTest).
  Heap curve (Axis Pay, wall / pause-only GC from -Xlog:gc "Pause" lines / flows; old -> new):
  | heap | old | new |
  |---|---|---|
  | 512 MB | 35 s / 7.3 s / 15 | 33 s / 4.4 s / 15 (same set) |
  | 256 MB | 140 s / 104.7 s / 15 | 105 s / 73.6 s / 15 (same set) |
  | 160 MB | 349 s / 281 s / 15 (24 of 25 groups re-run for memory) | 356 s / 289 s / 15 (same set; 22 re-run) |
  | 128 MB | 145 s / 107 s / 12 | 291 s / 242 s / 14 |
  Below about 200 MB both engines are in the memory-retry regime (groups re-run in smaller parts): the time goes to the live set, not to the churn, and the 128 MB flow set depends on which groups failed (neither run is a valid result there). The churn cut helps from 256 MB up. NOT measured: ART, the phone, WE Wallet (no APK here: only its report).
- **P3**: 12 posture signals. Corpus (47 decoded apps): hits only where the APIs exist (Axis Pay biometric + user-auth keys, webviewkiosk, Paperless; Credential Manager / biometrics inside libraries for KeePassDX, K-9, Thunderbird). The "event-only biometric" row excludes a class that also binds a CryptoObject (2 wrappers in the corpus).
- **Self-scan (APKReLab 1.0.0 debug APK, SandboxScan)**: in dev.apkrelab 4 HIGH, 18 MEDIUM, 8 LOW. The 4 HIGH read in the source: Zip Slip in MainActivity.analyzeFile (lists entry names, writes none: FP of the single-method heuristic), Zip Slip in Rebuilder.repack (zip to zip: FP), SplitApks.extractApks (the name is reduced to a sanitised basename: FP), the install receiver redirection (mitigated in 0.108.0: signature permission, not exported, URI grants stripped, own package refused). 3 more HIGH were matches of rule classes on their own pattern strings and were fixed (JS bridge annotation, provider header, ALLOW_ALL field read; 0 classes of the 47-app corpus change). The MEDIUM / LOW cards were not read one by one.
- **Fuzz** (tools/sandbox/FuzzMerge.java: 300 merged / switch classes x 6 mangled variants, Axis Pay, Keep It, unitto; parse + digest + taint with and without app-wide facts): 108 batches, 0 exceptions, 0 over 60 s, 0 methods caught throwing inside the taint run.
- **Gradle** (AGP 9.3.1, Gradle 9.8.2, JDK 21): assembleDebug OK, testDebugUnitTest 670 tests / 0 failures, lintDebug 0 errors, 198 warnings.

## Device result of 1.0.0 (owner's reports 5 / 6, Samsung M52, Axis Pay 3.0.4)
- Cold Deep scan: groups 211 -> 137 s, blocking GC 31,133 -> 108 ms (0.106.0 -> 1.0.0). Warm re-scan: plan 3 s + groups 0 s (cache).
- Result: 94 findings, 33 shown (1 HIGH, 11 MEDIUM, 21 LOW); MASVS 24 / 24 controls assessed. Card #15 (g34 via m42.c) was still there: MainActivity did not pass MergeFacts to the groups (fixed in 1.1.0, see below).

## 1.1.0: measurements behind each change
- **Erased generic callbacks** (TaintIr, `apkrelab.keepErasedFanout` = old behaviour): flow sets on the corpus gate (16 decoded apps with a manifest + Axis 3.0.1), 5 flows removed, each read: Axis FileIOHelper (card #12, FP: withContext union), webviewkiosk nn.Q / nn.Y (FP: cache-file rename in a merged class), tv4.m / zi0.loadUrl (BY-DESIGN: the kiosk's own home URL through Compose lambda unions of 182 / 373 targets), Keep It pd3 (representative source swap). The first version also covered nullary `()Object` and removed 25 flows in 4 apps: rejected.
- **MergeFacts in the app** (wired in 1.1.0): Axis 3.0.1 with app-wide facts (MeasureBig = the grouped path): 14 flows, no g34 / m42.c flow. Card #18 (df8 via q73.x) stays: the raw extra reaches the file name only through q73.x's catch-all, which returns its input when hashing throws. A MessageDigest.digest sanitizer changed 0 flows on Axis: reverted.
- **substringAfterLast('/') sanitizer**: 0 flows change on the 16-app gate (Axis 14, webviewkiosk 15, Keep It 11, unitto 6, gh4a 8, logger 3, Paperless 2, NewPipe 1, others 0); the gate's timings were taken under parallel load and are not a measurement.
- **Library prefixes**: 0 of the 40 corpus app packages fall under a new prefix.
- **Decryptors** (16 decoded apps): one table decryptor (Axis vs.C.d(I), 63,575 calls); the next highest static (I|II|String)->String app method has 265 calls (NewPipe intToStringMaxRadix). Constant StringBuilder chains: 15-692 per app, 13 that look like a URL / action / algorithm, none hiding a string from the rules (every piece is a const-string): folding not built.
- **Native methods** (16 decoded apps with their APKs): 875 native declarations; static JNI exports matched (KeePassDX 7 / 7, K-9 7, Paperless 2), run-time registration through the class's own loadLibrary (K-9, unitto, Keep It, NewPipe, webviewkiosk 7 each = androidx.graphics.path; Listen1 98 through SoLoader; fluffy_board 35), React Native / Qt methods left as candidates (the class loads nothing itself). Untrusted input reaching an app native method: 1 call site in 16 apps (Axis vs.K.a with the app's own APK entry names): not made a finding.
- **Deep links** (Axis 3.0.1 + 39 corpus APKs, manifests decoded by Axml): 50 link filters, 18 unverified web filters (most for hosts the app cannot own: YouTube in NewPipe, github.com in gh4a), 2 missed by the 1.0 per-activity check (Axis axisapp.dre.agconnect.link, AntennaPod OnlineFeedViewActivity).
- **Encrypted SharedPreferences value**: 0 cards change on the corpus; APKReLab's own Signing card goes (tuning on the self-scan, stated).
- **Self-scan**, same 1.1.0 debug APK (sha256 d3ca57cc...), sandbox pipeline (SandboxScan; no device, no AI), 1.0.0 scanner -> 1.1.0 scanner, dev.apkrelab only: HIGH 4 -> 0, MEDIUM 18 -> 12, LOW 8 -> 7 (library cards: 21 MEDIUM / 18 LOW, unchanged). Attribution by switching each rule off: DynamicReceivers 1 (HIGH -> LOW), PathFlow 2, substringAfterLast 1, erased callbacks 7, encrypted value 1.
- **Robustness**: FuzzMerge 2,700 mangled classes x 3 apps (Axis, Keep It, unitto): 0 exceptions, 0 over 60 s, 0 throws inside taint. FuzzParsers110: 16,080 corrupted .so / manifest / smali inputs into ElfAnalyzer, DeepLinks, the deep-link rule, NativeBridge, DynamicReceivers, PathFlow, VersionProbes: 0 escaped, 0 over 5 s.
- **Gradle** (AGP 9.3.1, Gradle 9.8.2, JDK 21): testDebugUnitTest 706 / 0 failures, lintDebug 0 errors (198 warnings), assembleDebug OK (1.1.0 / 223).
- Not measured: anything on the phone for 1.1.0; Axis 3.0.4 (not in the sandbox); WE Wallet (no APK).

## A0 (NEXT_GEN_ROADMAP): device baseline from the owner's reports (Axis Pay 3.0.4, 512 MB heap, 8 cores; collected 2026-10-25 from ./private)
Every Axis report in ./private is versionName 3.0.4 (checked in each manifest). 10,586 -> 9,725 "classes outside libraries" from 0.107 on is the 0.106.0 library-prefix change, not another APK.
| scanner | run | flows | plan s | groups s | threads | groups reused | GC ms total | GC ms blocking | cpu parse s | cpu analysis s |
|---|---|---|---|---|---|---|---|---|---|---|
| 0.102 | report 2 | 16 | 16 | 1016 | 1 | - | - | - | 40 | 975 |
| 0.102 | report 3 | 16 | 29 | 544 | 1 | - | - | - | 46 | 497 |
| 0.104 | report 6 (= 7) | 16 | 18 | 752 | 1 | - | 446,810 | 310,964 | 17 | 724 |
| 0.104 | report 8 | 16 | 25 | 743 | 2 | - | 620,158 | 538,329 | 37 | 1,407 |
| 0.104.1 | report 9 (warm) | 16 | 21 | 8 | 2 | 25 / 25 | 910 | 0 | 0 | 0 |
| 0.105 | cold | 16 | 15 | 211 | 2 | 0 | 124,048 | 31,133 | 18 | 392 |
| 0.105 | warm | 16 | 4 | 0 | 2 | 25 / 25 | 42 | 0 | 0 | 0 |
| 0.107 | warm | 17 | 3 | 0 | 2 | 25 / 25 | 26 | 0 | 0 | 0 |
| 0.108 | cold | 17 | 30 | 301 | 2 | 0 | 170,147 | 24,953 | 22 | 573 |
| 1.0.0 | cold | 17 | 30 | 137 | 2 | 0 | 77,373 | 108 | 16 | 252 |
| 1.0.0 | warm | 17 | 3 | 0 | 2 | 25 / 25 | 31 | 0 | 0 | 0 |
WE Wallet 1.0.73 on 0.107: 8 flows, plan 16 s + groups 192 s, GC 175,460 ms (160,406 blocking).
What this baseline does NOT give: (1) two cold runs of the same version (0.102 is the only pair: 1016 vs 544 s, -46% between identical scans), so a cold change below ~50% cannot be told apart from run-to-run spread; (2) any 1.1.0 run; (3) battery / temperature; (4) peak heap (the status line has GC, not the live set).
Protocol for the owner (1.1.0, Axis Pay 3.0.4, the same phone, charger on, after the phone has cooled): open the app, Deep scan (cold: the first scan after installing 1.1.0 rebuilds the cache); export the report; Deep scan again without re-picking the APK (warm); clear the plan cache by re-installing 1.1.0 or picking the APK again and run a second cold scan; send the three reports. The status lines are the measurement; nothing else is needed.
