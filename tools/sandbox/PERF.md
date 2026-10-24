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
