# Scan speed: what was measured (2026-10-19, sandbox: 1 core, JDK 21; device numbers from the owner's reports)

Pipeline measured: the device's own (`MeasureBig`: ScopePlanner.groups + SsaGroups.run, 2 threads). Tools here: `MeasurePlan.java` (the plan only: groups, class slots, how often a class repeats). `tools/sandbox/MeasureBig.java` runs the groups.

## Where the time goes (Axis Pay 3.0.1, 18,093 classes, Java Flight Recorder, 4,958 samples)
- `CallGraph.build` 44.7% of the CPU (dispatch ~18%, addEdge 9.2%: a string concatenation and hash per candidate edge); `TaintIr.analyze` 19.6%; parsing ~1%, SSA construction ~1%.
- The call graph is rebuilt from scratch for every group.

## Why: the groups overlap
Plan at the device cap (3000 classes): 31 groups, **70,814 class slots for 7,173 distinct classes: each class is analysed about 10 times** (64 classes sit in all 31 groups, 179 in 30).

## Exact changes (same result): old vs new call graph (edge dedupe without string keys, memoised dispatch)
Flows, plan, "top owners of real drops" and all counters identical on 5 real apps (Axis 18 flows, wallet 7, Fossify 13, OVAA 5, Jellyfin 7); `ir` tests 283/283.
Wall time: Axis 92 -> 80 s, wallet 44 -> 29, Fossify 29 -> 20, Jellyfin 48 -> 34; analysis CPU: Axis 163 -> 140 s, wallet 42 -> 39, Fossify 21 -> 15, Jellyfin 67 -> 50. Single runs on a 1-core VM: noisy.

## Group size cap (optimised call graph, Axis Pay): the same 18 flows in every row
| cap | groups | wall, 3 GB heap | wall, 1 GB heap | analysis CPU (3 GB) |
|---|---|---|---|---|
| 3000 (device) | 31 | 78 s | 142 s | 137 s |
| 5000 | 8 | 59 s | 140 s | 96 s |
| 8000 | 3 | 42 s | not finished | 55 s |
A bigger cap does less repeated work and found the same flows here (the older note of the project says grouping loses sinks at the device size on one app: bigger groups can only find more). The cost is memory: a 1 GB heap doubled the time (garbage collection) in the sandbox.

## What the phone did (the owner's reports)
- Axis Pay: groups phase 1,185 s (an earlier report) and 1,613 s (this one) for the SAME 16 flows: the phone's run-to-run variation is about 36%, so a single device timing cannot show a 10-20% gain.
- Wallet app: 4 groups, 478 s, **"2 group(s) re-run for memory"**: the phone's heap is already too small for 2 threads x 3000 classes on that app.
- On the phone, parsing is a larger share on the wallet app (142 s of 576 s CPU) than in the sandbox (7%): the device disassembles each class from the DEX on demand.

## Recommendation (not implemented here: another session is editing CallGraph.java and MainActivity.kt)
1. Print `Runtime.maxMemory()` and the core count in the "Deep scan status" line, so the next report says how much heap the phone really has.
2. Choose the group cap from the heap (for example 5000 only when maxMemory is at least 1.5 GB, else keep 3000): fewer groups, less repeated work, same flows.
3. After a "re-run for memory" on the first groups, finish the remaining groups on one thread instead of two.
4. Judge every change by the plan statistics and by the CPU seconds in the status line, not by one wall-clock run on the phone.

## CORRECTION (added by the session that measured the compact call graph, 0.101.0)
The table above says "the same 18 flows in every row". Only the COUNT is the same: compared as sets, the 5000-class and the 8000-class runs differ from the 3000-class run by ONE flow
(+1 / -1: a flow found only with the bigger groups, another found only with the device size). A change of the cap is a change of result, not a pure speed-up, and a bigger cap also
finds nothing faster on a small heap (5000 classes at 1 GB: 140 s, the same as 3000; 8000 did not finish). Memory is the limit on the phone ("2 group(s) re-run for memory").
The measurements that include the memory regime, the compact long set and the thread policy are in `docs/internal/PERF.md` (use that file; this one keeps the plan-redundancy numbers).
