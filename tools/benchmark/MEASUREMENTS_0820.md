# Measurements before 0.83.0 (2026-10-14, tool version 0.82.0, no code change; sandbox)

Two questions that decide what 0.83.0 should be. Tool: `tools/sandbox/MeasureCompare.java` (MeasureBig with `-Dwhole=true` = the whole app as ONE group, or `-Dgmax=N` = ScopePlanner groups of up to N classes; the device uses 3000). Flow identity = (title, sink method).

## 1. How many SSA flows does grouping lose?
| app (non-library classes) | whole app | groups of 3000 (device size) | groups of 1000 |
|---|---|---|---|
| AnkiDroid (10,304) | 34 sinks | **3 lost / 3 extra** (31 groups) | 12 lost / 2 extra (186 groups) |
| Termux (~9k smali, 1 group) | 9 | 0 / 0 | 0 / 0 |
| Markor (1 group at both sizes) | 8 | 0 lost / 1 extra | 0 / 1 |
| Jellyfin (7,203) | 7 | 0 / 0 (5 groups) | **7 lost** (64 groups) |
What was lost at the device size (AnkiDroid): 3 sinks, all with a `SharedPreferences.getString()` source (a server URL, a file path, a class name): weak, low-value leads. No Intent-sourced flow (the kind that gave every true positive of sets 1-6) was lost in any of the four apps at 3000. Grouping also ADDS flows the whole-app run does not have (3 in AnkiDroid, 1 in Markor: HIGH/LOW, SharedPreferences source -> Runtime.exec in `GsFileUtils.gatherMimeType`; not judged), so the two modes disagree both ways, not only by loss.
Strong dependence on the group size (AnkiDroid 9% -> 35%; Jellyfin 0 -> 100%), but the device runs 3000, and JustMarkets (59,667 classes) was planned as 5 groups over 325 marked classes. JustMarkets itself cannot be run whole in 4 GB, so ITS loss is NOT measured; AnkiDroid is the closest proxy.
Limits: 4 apps, the whole-app run is also an approximation (RTA), 3 of 4 apps fit in 1-5 groups at the device size.
**Reading: boundary summaries would recover ~9% of AnkiDroid's flows at the device group size, all low-value. Not worth building now.**

## 2. How much does the old in-class taint engine add on top of the SSA?
Across the 23 apps' latest reports: 123 taint cards, **122 from the SSA engine and 1 only from the old in-class engine** (Catima CardsContentProvider SQL, judged BY-DESIGN). On the JustMarkets code-rule run (no SSA in that run) the old engine gives 1 LOW card. Because dedupe lets the SSA card absorb the in-class twin, "1" is the number of cards with NO SSA twin.
**Reading: the old engine is almost redundant. Retiring it (or reducing it to the cases SSA cannot see) is a clean-up with no measured recall effect; it removes the duplicate-card family and the absorb rules.** Not verified on a big app where the SSA is grouped.

## Consequence for 0.83.0
Neither "boundary summaries" nor "engine merge" is a recall win on this evidence. Candidates, in the order the data supports: (1) set 7 of unseen real apps on 0.82.0 (the only number that has moved the roadmap so far), (2) retire the in-class taint engine behind a flag and re-run the 23 apps (clean-up, measurable), (3) judge the 'extra in grouped' flows (is grouping creating false positives?).
