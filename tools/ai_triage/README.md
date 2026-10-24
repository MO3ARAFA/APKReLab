# AI triage replay (measured 2026-10-28)

`eval.py` replays the app's AI triage (the prompt of `MainActivity.triageWithAi`, copied verbatim) on findings that have a HAND verdict from `tools/benchmark/heldout_real/*.md`
(rows in `hand_verdict_rows.json`; the owner's closed set 9 is excluded) and compares. `SandboxScanReach -Dtriage=<file>` dumps what the triage prompt contains (code excerpt, source method, data path).
Only open-source apps were sent (their code is public). The key is read from the environment, never written to a file.

Result with Sonnet 5.5, two runs per card, **n = 19 cards (7 real, 9 false positives, 3 by design)**:
- hand verdict "false positive" (9 cards x 2 runs): AI said FALSE_POSITIVE 14, NEEDS_REVIEW 4, **TRUE_POSITIVE 0**: it never confirmed a false alarm in this sample.
- hand verdict "real" (7 cards x 2 runs): AI said TRUE_POSITIVE 9, NEEDS_REVIEW 1, **FALSE_POSITIVE 4** (two cards, both times): it buried 2 of 7 real findings (a Markor "one click" file-path write and a Jellyfin JavaScript bridge: both low-severity borderline cards in my own judgement, TP-1CLICK / TP-low).
- 2 of 19 cards got different verdicts in the two runs.
Why this is weak evidence: 19 cards; the verdicts are mine (borderline ones included); the cards are the ones that SURVIVE the current scanner (72 hand verdicts, only 19 still exist as MEDIUM+ code findings of the current scanner: the false positives fixed since
cannot be replayed); the reach text exists only for taint flows in the sandbox (the app traces every finding), so the model saw less than in the app; one model, one prompt, default temperature.
Reading: as a SIGNAL to rank / dismiss, useful (no false confirmation here); as a reason to hide a finding, not safe on this evidence (2 of 7 real ones buried): the app keeps the verdict as a suppression under review, not a deletion, and `guardFalsePositive` exists: keep it that way.
