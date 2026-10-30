# Recall by injection (0.86.1)

What it measures: for a list of known weakness patterns (cases.py: 32 "must" = a rule exists for exactly this, 10 "probe" = the same weakness in a different shape),
does the real pipeline report a card of an expected rule for the injected class, and at the expected severity or higher.
How: `run_recall.py <snapshot> <host...>` hard-links a decoded real app, adds the cases as smali classes in the app's own package (readable names, APP scope)
and, for the components, as manifest entries (`-Dmanifest` of `tools/sandbox/SandboxScanReach.kt`), scans, and parses the report.
Needs: a snapshot dir with `ss2/ kout/ irk/` (see tools/sandbox/SETUP_FROM_SCRATCH.md and batch.sh), decoded apps in /home/claude/apps/dec_<host>.

What it does NOT measure (read before quoting a number):
- The cases and the rules were written by the same people: 32/32 means "no regression and calibrated on textbook shapes", not "the scanner finds 100% of weaknesses".
- The 10 probes are the honest part: they change the shape (key in Base64, key in a static array, token in an interceptor class, runtime-built algorithm
  string, forwarding between activities, deep-link query parameter, exec with an array ...). Results of the last run are in results-<host>.md.
- The injected code is synthetic smali, not R8 output (except case 11); apps that encrypt their strings or flatten control flow are not represented.
- Expectations were lowered twice after seeing a first result (cases 18 and 30, reasons in cases.py): that is a judgement, revisit it.
