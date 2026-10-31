# Contributing

Read `CLAUDE.md` first (it holds the working rules), then the top of `docs/internal/HANDOFF.md`.

## Working rules (each one caught a real mistake)
1. Measure before you build; say plainly what you did not measure. A claim is "verified" only when you ran it.
2. Held-out discipline: the first run of a benchmark app is frozen in `tools/benchmark/runs/`; an app you tuned on is a tuning app and its numbers are never reported as blind.
3. Precision means reading the smali of every HIGH / CRITICAL card.
4. No tuning to app or package names; prefer evidence in the code.
5. Every new rule has a positive test and a negative twin; every engine change has a mutation check (switch the feature off, a positive test must fail).
6. Say where something came from if you did not write it.
7. Do not delete or rewrite files to tidy up; `docs/internal/HANDOFF.md` is the log, add to it.

## Tests and checks
- Full build: `tools/sandbox/gradle_build.sh` (`testDebugUnitTest`, `lintDebug`, `assembleDebug`). Every change to `MainActivity.kt` / `Ui.kt` or any Android-only file must pass it before it is pushed.
- Engine tests without Gradle: `tools/termux/run_ir_tests.sh`.
- Release self-check: `tools/sandbox/self_check.sh` (benchmark recall, judged true positives against the last baseline, flow set). A lost judged true positive blocks the release.

## Repository hygiene
- **Never commit an APK, a decoded app, a `.dex`, a `.so` or a scan report of a third-party or company app.** They live in `./private/` (git-ignored). The GitHub web upload ignores `.gitignore`: do not upload binaries through it.
- Enable the hook once per clone: `git config core.hooksPath .githooks` (or `pre-commit install` with `.pre-commit-config.yaml`): it refuses app binaries and files over 1024 KB. CI runs the same check.
- No tokens or API keys in files, commit messages or issues.
