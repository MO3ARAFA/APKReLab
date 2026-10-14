# Autonomous AI Agency & Master Orchestrator

A modular Python agency run by a central **Master Orchestrator**. Five isolated project pipelines pass through a
**Triple-Gate loop** (PM pre-check → CFO financial audit → CEO ≥95% quality gate), with real state persistence, a
Cross-Subsidization financial model and a live Rich executive dashboard.

Everything works **offline with no API key**: each project is a deterministic engine, and an LLM (Anthropic / OpenAI /
Gemini / Ollama) only *enriches* narrative text (summaries, positioning, outreach drafts) when configured.

```
main.py ──► Orchestrator ──► per project (5 in parallel threads)
              │                 PM-0X builds ─► Gate 1: PM pre-check ─► Gate 2: CFO audit ─► Gate 3: CEO QC (≥95%)
              │                       ▲                                                              │
              │                       └──────────── actionable feedback, up to MAX_REVISION_CYCLES ──┘
              ├─ AI CFO  (agents/cfo_agent.py)  tokens · API calls · compute time · quotas · 85/15 split · 60% reinvest
              ├─ AI CEO  (agents/ceo_agent.py)  dispatch · independent artifact verification · Rich dashboard
              └─ state/agency_state.json        atomic, thread-safe persistence
```

## Quick start

```bash
pip install -r requirements.txt
cp .env.example .env            # optional: add API_KEY + LLM_PROVIDER for LLM enrichment
python main.py --run-all        # sprint across all 5 projects (~3 s offline)
python main.py --dashboard      # executive table from persisted state
python main.py --project PRJ-01 # one project → output/PRJ-01/
python main.py --log-revenue PRJ-01 --amount 250   # record real revenue (unlocks Group B reinvestment)
python main.py --run-all --live # live-refreshing dashboard while the sprint runs
python -m pytest                # 80 tests: framework + every project
```

Flags: `--sequential` (no parallelism), `--reset` (wipe persisted state). Exit code is non-zero if any requested
project is not CEO-approved.

## The Triple-Gate loop

| Gate | Owner | What it checks |
|---|---|---|
| 1. Pre-check | PM-0X | artifacts exist; every self-check the pipeline ran passed (tests, validators, exploit replays) |
| 2. Financial audit | CFO | spend ≤ quota; Group B limited to dry-run until Group A has revenue; `HEALTHY / WATCH / DRY-RUN / OVER BUDGET` |
| 3. Quality gate | CEO | **independently** re-verifies artifacts (exist, non-empty, JSON parses, Python compiles) and scores `40·artifacts + 50·verification checks + 10·report`; **<95% is rejected** with feedback returned to the PM |

A failing gate re-runs the PM with the feedback (default 3 cycles). A crashing pipeline becomes a blocker on the
dashboard instead of crashing the orchestrator.

## Financial model (CFO)

* `AGENCY_BUDGET_USD` is split **85% → Group A** (PRJ-01..03, equal shares) and **15% → Group B** (PRJ-04..05).
* Group B runs **dry-run** (reduced scope, labelled in reports) until Group A logs revenue.
* After revenue, **60% of Group A profit** (revenue − spend) is added to Group B quotas — idempotently (only the delta).
* Cost = LLM tokens × provider price table (`llm.py`, estimates) + compute seconds × `COMPUTE_RATE_USD_PER_HOUR`.
  Offline runs cost ≈ $0 API but still accrue compute cost.
* **Revenue is never simulated.** It only changes when you run `--log-revenue`.

## Projects (artifacts land in `output/PRJ-0X/`)

| ID | Group | What it really does |
|---|---|---|
| **PRJ-01** Legacy Migrator | A | AST analyzer for Python (+ regex scanners for PHP/JS): deprecated libs, secrets, SQLi, shell exec, unsafe YAML, weak hashes, monolithic functions (length/cyclomatic/nesting). Applies safe AST auto-fixes, generates a **FastAPI microservice**, **golden-master pytest suite** (characterization tests captured by executing pure functions in an isolated subprocess), Dockerfile, and a **B2B audit report**. Functions with code-exec risk are quarantined, never exposed as endpoints. |
| **PRJ-02** Gap Cloner | A | `review_pain_extractor.py` mines 1–2★ reviews → pricing/performance/missing-feature/support pain, price points, clustered & ranked feature gaps, gap brief. `crm_clipper_extension/` is a complete **Manifest V3** extension (IndexedDB offline store, outbox with exponential backoff, HMAC-signed webhook sync, context menu, CSV export with formula-injection guard, optional host permission requested at runtime). Validated statically, syntax-checked and logic-tested in Node against an IndexedDB fake; packaged as a Web-Store-ready zip. |
| **PRJ-03** Deal Closer | A | `b2b_sniper.py`: real HTTP fetch (TTFB, size, compression, redirects with **SSRF guard**), HTML diagnostics (meta/SEO, blocking scripts, CTAs, form friction, social proof, contact path), ranked findings and a **<110-word CEO outreach** — LLM draft is validated (word limit, CEO name, cites a real finding, no placeholders, CTA question) with one retry, then a deterministic template. Default target is a pair of local fixture sites; set `TARGET_URL`/`TARGET_CEO` for a real prospect. |
| **PRJ-04** Zero-Day Hunter | B | `auto_patcher.py`: intra-procedural taint **data-flow graph** (sources → variables → sinks; JSON + Graphviz), detects SQLi, command injection, **IDOR**, missing authn/authz, mass assignment, path traversal, open redirect and client-controlled business logic. Emits a **`git apply`-able diff** for what is safely fixable (parameterized SQL incl. `LIKE`/`%`/`.format`/SQLAlchemy `text()`, argv-based subprocess, `@login_required`, admin and ownership guards); the rest is reported with a manual fix. The patch is verified: applies with git, is idempotent, and a SQL-injection payload is replayed against real SQLite before/after. |
| **PRJ-05** Synthetic Foundry | B | `synthetic_engine.py`: PII detection (by name and by value incl. Luhn), PII-free statistical profile (trimmed quantiles, rare-category suppression, optional Laplace noise, Gaussian-copula correlations), seeded sampling, and a **mathematical validation score** (KS, TVD, correlation error, exact-row-match, distance-to-closest-record, PII-leak scan). A privacy failure caps the score at 50. |

## Configuration (`.env`)

| Var | Meaning |
|---|---|
| `LLM_PROVIDER` | `anthropic` \| `openai` \| `gemini` \| `ollama` \| `offline` |
| `API_KEY` | key for the hosted provider (no key → offline) |
| `LLM_MODEL` | optional override (defaults in `llm.py`) |
| `OLLAMA_HOST` / `OLLAMA_MODEL` / `LLM_FALLBACK_OLLAMA` | local fallback if the hosted call fails |
| `AGENCY_BUDGET_USD`, `COMPUTE_RATE_USD_PER_HOUR` | financial model |
| `QC_THRESHOLD`, `MAX_REVISION_CYCLES` | CEO gate |
| `AGENCY_STATE_PATH`, `AGENCY_OUTPUT_DIR` | relocate state/output (used by the CLI tests) |

Secrets are read only from `.env`/environment; `.env` is git-ignored.

## Installing the Chrome extension

`chrome://extensions` → enable Developer mode → *Load unpacked* → select `output/PRJ-02/crm_clipper_extension`
(or upload `crm_clipper_extension.zip` to the Chrome Web Store). Set an `https` webhook URL under *Webhook settings*;
Chrome will prompt for that single host permission.

## Layout

```
main.py  orchestrator.py  config.py  llm.py  state.py
agents/        ceo_agent.py  cfo_agent.py  pm_agents.py
projects/      common.py  prj_01_legacy_migrator/  prj_02_gap_cloner/  prj_03_deal_closer/
               prj_04_zeroday_hunter/  prj_05_synthetic_foundry/   (each: pipeline.py, engine, sample data, tests/)
tests/         framework + CLI end-to-end tests
state/agency_state.json   (created at runtime)       output/   (created at runtime)
```

## Known limits (read before relying on it)

* The projects run on **bundled sample inputs** by default (a sample legacy repo, review set, fixture sites, a vulnerable
  Flask app, a sample customer CSV). Each engine accepts your own input (see each `pipeline.py`/CLI), but the
  CEO's 95% score measures *this tool's own verification checks*, not business value.
* PRJ-01 tests pin the behavior of the **modernized** code and execute legacy module code in a subprocess — only point
  it at repositories you trust. Python 2 files are detected but not auto-ported.
* PRJ-04 analysis is intra-procedural and Flask-style; it is a triage aid, not a replacement for a SAST/pentest.
  Patches are computed on an AST-normalized copy (comments/formatting are not preserved) — review before merging.
* PRJ-05 noise on released statistics is **not** an end-to-end differential-privacy proof.
* Token prices in `llm.py` are estimates; check your provider's current pricing.
* Nothing here generates revenue by itself; the CFO model only allocates quota and tracks revenue you log.
