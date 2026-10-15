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
python main.py --run-all        # sprint across all 5 projects (~3 s offline, $0.00)
python main.py --dashboard      # executive table from persisted state
python main.py --project PRJ-01 # one project → output/PRJ-01/
python main.py --log-revenue PRJ-01 --amount 250   # record real revenue (unlocks Group B reinvestment)
python main.py --run-all --live # live-refreshing dashboard while the sprint runs
python -m pytest                #  tests: framework, budget controls + every project
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

## Financial model: $10.00 seed capital (CFO)

**Hard ceiling: $10.00 total API spend** (`SEED_CAPITAL_USD`). Logged revenue is unverified CLI input, so it can
never raise the ceiling.

| Bucket | Share | Default $ |
|---|---|---|
| PRJ-03 B2B Sniper | 35% | $3.50 |
| PRJ-01 Legacy Migrator | 25% | $2.50 |
| PRJ-02 Gap Cloner / Extension | 20% | $2.00 |
| PRJ-04, PRJ-05 (Group B) | 2.5% each | $0.25 each |
| Emergency reserve vault | 15% | $1.50 - locked; released automatically to the **first Group A project that logs revenue** |

* Group B is **local/deterministic only** (live calls blocked) until Group A logs revenue via `--log-revenue`.
* The 60% Group A profit -> Group B reinvestment only fills *unallocated headroom under the seed*; at the default
  matrix there is none (the vault is the scaling mechanism). To deliberately re-seed, raise `SEED_CAPITAL_USD` and `--reset`.
* An exhausted sub-budget never crashes a project: the breaker keeps it on free local execution (CFO status `BREAKER`).
* **Revenue is never simulated.**

### Zero-waste token engineering (`llm.py`)

1. **2-tier router.** Tier 1 (workhorse, ~90% of calls: PM drafts, review mining, sniper drafts): `claude-haiku-5-5` /
   `gpt-4o-mini` / `gemini-2.5-flash`. Tier 2 (gatekeeper): `claude-opus-5-5` / `gpt-4o` / `gemini-2.5-pro` - used only by the
   **CEO quality gate** and the **PRJ-04 security narrative**. Override with `LLM_MODEL_T1/T2`. Anthropic prices are from the
   current model table (Haiku 5.5 $0.10/$0.50, Opus 5.5 $4/$20 per 1M tokens); other providers' prices are estimates.
2. **Response cache** `state/llm_cache.json`: key = sha256(model, system, prompt); a hit costs $0.00, works even when the
   breaker is tripped, and is credited to *Cache Savings*. Offline fallbacks are never cached.
3. **Pre-flight estimate + circuit breaker.** Before a paid call the CFO atomically *reserves* a pessimistic worst-case cost
   (input at ~3 chars/token + the full `max_tokens` at output price). If it would exceed the project sub-budget or the global
   cap, the call is aborted and the deterministic engine's output is used. Reservations are held until spend is booked, so
   parallel PMs cannot overshoot.
4. **Hybrid pre-processing.** Scraping, AST parsing, regex and HTML stripping are local; prompts are distilled to <=500 tokens
   and system prompts compressed to <=300 before sending.

Every call is logged to the ledger in `agency_state.json` with model, tier, tokens and exact USD.

### Dashboard ROI telemetry

`python main.py --dashboard` shows: **Remaining Seed Capital** (`$10 - burn`), **Total Burn**, **Cache Savings**,
**Est. Revenue Pipeline**, **Circuit Breaker** (`ACTIVE ($X.XX remaining)` / `TRIPPED (Hard Cap Reached)`), reserve vault state,
blocked live calls, and per-project cache/blocked counters. The pipeline figure is an **assumption-based projection, not
revenue**: units x per-unit value in `config.py` (override with `ROI_VALUES_JSON`): $3 per audit-ready outreach (your plan:
500 audits -> one $1,500 client), $100 per legacy repo audited ($2,500 deal at an assumed 1-in-25 close), $390 per packaged
extension ($39 LTD x an assumed 10 early sales). PRJ-03 batch mode (`TARGETS_FILE=prospects.csv` with `url,ceo,company`, up to
`TARGETS_MAX`=500) is what makes "N audits ready" real: only validated (<110 words) outreach counts.

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
| `SEED_CAPITAL_USD` (alias `AGENCY_BUDGET_USD`), `COMPUTE_RATE_USD_PER_HOUR` (default 0) | seed cap / compute pricing |
| `LLM_MODEL_T1`, `LLM_MODEL_T2` | tier-1 / tier-2 model overrides |
| `AGENCY_CACHE_PATH`, `ROI_VALUES_JSON`, `TARGETS_FILE`, `TARGETS_MAX` | cache location, ROI assumptions, PRJ-03 batch |
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
