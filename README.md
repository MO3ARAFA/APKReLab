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
python main.py --web            # local web command center at http://127.0.0.1:8080
python main.py --dashboard      # executive table from persisted state
python main.py --project PRJ-01 # one project → output/PRJ-01/
python main.py --log-revenue PRJ-01 --amount 250   # record real revenue (unlocks Group B reinvestment)
python main.py --run-all --watch # live-refreshing dashboard while the sprint runs
python main.py --project PRJ-03 --live --max-spend 0.05   # PAID LLM calls (key from .env), capped for this run
python tools/build_ready_to_sell.py   # assemble output/READY_TO_SELL_NOW.md from real artifacts + CFO state
python main.py --daemon         # AI COO: unattended cycles + Telegram briefings/approvals (docs/AUTOPILOT.md)
python main.py --growth         # PM-06 cost report, runway and routing policy
python main.py --free-tiers     # which free-tier providers are configured (--check to ping them)
python -m pytest                # 273 tests: framework, budget, live-mode, web UI, auto-pilot, PM-06 + every project
```

Flags: `--live` (**enables paid LLM calls**; without it every run is offline and free even if a key is in `.env`),
`--max-spend USD` (hard cap for *this run*, on top of the seed cap), `--watch` (live-refreshing dashboard),
`--sequential` (no parallelism), `--reset` (wipe persisted state). After a `--live` run the CLI prints how many calls were
live / cached / blocked / failed, so a silent fallback to offline output can't be mistaken for a live run. Exit code is non-zero if any requested
project is not CEO-approved.

## AI COO: unattended operation with Telegram approvals (Phase 7)

`python main.py --daemon` runs an auto-pilot cycle every 12 hours and reports to your Telegram. **$0 work runs by itself**
(templates or the free lane, with a spending cap of zero). **Anything that could spend money waits for your Approve tap**
(hard per-cycle cap plus a daily cap; a "No" runs the $0 version instead). **Contacting prospects is never automatic**: on your
approval the validated messages are delivered to your own chat to review and send yourself. The briefing's numbers are computed
from state; the COO's analysis paragraph is model-written (or rule-based), labelled, and cannot trigger actions. It pauses itself
after repeated failures, only one daemon runs at a time, and web/CLI runs wait while a cycle writes the state file.
One-time setup: `@BotFather` token in `.env`, then `python main.py --telegram-setup` (code pairing so only you can command it).
Full guide, Termux commands, privacy notes and limits: [`docs/AUTOPILOT.md`](docs/AUTOPILOT.md).

## Sales loop: from audit to payment (Phase 8)

After you release a batch, every message arrives in Telegram with a public contact path found on the company's own site (role addresses
only), a suggested subject, your legal footer, and, for non-English sites, an unverified AI translation. `/sent all` starts follow-up
reminders (day 3 and day 7, never more than two). `/replied Acme` returns the **reply kit**: top findings, a price, and a ready draft with
PayPal links. The COO prices each job from the audit (report-only fee, or report plus the estimated hours for the top 5 fixes; above a cap it
is "custom"); `/quote Acme 120` overrides. `/won Acme 149` logs verified revenue after you confirm, `/report Acme` produces the written
deliverable, `/optout` is permanent, `/addlead` queues your own prospects. The agency never sends anything and never touches your money.
Set `PAYPAL_ME` and `SENDER_ADDRESS` in `.env`. Details, pricing rules, compliance notes and limits: [`docs/SALES.md`](docs/SALES.md).

## PM-06: AI Growth & Cost-Hacking Agent (free lane)

PM-06 watches model spend and routes each call *before* it is made:

| Mode | Trigger | Effect |
|---|---|---|
| normal | budget healthy | paid provider (the $10 breaker still guards it) |
| conserve | <= `CONSERVE_BELOW_PCT` (25%) left | the 2 most token-hungry projects use the free lane; tier-2 flagship paused |
| free | <= `FREE_LANE_THRESHOLD_USD` ($0.50) left, cap reached, or the paid provider refused (no credit / bad key) | every call uses the free lane; paid is retried after `PAID_RETRY_HOURS` |

The free lane is local Ollama, then free-tier providers whose keys **you** registered by hand (Groq, OpenRouter `:free`, Google AI Studio,
Mistral), each with self-imposed request limits below the published ones and a cool-down after errors; with nothing available the deterministic
templates run ($0, lower quality). Free usage and the paid cost it avoided are shown on the dashboard card, the **PM-06 Free Tiers** tab and
`--growth`. With no paid key but a free key in `.env`, live mode runs on the free lane alone.

**What it will not do:** create accounts, solve CAPTCHAs/identity checks or rotate identities. That breaks provider terms and gets accounts
banned. [`docs/FREE_TIERS.md`](docs/FREE_TIERS.md) is the manual, source-linked guide (limits, data-use caveats, startup-credit programs).
There is no guarantee of "$0 forever": free tiers change and some use your prompts for training, so do not send client data through them.

## AI CEO auto-pilot (zero manual entry)

```bash
python main.py --ceo-autopilot                 # free: real site audits + template drafts, no API spend
python main.py --ceo-autopilot --live          # paid drafts, capped at $0.10 for the whole chain unless --max-spend says otherwise
python main.py --ceo-autopilot --live --discover-targets   # also let the tier-1 model suggest extra prospects
```

Or tap **AI CEO: Run Full Auto-Pilot** in the web dashboard (live, capped at $0.10) / **AI CEO: Auto-Pilot (Offline)**. One sequence:

1. **CEO target dispatch** - if `targets.csv` is missing, empty, or fully audited, the CEO loads the next un-audited prospects (5 by default) from the
   curated pool `projects/prj_03_deal_closer/prospect_pool.json` and assigns them to PM-03. Rows you added yourself are respected.
2. **PM-03 batch audit** - real HTTP diagnostics of each site and one outreach message per site (live LLM, or deterministic templates offline), signed
   with `SENDER_NAME` (default `Mohamed`). Every prospect is then marked audited so the next run moves on.
3. **PM-01 / PM-02** - legacy audit package and extension kit with launch copy, through the CFO and CEO gates.
4. **Sell sheet** - `output/READY_TO_SELL_NOW.md` is rebuilt (the Master Sell Sheet tab refreshes itself).

A failed step is recorded and the later steps still run; the whole chain shares one CFO run cap. The **Rotate / Load Next 5 Prospects** button in the
Target Manager tab loads a fresh batch with one tap.

**The prospect pool is a vetted starting list, not a guarantee.** 18 real SaaS companies and agencies whose sites were reachable and auditable on
2026-10-15. A leader's name is used as the greeting only where a source is recorded (7 of 18); everything else greets with "there". The pool loader
refuses an unsourced name. Findings are re-measured on every run, and you should still read each message and confirm the recipient before sending.
Prospects suggested by the LLM (`--discover-targets`, or the checkbox in the UI) are **unverified leads**: validated (https, public hosts only, no
duplicates), fetched before use, and always greeted with "there".

## Local web command center

```bash
python main.py --web            # http://127.0.0.1:8080   (add --port 9090 to change)
```

Standard library only (no FastAPI, pydantic or Rust build), so it installs on a phone (Termux), a Raspberry Pi or a locked-down laptop:

```bash
pip install rich python-dotenv pytest   # all pure Python (pytest is needed: projects self-verify with it)
python main.py --web               # then open http://127.0.0.1:8080 in a browser on the same device
```

On Termux: `pkg install python git`, clone the repo, run the two lines above, and open the URL in your phone's browser
(keep Termux running while you use it). A dark, single-page executive UI (no Node build, no CDN - its own CSS/JS) over the
same state files the CLI uses:

* **CFO telemetry bar** - remaining seed capital with progress bar, total burn (live vs cached calls), cache savings, reserve vault
  (locked/unlocked) with the assumption-based revenue pipeline, and a green ACTIVE / red TRIPPED circuit-breaker badge. Refreshes every 3 s.
* **AI CEO project matrix** - group, PM, spent/cap, CEO QC %, status (`APPROVED` / `DRY-RUN` / `BREAKER`), sellable units, and per-row
  **Run Offline (Free)** / **Run Live (Paid)** buttons (live asks for confirmation and uses the per-click max-spend box, default $0.05).
* **Agency controls** - Run All offline, Run All live (capped at $0.10), Rebuild Master Sell Sheet, and a Log Real Revenue dialog.
* **Commercial vault tabs** - the rendered Master Sell Sheet with a *Copy message* button on every outreach email/pitch and *Copy section*
  on every heading; the `targets.csv` manager (add/remove, then *Audit Targets Live*, which rebuilds the sheet); the PRJ-02 launch copy with a
  zip download; and the PRJ-01 audit report beside the CFO's exact per-call spend ledger.

Safety design (the server can spend money, so it is locked down even though it is local):

* binds to `127.0.0.1` only - `serve()` has no host parameter;
* `Host` must be `127.0.0.1`/`localhost:<port>` (anti DNS-rebinding), any `Origin` must match, and every state-changing request needs a per-process
  CSRF token that only the served page can read; no CORS is enabled;
* live runs are enforced **server-side**: key configured, `confirm: true`, and `0 < max_spend <= $1.00` per click, on top of the CFO sub-budgets and
  the $10 cap. Offline is the default everywhere. One mutating operation runs at a time;
* **no secrets in responses**: `.env` is never read by any endpoint, keys and key-shaped strings are scrubbed from every payload, artifacts are served
  from a fixed allowlist (no user-supplied paths), and the page runs under a strict CSP with no inline scripts;
* markdown from scraped sites / LLM output is rendered by an escape-first renderer, so it cannot inject HTML or `javascript:` links.

JSON API (for scripting): `GET /api/state`, `/api/ledger`, `/api/sell-sheet`, `/api/launch-copy`, `/api/audit-report`, `/api/targets`,
`/api/download/extension`, `/api/jobs/{id}`; `POST /api/run/{PRJ-0X}`, `/api/run-all`, `/api/revenue`, `/api/rebuild-sell-sheet`,
`/api/targets`, `/api/targets/audit` (all POSTs need the `X-CSRF-Token` header from the page's `<meta name="csrf-token">`).

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
| `AGENCY_CACHE_PATH`, `ROI_VALUES_JSON`, `TARGETS_FILE`, `TARGETS_MAX`, `REVIEWS_FILE` | cache location, ROI assumptions, PRJ-03 prospect batch, PRJ-02 real review export |
| `GROQ_API_KEY`, `OPENROUTER_API_KEY`, `GEMINI_FREE_API_KEY`, `MISTRAL_API_KEY` | free-tier keys you registered yourself (PM-06 free lane) |
| `FREE_PROVIDERS`, `FREE_MODEL_<NAME>`, `FREE_LIMITS_JSON` | pick/order free providers, override their models, override self-imposed rpm/rpd |
| `FREE_LANE_ENABLED`, `FREE_LANE_THRESHOLD_USD`, `CONSERVE_BELOW_PCT`, `PAID_RETRY_HOURS` | PM-06 thresholds |
| `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | AI COO Telegram bridge (chat id comes from `--telegram-setup`) |
| `DAEMON_CYCLE_HOURS`, `DAEMON_QUIET_HOURS`, `DAEMON_DAILY_CAP_USD`, `DAEMON_LIVE_CAP_USD`, `DAEMON_MAX_FAILURES`, `DAEMON_PROPOSAL_TTL_HOURS`, `DAEMON_REJECT_COOLDOWN_HOURS` | daemon schedule and spending limits |
| `PAYPAL_ME`, `SENDER_ADDRESS`, `PRICE_REPORT_USD`, `PRICE_HOURLY_USD`, `PRICE_CAP_USD`, `DELIVERY_DAYS`, `FOLLOWUP_FIRST_DAYS`, `FOLLOWUP_SECOND_DAYS` | sales loop: payment handle, legal footer, pricing, follow-up timing |
| `QC_THRESHOLD`, `MAX_REVISION_CYCLES` | CEO gate |
| `AGENCY_STATE_PATH`, `AGENCY_OUTPUT_DIR` | relocate state/output (used by the CLI tests) |

Secrets are read only from `.env` (which overrides shell variables) and `.env` is git-ignored, so it can never be committed.
Key variables: `API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`/`GOOGLE_API_KEY`; the provider is detected from the
key prefix (`sk-ant-` -> Anthropic, `AIza` -> Gemini, other `sk-` -> OpenAI) and wins over a stale `LLM_PROVIDER`. The test suite ignores
`.env`, API keys and the real state/cache files entirely.

## Installing the Chrome extension

`chrome://extensions` → enable Developer mode → *Load unpacked* → select `output/PRJ-02/crm_clipper_extension`
(or upload `crm_clipper_extension.zip` to the Chrome Web Store). Set an `https` webhook URL under *Webhook settings*;
Chrome will prompt for that single host permission.

## Layout

```
main.py  orchestrator.py  config.py  llm.py  state.py  web_dashboard.py  web_markdown.py  web/ (index.html, static/)  tools/ (sell-sheet builder)
agents/        ceo_agent.py  cfo_agent.py  growth_agent.py (PM-06)  coo_agent.py  policy.py  pm_agents.py
ops/           daemon.py  telegram.py  lock.py  sales.py
docs/          FREE_TIERS.md  AUTOPILOT.md  SALES.md
projects/      common.py  prj_01_legacy_migrator/  prj_02_gap_cloner/  prj_03_deal_closer/
               prj_04_zeroday_hunter/  prj_05_synthetic_foundry/   (each: pipeline.py, engine, sample data, tests/)
tests/         framework + CLI end-to-end tests
state/agency_state.json   (created at runtime)       output/   (created at runtime)
```

## Known limits (read before relying on it)

* The projects run on **bundled sample inputs** by default (a sample legacy repo, review set, fixture sites, a vulnerable
  Flask app, a sample customer CSV). Each engine accepts your own input (see each `pipeline.py`/CLI), but the
  CEO's 95% score measures *this tool's own verification checks*, not business value.
* **Real-site outreach is deliberately conservative.** Messages to real prospects cite only objective findings that can be
  re-checked in the page HTML (meta description, viewport, render-blocking scripts, alt text, H1 count, form fields, structured data);
  judgement calls (social proof, CTA wording) and single-sample timings are excluded. Error/bot-challenge pages are never audited.
  Verify every finding yourself and confirm the recipient's name before sending.
* PRJ-02 launch copy never uses review statistics or quotes (the bundled review set is a synthetic sample); every feature claim is
  checked against the extension source in tests. The extension itself has not been loaded in a real Chrome profile here.
* PRJ-01 tests pin the behavior of the **modernized** code and execute legacy module code in a subprocess — only point
  it at repositories you trust. Python 2 files are detected but not auto-ported.
* PRJ-04 analysis is intra-procedural and Flask-style; it is a triage aid, not a replacement for a SAST/pentest.
  Patches are computed on an AST-normalized copy (comments/formatting are not preserved) — review before merging.
* PRJ-05 noise on released statistics is **not** an end-to-end differential-privacy proof.
* Token prices in `llm.py` are estimates; check your provider's current pricing.
* Nothing here generates revenue by itself; the CFO model only allocates quota and tracks revenue you log.
