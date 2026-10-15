# PM-06 Free Tier Guide: keep the agency running at $0.00 (as far as it honestly can)

PM-06 (AI Growth & Cost-Hacking Agent) watches what each model call costs. When the paid balance runs low, or the paid provider refuses a call, it moves work to a **free lane**. This guide is how *you* set that lane up. It is deliberately manual.

## What PM-06 does and does not do

- It never creates accounts, never fills sign-up forms and never touches CAPTCHAs, phone or identity checks. Those exist to stop automation, and bypassing them breaks the provider's terms and gets accounts banned.
- It does not use several accounts, several identities or rotating keys to multiply a free quota. Use one account per person, and keep to the limits each provider publishes.
- It uses only keys you add to `.env` yourself, and it only sends them to the provider they belong to.
- There is no guarantee of "$0 forever". Free tiers change, shrink and disappear, and some use your prompts to improve their products. When every free provider is unavailable, PM-06 falls back to the built-in deterministic templates, which cost exactly $0 but are lower quality than a model.

## How PM-06 routes (automatic)

- **normal**: the paid provider handles everything. The $10 circuit breaker still applies.
- **conserve**: 25% or less of the seed is left (`CONSERVE_BELOW_PCT`). The two most token-hungry projects use the free lane, and the flagship tier-2 model is paused. This only happens if a free provider is actually configured.
- **free**: $0.50 or less is left (`FREE_LANE_THRESHOLD_USD`), the hard cap is reached, or the paid provider just returned "no credit" or "bad key". All calls use the free lane. After `PAID_RETRY_HOURS` (6 by default) the paid provider is tried again.

Inside the free lane, providers are tried from most private to least: Ollama (on your device), Groq, OpenRouter `:free` models, Google AI Studio, Mistral. Each one has self-imposed request limits set *below* the published numbers (`FREE_LIMITS_JSON` overrides them), a cool-down after any error, and a shared response cache so repeated prompts cost nothing.

## Register by hand, then add the key

Every figure below came from public documentation or third-party summaries at the time of writing. Treat them as hints and verify the current limits in each provider's own console before relying on them.

### Ollama (local, nothing leaves your device)
- Download: https://ollama.com/download
- On Termux (Android) community guides install it with `pkg install ollama` and `ollama serve`. It needs roughly 2 to 8 GB of free RAM depending on the model, so use a small model such as `llama3.2:1b`.
- No key. Set `OLLAMA_MODEL=<model you pulled>` and keep `LLM_FALLBACK_OLLAMA=true`.

### Groq
- Console: https://console.groq.com/keys (no card was required when this was written).
- Limits apply per organization and per model; exceeding them returns HTTP 429.
- `.env`: `GROQ_API_KEY=...` (override the model with `FREE_MODEL_GROQ=`). Read Groq's terms for data use.

### OpenRouter (`:free` models)
- Keys: https://openrouter.ai/settings/keys
- Free models were limited to about 20 requests/minute and about 50 requests/day per account (reported as 1000/day after you have ever bought $10 of credit). PM-06 defaults to 45/day.
- `.env`: `OPENROUTER_API_KEY=...`. Free-model providers may log prompts.

### Google AI Studio (Gemini free tier)
- Key: https://aistudio.google.com/apikey
- Content sent on the free tier may be used to improve Google products, so do not send client data through it.
- `.env`: `GEMINI_FREE_API_KEY=...`. This is a separate variable from `GEMINI_API_KEY` (the paid key), so the free key can never be billed as the paid one.

### Mistral (Experiment plan)
- Console: https://console.mistral.ai/api-keys
- The Experiment plan needed phone verification when this was written, and requests may be used to train Mistral models.
- `.env`: `MISTRAL_API_KEY=...`

### Cloudflare Workers AI (reference, not wired in)
- The free allowance was 10,000 neurons per day, resetting at 00:00 UTC. See https://developers.cloudflare.com/workers-ai/platform/pricing/
- It is not an OpenAI-compatible drop-in for this agency yet, so PM-06 does not call it.

## Startup credit programs (apply manually)

Cloud and AI vendors run credit programs for early-stage companies, for example AWS Activate, Google for Startups Cloud Program and Microsoft for Startups Founders Hub; some AI labs give credits through venture partners. Eligibility rules are strict (a real company, often an investor or accelerator link). Apply honestly with your real details, read the program terms, and never describe a business you do not have. PM-06 does not apply for you.

## Check it works

```
python main.py --free-tiers            # which providers are configured, today's usage, where to register
python main.py --free-tiers --check    # one tiny request per configured provider (uses a little quota)
python main.py --growth                # spend per model and project, runway, current policy
```

The web command center shows the same in the **PM-06 Free Tiers** tab, and a `PM-06 policy` row appears in the ledger whenever the mode changes. Only the presence of a key is ever shown, never its value.
