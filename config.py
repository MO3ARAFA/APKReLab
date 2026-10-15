"""Central configuration. Secrets and model settings come only from a local .env file / environment."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
if not os.getenv("AGENCY_SKIP_DOTENV"):  # tests set this so a real .env can never leak into them
    # override=True: the project's .env is authoritative (a stray ANTHROPIC_API_KEY in the shell must not win)
    load_dotenv(ROOT / ".env", override=True)

KEY_VARS = ("API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY")
# Free-lane keys (PM-06). Never used as the primary key; listed so the scrubbers redact them too.
FREE_KEY_VARS = ("GROQ_API_KEY", "OPENROUTER_API_KEY", "GEMINI_FREE_API_KEY", "MISTRAL_API_KEY")
# Everything the scrubbers must redact from UI/JSON output (the Telegram bot token is a credential too).
SECRET_VARS = (*KEY_VARS, *FREE_KEY_VARS, "TELEGRAM_BOT_TOKEN")


def detect_provider(key: str) -> str | None:
    """Provider from the key prefix: sk-ant- -> anthropic, AIza -> gemini, other sk- -> openai."""
    if key.startswith("sk-ant-"):
        return "anthropic"
    if key.startswith("AIza"):
        return "gemini"
    if key.startswith("sk-"):
        return "openai"
    return None


def _f(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return float(default)


# Assumption-based value of sellable artifacts (USD per unit). These are ESTIMATES, not revenue.
# Derived from the operator's plan: 500 audits -> one $1,500 client ($3/audit); a legacy-code audit closes a
# $2,500 deal ~1 in 25 ($100); a packaged $39 lifetime-deal extension ~10 early sales ($390). Override with
# ROI_VALUES_JSON='{"audits_ready": 2.0}'.
_DEFAULT_ROI = {"audits_ready": 3.0, "legacy_repos_audited": 100.0, "extensions_packaged": 390.0,
                "patches_ready": 0.0, "datasets_generated": 0.0}


def sender_name() -> str:
    """Sign-off for outreach messages (SENDER_NAME in .env). Stripped of characters that would look like placeholders."""
    name = re.sub(r"[\[\]{}<>\r\n]", "", os.getenv("SENDER_NAME", "")).strip()[:60]
    return name or "Mohamed"


def roi_values() -> dict:
    import json
    vals = dict(_DEFAULT_ROI)
    try:
        vals.update({k: float(v) for k, v in json.loads(os.getenv("ROI_VALUES_JSON", "{}")).items()})
    except (ValueError, TypeError, AttributeError):
        pass
    return vals


@dataclass(frozen=True)
class Settings:
    provider: str = "offline"
    api_key: str = ""
    model: str = ""
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    fallback_ollama: bool = True
    budget_usd: float = 10.0  # total seed capital: the agency-wide hard cap
    model_t1: str = ""  # tier-1 workhorse override (default per provider in llm.py)
    model_t2: str = ""  # tier-2 gatekeeper override
    cache_path: Path = ROOT / "state" / "llm_cache.json"
    targets_path: Path = ROOT / "targets.csv"
    free_lane: bool = True  # PM-06 may route to free providers when the paid budget is low
    free_threshold_usd: float = 0.50  # remaining global budget at/below which everything moves to the free lane
    conserve_pct: float = 25.0  # remaining % at/below which heavy projects move to the free lane and flagship calls pause
    paid_retry_hours: float = 6.0  # how long a paid-provider failure (no credit / bad key) keeps the free lane on
    # Unattended operation (Phase 7). The Telegram token / chat id are read straight from the environment, not stored here.
    daemon_cycle_hours: float = 12.0  # hours between auto-pilot cycles
    daemon_quiet_hours: str = "23-8"  # local hours when notifications are sent silently ("" = never quiet)
    daemon_daily_cap_usd: float = 0.15  # most real money the daemon may spend per local day (approved cycles + briefings)
    daemon_live_cap_usd: float = 0.10  # per-cycle cap for a paid cycle the owner approved
    daemon_max_failures: int = 3  # consecutive failed cycles before the daemon pauses itself
    daemon_proposal_ttl_hours: float = 24.0  # an unanswered decision expires (never executed late on stale facts)
    daemon_reject_cooldown_hours: float = 24.0  # after a "no", the same proposal is not repeated for this long
    compute_rate_per_hour: float = 0.0  # local compute is free; the seed budget is for API spend
    qc_threshold: float = 95.0
    max_cycles: int = 3
    state_path: Path = ROOT / "state" / "agency_state.json"
    output_dir: Path = ROOT / "output"

    @staticmethod
    def load() -> "Settings":
        key = next((os.getenv(v, "").strip() for v in KEY_VARS if os.getenv(v, "").strip()), "")
        provider = os.getenv("LLM_PROVIDER", "").strip().lower()
        detected = detect_provider(key) if key else None
        if detected and provider != "ollama":
            provider = detected  # the key's prefix is the source of truth over a stale LLM_PROVIDER
        provider = provider or "anthropic"
        # No key for a hosted provider -> run offline (deterministic engines) unless ollama is requested.
        if provider in {"anthropic", "openai", "gemini"} and not key:
            provider = "offline"
            # No paid key but the owner registered free-tier keys by hand: live mode runs on the free lane only ($0).
            if os.getenv("FREE_LANE_ENABLED", "true").lower() == "true" and (
                    any(os.getenv(v, "").strip() for v in FREE_KEY_VARS) or os.getenv("FREE_PROVIDERS", "").strip()):
                provider = "free"
        return Settings(
            provider=provider,
            api_key=key,
            model=os.getenv("LLM_MODEL", "").strip(),
            model_t1=(os.getenv("LLM_MODEL_T1") or os.getenv("LLM_MODEL") or "").strip(),
            model_t2=os.getenv("LLM_MODEL_T2", "").strip(),
            cache_path=Path(os.getenv("AGENCY_CACHE_PATH", ROOT / "state" / "llm_cache.json")),
            targets_path=Path(os.getenv("AGENCY_TARGETS_PATH", ROOT / "targets.csv")),
            free_lane=os.getenv("FREE_LANE_ENABLED", "true").lower() == "true",
            free_threshold_usd=_f("FREE_LANE_THRESHOLD_USD", 0.50),
            conserve_pct=_f("CONSERVE_BELOW_PCT", 25.0),
            paid_retry_hours=_f("PAID_RETRY_HOURS", 6.0),
            daemon_cycle_hours=_f("DAEMON_CYCLE_HOURS", 12.0),
            daemon_quiet_hours=os.getenv("DAEMON_QUIET_HOURS", "23-8").strip(),
            daemon_daily_cap_usd=_f("DAEMON_DAILY_CAP_USD", 0.15),
            daemon_live_cap_usd=_f("DAEMON_LIVE_CAP_USD", 0.10),
            daemon_max_failures=int(_f("DAEMON_MAX_FAILURES", 3)),
            daemon_proposal_ttl_hours=_f("DAEMON_PROPOSAL_TTL_HOURS", 24.0),
            daemon_reject_cooldown_hours=_f("DAEMON_REJECT_COOLDOWN_HOURS", 24.0),
            ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/"),
            ollama_model=os.getenv("OLLAMA_MODEL", "llama3.1"),
            fallback_ollama=os.getenv("LLM_FALLBACK_OLLAMA", "true").lower() == "true",
            budget_usd=_f("SEED_CAPITAL_USD", _f("AGENCY_BUDGET_USD", 10.0)),
            compute_rate_per_hour=_f("COMPUTE_RATE_USD_PER_HOUR", 0.0),
            qc_threshold=_f("QC_THRESHOLD", 95.0),
            max_cycles=int(_f("MAX_REVISION_CYCLES", 3)),
            state_path=Path(os.getenv("AGENCY_STATE_PATH", ROOT / "state" / "agency_state.json")),
            output_dir=Path(os.getenv("AGENCY_OUTPUT_DIR", ROOT / "output")),
        )
