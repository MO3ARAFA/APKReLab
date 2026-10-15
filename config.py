"""Central configuration. Secrets and model settings come only from a local .env file / environment."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")


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
    compute_rate_per_hour: float = 0.0  # local compute is free; the seed budget is for API spend
    qc_threshold: float = 95.0
    max_cycles: int = 3
    state_path: Path = ROOT / "state" / "agency_state.json"
    output_dir: Path = ROOT / "output"

    @staticmethod
    def load() -> "Settings":
        key = os.getenv("API_KEY", "").strip()
        provider = os.getenv("LLM_PROVIDER", "anthropic").strip().lower()
        # No key for a hosted provider -> run offline (deterministic engines) unless ollama is requested.
        if provider in {"anthropic", "openai", "gemini"} and not key:
            provider = "offline"
        return Settings(
            provider=provider,
            api_key=key,
            model=os.getenv("LLM_MODEL", "").strip(),
            model_t1=(os.getenv("LLM_MODEL_T1") or os.getenv("LLM_MODEL") or "").strip(),
            model_t2=os.getenv("LLM_MODEL_T2", "").strip(),
            cache_path=Path(os.getenv("AGENCY_CACHE_PATH", ROOT / "state" / "llm_cache.json")),
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
