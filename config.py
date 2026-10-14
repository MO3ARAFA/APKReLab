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


@dataclass(frozen=True)
class Settings:
    provider: str = "offline"
    api_key: str = ""
    model: str = ""
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    fallback_ollama: bool = True
    budget_usd: float = 50.0
    compute_rate_per_hour: float = 0.10
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
            ollama_host=os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/"),
            ollama_model=os.getenv("OLLAMA_MODEL", "llama3.1"),
            fallback_ollama=os.getenv("LLM_FALLBACK_OLLAMA", "true").lower() == "true",
            budget_usd=_f("AGENCY_BUDGET_USD", 50.0),
            compute_rate_per_hour=_f("COMPUTE_RATE_USD_PER_HOUR", 0.10),
            qc_threshold=_f("QC_THRESHOLD", 95.0),
            max_cycles=int(_f("MAX_REVISION_CYCLES", 3)),
            state_path=Path(os.getenv("AGENCY_STATE_PATH", ROOT / "state" / "agency_state.json")),
            output_dir=Path(os.getenv("AGENCY_OUTPUT_DIR", ROOT / "output")),
        )
