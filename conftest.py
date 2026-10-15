"""Hermetic tests: a developer's real .env / API keys must never reach the test suite (no accidental spend)."""
import os

os.environ["AGENCY_SKIP_DOTENV"] = "1"
for _v in ("API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_PROVIDER",
           "TARGETS_FILE", "TARGET_URL", "REVIEWS_FILE", "GROQ_API_KEY", "OPENROUTER_API_KEY", "GEMINI_FREE_API_KEY",
           "MISTRAL_API_KEY", "FREE_PROVIDERS", "FREE_LANE_ENABLED", "FREE_LANE_THRESHOLD_USD", "CONSERVE_BELOW_PCT",
           "PAID_RETRY_HOURS", "FREE_LIMITS_JSON", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "DAEMON_CYCLE_HOURS",
           "DAEMON_QUIET_HOURS", "DAEMON_DAILY_CAP_USD", "DAEMON_LIVE_CAP_USD", "DAEMON_MAX_FAILURES",
           "DAEMON_PROPOSAL_TTL_HOURS", "DAEMON_REJECT_COOLDOWN_HOURS"):
    os.environ.pop(_v, None)

# Tests must never touch the real state/cache files (a polluted cache would fake "savings").
import tempfile  # noqa: E402

_tmp = tempfile.mkdtemp(prefix="agency-tests-")
os.environ.setdefault("AGENCY_STATE_PATH", os.path.join(_tmp, "agency_state.json"))
os.environ.setdefault("AGENCY_CACHE_PATH", os.path.join(_tmp, "llm_cache.json"))
os.environ.setdefault("AGENCY_OUTPUT_DIR", os.path.join(_tmp, "output"))
os.environ.setdefault("AGENCY_TARGETS_PATH", os.path.join(_tmp, "targets.csv"))
os.environ.pop("SENDER_NAME", None)  # tests assert the default sign-off
