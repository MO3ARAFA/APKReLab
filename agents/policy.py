"""Shared cost-routing rules used by the CFO (enforcement) and PM-06 (decision making).

Kept dependency-free so both can import it without a cycle.
"""
from __future__ import annotations

import json
import os
import re

# Self-imposed safety margins for the free lane (requests per minute / per UTC day). They sit BELOW every published
# figure we found, because published free-tier limits differ by account and change without notice. A 429 from a provider
# also puts it on a cool-down. Override with FREE_LIMITS_JSON='{"groq": {"rpm": 10, "rpd": 200}}'.
FREE_LIMIT_DEFAULTS: dict[str, dict] = {
    "groq": {"rpm": 20, "rpd": 500},
    "openrouter": {"rpm": 15, "rpd": 45},      # :free models allow 50/day until $10 of credit has ever been bought
    "gemini_free": {"rpm": 8, "rpd": 150},
    "mistral": {"rpm": 30, "rpd": 1000},
    "ollama": {"rpm": None, "rpd": None},      # local: no provider limit
}

CREDIT_RE = re.compile(r"credit balance|insufficient (funds|quota|credit)|billing|exceeded your current quota|quota exceeded|"
                       r"payment required|plans? & billing", re.I)


def free_limits(provider: str) -> dict:
    limits = dict(FREE_LIMIT_DEFAULTS.get(provider, {"rpm": 10, "rpd": 100}))
    try:
        limits.update(json.loads(os.getenv("FREE_LIMITS_JSON", "{}")).get(provider, {}))
    except (ValueError, AttributeError, TypeError):
        pass
    return limits


def classify_paid_failure(status: int | None, message: str) -> str:
    """'' (transient/other), 'exhausted' (no credit / quota) or 'auth' (key rejected) for a PAID provider error."""
    if status in (401, 403):
        return "auth"
    if status == 402 or CREDIT_RE.search(message or ""):
        return "exhausted"
    return ""


def paid_allowed(policy: dict | None, pid: str, tier: int) -> tuple[bool, str]:
    """May this project use the paid provider for a call of this tier under the current PM-06 policy?"""
    policy = policy or {}
    mode = policy.get("mode", "normal")
    if mode == "free":
        return False, f"PM-06 free lane: {policy.get('reason', 'paid budget protected')}"
    if mode == "conserve":
        if pid in policy.get("heavy", []):
            return False, f"PM-06 conserve mode: {pid} is a heavy consumer, moved to the free lane"
        if tier >= 2:
            return False, "PM-06 conserve mode: flagship tier paused to protect the remaining budget"
    return True, ""
