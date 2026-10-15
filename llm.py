"""Pluggable LLM layer with a 2-tier model router, response cache and budget circuit breaker.

Tier 1 (workhorse, ~90% of calls): cheapest capable model - PM drafts, review mining, sniper drafts.
Tier 2 (gatekeeper, ~10%): flagship model - CEO quality gate and complex security-patch reasoning only.

Zero-waste mechanics (all local, all before any paid call):
  1. system prompts are compressed to <=300 tokens, user prompts distilled to <=500 tokens (HTML stripped);
  2. identical (model, system, prompt) requests are served from state/llm_cache.json for $0.00;
  3. a pre-flight cost estimate is checked against the CFO's budget gate; if the call would breach a project
     sub-budget or the global cap it is aborted and the deterministic fallback is returned instead.
Only the stdlib is used for HTTP (no SDK dependency).
"""
from __future__ import annotations

import hashlib
import html as htmllib
import json
import os
import re
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from config import Settings

MIN_MAX_TOKENS = 512  # floor: a too-small cap can be eaten by hidden reasoning and bill for an empty answer
MAX_SYSTEM_TOKENS = 300
MAX_INPUT_TOKENS = 500
CACHE_MAX_ENTRIES = 2000

# (tier-1 workhorse, tier-2 gatekeeper). Anthropic IDs/prices verified against the current model table.
TIER_MODELS = {
    "anthropic": ("claude-haiku-5-5", "claude-opus-5-5"),
    "openai": ("gpt-4o-mini", "gpt-4o"),
    "gemini": ("gemini-2.5-flash", "gemini-2.5-pro"),
}
# USD per 1M tokens (input, output). Non-Anthropic prices are estimates - verify with your provider.
PRICING = {
    "claude-haiku-5-5": (0.10, 0.50), "claude-sonnet-5-5": (2.00, 10.00), "claude-opus-5-5": (4.00, 20.00),
    "claude-fable-5-1": (10.00, 50.00),
    "gpt-4o-mini": (0.15, 0.60), "gpt-4o": (2.50, 10.00),
    "gemini-2.5-flash": (0.30, 2.50), "gemini-2.5-pro": (1.25, 10.00),
}


def price_for(provider: str, model: str, tier: int = 2) -> tuple[float, float]:
    """Unknown/overridden models are priced at their provider's tier price (never as free) so the breaker stays safe."""
    if provider in {"ollama", "offline"}:
        return (0.0, 0.0)
    if model in PRICING:
        return PRICING[model]
    t1, t2 = TIER_MODELS.get(provider, (None, None))
    return PRICING.get(t2 if tier == 2 else t1, PRICING["claude-opus-5-5"])


def est_tokens(text: str) -> int:
    """Deliberately pessimistic (~3 chars/token) so pre-flight estimates over- rather than under-state cost."""
    return len(text) // 3 + 8


def strip_html(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", text)
    text = re.sub(r"(?s)<!--.*?-->", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    return htmllib.unescape(text)


def _clip(text: str, max_tokens: int, head: float = 0.7) -> str:
    limit = max_tokens * 3
    if len(text) <= limit:
        return text
    h = int(limit * head)
    return text[:h].rstrip() + " ... " + text[-(limit - h - 5):].lstrip()


def distill(text: str, max_tokens: int = MAX_INPUT_TOKENS) -> str:
    """Hybrid pre-processing: strip markup, normalise whitespace, keep head+tail within the token budget."""
    # Strip only real HTML documents (>=3 tags, or a document-level tag); a plain sentence that merely mentions
    # "<h1>" or "<head>" must reach the model intact.
    if (len(re.findall(r"<[a-zA-Z/!][^>]*>", text)) >= 3 and re.search(r"</[a-zA-Z][a-zA-Z0-9]*>", text)) \
            or re.search(r"(?i)<(!doctype|html|body)\b", text):
        text = " ".join(strip_html(text).split())
    else:
        text = re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]+", " ", text)).strip()
    return _clip(text, max_tokens)


def compress_system(system: str, max_tokens: int = MAX_SYSTEM_TOKENS) -> str:
    s = " ".join(system.split())
    if est_tokens(s) <= max_tokens:
        return s
    cut = s[: (max_tokens - 8) * 3]
    end = max(cut.rfind(". "), cut.rfind("; "))
    return (cut[: end + 1] if end > len(cut) // 2 else cut).rstrip()


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    live: bool = False
    tier: int = 1
    cached: bool = False
    saved_usd: float = 0.0
    blocked: str = ""  # reason a paid call was aborted by the circuit breaker
    error: str = ""  # provider failure that forced the fallback (never contains credentials)


class LLMError(RuntimeError):
    pass


class BudgetGate(Protocol):
    def try_reserve(self, est_usd: float) -> tuple[bool, str]: ...
    def release(self, est_usd: float) -> None: ...


class LLMCache:
    """Thread-safe JSON response cache keyed by sha256(model, system, prompt)."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self._lock = threading.Lock()
        self.entries: dict[str, dict] = {}
        try:
            self.entries = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            self.entries = {}

    @staticmethod
    def key(model: str, system: str, prompt: str) -> str:
        return hashlib.sha256(json.dumps([model, system, prompt], ensure_ascii=False).encode()).hexdigest()

    def get(self, key: str) -> dict | None:
        with self._lock:
            return dict(self.entries[key]) if key in self.entries else None

    def put(self, key: str, text: str, tokens_in: int, tokens_out: int, usd: float, model: str) -> None:
        with self._lock:
            self.entries[key] = {"text": text, "tin": tokens_in, "tout": tokens_out, "usd": usd, "model": model, "ts": time.time()}
            if len(self.entries) > CACHE_MAX_ENTRIES:
                for k, _ in sorted(self.entries.items(), key=lambda kv: kv[1]["ts"])[: len(self.entries) - CACHE_MAX_ENTRIES]:
                    del self.entries[k]
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".cache-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as fh:
                    json.dump(self.entries, fh)
                os.replace(tmp, self.path)
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise


def _post(url: str, payload: dict, headers: dict, timeout: float = 60.0) -> dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"content-type": "application/json", **headers}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise LLMError(str(exc)) from exc


class LLMClient:
    def __init__(self, settings: Settings, recorder: Callable[[LLMResult], None] | None = None,
                 budget: BudgetGate | None = None, cache: LLMCache | None = None):
        self.s = settings
        self.recorder = recorder
        self.budget = budget
        self.cache = cache if cache is not None else LLMCache(settings.cache_path)
        self._ollama_dead = False

    # -- routing ---------------------------------------------------------------------------
    def model_for(self, provider: str, tier: int) -> str:
        if provider == "ollama":
            return self.s.ollama_model
        override = self.s.model_t2 if tier == 2 else self.s.model_t1
        return override or TIER_MODELS[provider][1 if tier == 2 else 0]

    # -- providers (model passed explicitly) -----------------------------------------------
    def _anthropic(self, model: str, system: str, prompt: str, max_tokens: int) -> LLMResult:
        d = _post(
            "https://api.anthropic.com/v1/messages",
            {"model": model, "max_tokens": max_tokens, "system": system,
             "output_config": {"effort": "low"},  # bounds hidden reasoning spend on adaptive-thinking models
             # Haiku 5.5 may run with thinking off (accepted at effort <= high); Opus 5.5 cannot, so omit it there.
             **({"thinking": {"type": "disabled"}} if model.startswith("claude-haiku-5") else {}),
             "messages": [{"role": "user", "content": prompt}]},
            {"x-api-key": self.s.api_key, "anthropic-version": "2023-06-01"},
        )
        try:
            text = "".join(b.get("text", "") for b in d["content"] if b.get("type", "text") == "text")
            u = d.get("usage", {})
        except (KeyError, TypeError) as exc:
            raise LLMError(f"bad anthropic response: {d}") from exc
        return LLMResult(text, "anthropic", model, u.get("input_tokens", 0), u.get("output_tokens", 0), live=True)

    def _openai(self, model: str, system: str, prompt: str, max_tokens: int) -> LLMResult:
        d = _post(
            "https://api.openai.com/v1/chat/completions",
            {"model": model, "max_tokens": max_tokens,
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]},
            {"authorization": f"Bearer {self.s.api_key}"},
        )
        try:
            text = d["choices"][0]["message"]["content"] or ""
            u = d.get("usage", {})
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"bad openai response: {d}") from exc
        return LLMResult(text, "openai", model, u.get("prompt_tokens", 0), u.get("completion_tokens", 0), live=True)

    def _gemini(self, model: str, system: str, prompt: str, max_tokens: int) -> LLMResult:
        d = _post(
            f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
            {"systemInstruction": {"parts": [{"text": system}]},
             "contents": [{"role": "user", "parts": [{"text": prompt}]}],
             "generationConfig": {"maxOutputTokens": max_tokens}},
            {"x-goog-api-key": self.s.api_key},
        )
        try:
            text = "".join(p.get("text", "") for p in d["candidates"][0]["content"]["parts"])
            u = d.get("usageMetadata", {})
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"bad gemini response: {d}") from exc
        # candidatesTokenCount excludes hidden thinking tokens, which are billed as output
        out = u.get("candidatesTokenCount", 0) + u.get("thoughtsTokenCount", 0)
        return LLMResult(text, "gemini", model, u.get("promptTokenCount", 0), out, live=True)

    def _ollama(self, model: str, system: str, prompt: str, max_tokens: int) -> LLMResult:
        d = _post(
            f"{self.s.ollama_host}/api/chat",
            {"model": model, "stream": False, "options": {"num_predict": max_tokens},
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]},
            {}, timeout=120.0,
        )
        try:
            text = d["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError(f"bad ollama response: {d}") from exc
        return LLMResult(text, "ollama", model, d.get("prompt_eval_count", 0), d.get("eval_count", 0), live=True)

    # -- public ----------------------------------------------------------------------------
    def complete(self, prompt: str, system: str = "You are a precise, concise assistant.", fallback: str = "",
                 max_tokens: int = 800, tier: int = 1, max_input_tokens: int = MAX_INPUT_TOKENS) -> LLMResult:
        """cache -> (breaker-gated) provider chain -> deterministic `fallback`. Always records exactly one result."""
        system = compress_system(system)
        prompt = distill(prompt, max_input_tokens)
        max_tokens = max(max_tokens, MIN_MAX_TOKENS)
        errors: list[str] = []
        chain: list[str] = []
        if self.s.provider in {"anthropic", "openai", "gemini"}:
            chain.append(self.s.provider)
        if self.s.provider == "ollama" or (self.s.fallback_ollama and self.s.provider != "offline"):
            chain.append("ollama")

        result: LLMResult | None = None
        blocked = ""
        reserved = 0.0
        try:
            for name in chain:
                if name == "ollama" and self._ollama_dead:
                    continue
                model = self.model_for(name, tier)
                key = LLMCache.key(model, system, prompt)
                hit = self.cache.get(key)
                if hit:  # $0.00: no API call, no budget check
                    result = LLMResult(hit["text"], name, model, 0, 0, 0.0, live=True, tier=tier, cached=True,
                                       saved_usd=hit["usd"])
                    break
                pin, pout = price_for(name, model, tier)
                if pin or pout:  # paid provider: pre-flight estimate + circuit breaker
                    est = (est_tokens(system + prompt) * pin + max_tokens * pout) / 1_000_000
                    if self.budget is not None:
                        ok, reason = self.budget.try_reserve(est)
                        if not ok:
                            blocked = blocked or reason
                            continue
                        reserved = est
                try:
                    res = getattr(self, f"_{name}")(model, system, prompt, max_tokens)
                except LLMError as exc:
                    errors.append(f"{name}/{model}: {str(exc)[:200]}")
                    if name == "ollama":
                        self._ollama_dead = True  # don't re-pay the connection timeout every call
                    if reserved and self.budget is not None:
                        self.budget.release(reserved)
                        reserved = 0.0
                    continue
                res.tier = tier
                res.cost_usd = (res.tokens_in * pin + res.tokens_out * pout) / 1_000_000
                if not res.text.strip():
                    # Tokens were billed even though nothing usable came back: book the cost, use the fallback,
                    # never cache, and don't retry on another provider.
                    res.error = "empty response (tokens billed)"
                    res.text, res.live = fallback, False
                else:
                    self.cache.put(key, res.text, res.tokens_in, res.tokens_out, res.cost_usd, model)
                result = res
                break
            if result is None:
                result = LLMResult(fallback, "offline", "deterministic-engine", live=False, tier=tier, blocked=blocked,
                                   error="; ".join(errors))
                result.tokens_in, result.tokens_out = len(prompt) // 4, len(fallback) // 4
            if self.recorder:
                self.recorder(result)  # spend is booked BEFORE the reservation is released (no overshoot window)
        finally:
            if reserved and self.budget is not None:
                self.budget.release(reserved)
        return result
