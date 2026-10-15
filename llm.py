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

from agents.policy import classify_paid_failure
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


# Free lane: providers that cost $0.00 per call. Endpoints are fixed here (never user-supplied), so a configured key can
# only ever be sent to the provider it belongs to. Model defaults change often: override with FREE_MODEL_<NAME>.
FREE_PROVIDERS: dict[str, dict] = {
    "ollama": {"label": "Ollama (local)", "local": True, "key_env": None, "model": ""},
    "groq": {"label": "Groq", "url": "https://api.groq.com/openai/v1/chat/completions", "key_env": "GROQ_API_KEY",
             "model": "llama-3.1-8b-instant", "data": "check Groq's terms for data use"},
    "openrouter": {"label": "OpenRouter (:free models)", "url": "https://openrouter.ai/api/v1/chat/completions",
                   "key_env": "OPENROUTER_API_KEY", "model": "meta-llama/llama-3.3-70b-instruct:free",
                   "data": "free-model providers may log prompts"},
    "gemini_free": {"label": "Google AI Studio (free tier)", "url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                    "key_env": "GEMINI_FREE_API_KEY", "model": "gemini-2.5-flash", "data": "free-tier content is used to improve Google products"},
    "mistral": {"label": "Mistral (Experiment plan)", "url": "https://api.mistral.ai/v1/chat/completions", "key_env": "MISTRAL_API_KEY",
                "model": "mistral-small-latest", "data": "Experiment-plan requests may be used to train Mistral models"},
}
FREE_ORDER = ["ollama", "groq", "openrouter", "gemini_free", "mistral"]  # most private first
PAID_PROVIDERS = {"anthropic", "openai", "gemini"}


def price_for(provider: str, model: str, tier: int = 2) -> tuple[float, float]:
    """Unknown/overridden models are priced at their provider's tier price (never as free) so the breaker stays safe."""
    if provider in {"ollama", "offline"} or provider in FREE_PROVIDERS:
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
    free: bool = False  # served by the $0 free lane
    paid_failure: str = ""  # "exhausted: ..." / "auth: ..." when the PAID provider refused (feeds PM-06's policy)
    routed: str = ""  # why the paid provider was skipped by a PM-06 routing decision


class LLMError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class BudgetGate(Protocol):
    def try_reserve(self, est_usd: float, tier: int = 1) -> tuple[bool, str]: ...
    def release(self, est_usd: float) -> None: ...
    def route(self, tier: int) -> tuple[bool, str]: ...
    def free_allowed(self, provider: str) -> tuple[bool, str]: ...


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
    except urllib.error.HTTPError as exc:  # keep the API's own explanation (credit, auth, rate limit...) - it is the diagnosis
        detail = ""
        try:
            raw = exc.read(2000).decode("utf-8", "replace")
            body = json.loads(raw)
            err = body.get("error", body) if isinstance(body, dict) else raw
            detail = err.get("message", "") if isinstance(err, dict) else str(err)
        except (ValueError, OSError, AttributeError):
            pass
        raise LLMError(f"HTTP {exc.code}: {(detail or exc.reason or '')[:300]}", status=exc.code) from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        raise LLMError(str(exc)) from exc


class LLMClient:
    def __init__(self, settings: Settings, recorder: Callable[[LLMResult], None] | None = None,
                 budget: BudgetGate | None = None, cache: LLMCache | None = None):
        self.s = settings
        self.recorder = recorder
        self.budget = budget
        self.cache = cache if cache is not None else LLMCache(settings.cache_path)
        self._cool: dict[str, float] = {}  # provider -> time.time() until which it is skipped after a failure

    # -- routing ---------------------------------------------------------------------------
    def model_for(self, provider: str, tier: int) -> str:
        if provider == "ollama":
            return self.s.ollama_model
        override = self.s.model_t2 if tier == 2 else self.s.model_t1
        return override or TIER_MODELS[provider][1 if tier == 2 else 0]

    # -- free lane ---------------------------------------------------------------------------
    def free_names(self) -> list[str]:
        """Free providers this installation can use: FREE_PROVIDERS=a,b overrides; otherwise every provider whose key is
        present in the environment, plus local Ollama when fallback_ollama is on."""
        if not self.s.free_lane:
            return []
        env = os.getenv("FREE_PROVIDERS")
        if env is not None:
            return [n.strip() for n in env.split(",") if n.strip() in FREE_PROVIDERS]
        return [n for n in FREE_ORDER if (n == "ollama" and self.s.fallback_ollama)
                or (n != "ollama" and os.getenv(FREE_PROVIDERS[n]["key_env"], "").strip())]

    def free_model(self, name: str) -> str:
        if name == "ollama":
            return self.s.ollama_model
        return os.getenv(f"FREE_MODEL_{name.upper()}", "").strip() or FREE_PROVIDERS[name]["model"]

    def _free_call(self, name: str, model: str, system: str, prompt: str, max_tokens: int) -> LLMResult:
        if name == "ollama":
            return self._ollama(model, system, prompt, max_tokens)
        spec = FREE_PROVIDERS[name]
        key = os.getenv(spec["key_env"], "").strip()
        if not key:
            raise LLMError(f"{name}: no API key configured")
        d = _post(spec["url"], {"model": model, "max_tokens": max_tokens,
                                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]},
                  {"authorization": f"Bearer {key}"})
        try:
            text = d["choices"][0]["message"]["content"] or ""
            u = d.get("usage", {})
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(f"bad {name} response") from exc
        return LLMResult(text, name, model, u.get("prompt_tokens", 0), u.get("completion_tokens", 0), live=True, free=True)

    def probe(self, name: str) -> tuple[bool, str]:
        """One tiny call to a free provider (costs $0 but uses a little of its quota)."""
        try:
            r = self._free_call(name, self.free_model(name), "Be terse.", "Reply with the single word: OK", MIN_MAX_TOKENS)
            return (bool(r.text.strip()), f"{r.model} replied in {r.tokens_out} tokens")
        except LLMError as exc:
            return False, str(exc)[:200]

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
        """cache -> PM-06 route -> (breaker-gated) paid provider -> free lane -> deterministic `fallback`.
        Always records exactly one result."""
        system = compress_system(system)
        prompt = distill(prompt, max_input_tokens)
        max_tokens = max(max_tokens, MIN_MAX_TOKENS)
        errors: list[str] = []
        paid_failure = routed = blocked = ""

        chain: list[str] = []
        if self.s.provider in PAID_PROVIDERS:
            allow, why = self.budget.route(tier) if self.budget is not None and hasattr(self.budget, "route") else (True, "")
            if allow:
                chain.append(self.s.provider)
            else:
                routed = why  # PM-06 decided this call goes to the free lane (or the templates)
        if self.s.provider != "offline":
            free = self.free_names()
            if self.s.provider == "ollama" and "ollama" not in free:
                free = ["ollama"] + free  # an explicit local provider is always allowed
            chain += [n for n in free if n not in chain]

        result: LLMResult | None = None
        reserved = 0.0
        try:
            for name in chain:
                is_free = name in FREE_PROVIDERS
                if self._cool.get(name, 0) > time.time():
                    continue
                model = self.free_model(name) if is_free else self.model_for(name, tier)
                key = LLMCache.key(f"{name}:{model}" if is_free else model, system, prompt)
                hit = self.cache.get(key)
                if hit:  # $0.00: no API call, no budget or quota check
                    result = LLMResult(hit["text"], name, model, 0, 0, 0.0, live=True, tier=tier, cached=True,
                                       saved_usd=hit["usd"], free=is_free)
                    break
                if is_free:
                    ok, reason = self.budget.free_allowed(name) if self.budget is not None and hasattr(self.budget, "free_allowed") else (True, "")
                    if not ok:
                        blocked = blocked or reason
                        continue
                pin, pout = price_for(name, model, tier)
                if pin or pout:  # paid provider: pre-flight estimate + circuit breaker
                    est = (est_tokens(system + prompt) * pin + max_tokens * pout) / 1_000_000
                    if self.budget is not None:
                        ok, reason = self.budget.try_reserve(est, tier)
                        if not ok:
                            blocked = blocked or reason
                            continue
                        reserved = est
                try:
                    res = self._free_call(name, model, system, prompt, max_tokens) if is_free else \
                        getattr(self, f"_{name}")(model, system, prompt, max_tokens)
                except LLMError as exc:
                    errors.append(f"{name}/{model}: {str(exc)[:200]}")
                    if not is_free:
                        kind = classify_paid_failure(exc.status, str(exc))
                        if kind:
                            paid_failure = f"{kind}: {str(exc)[:160]}"
                    # cool the provider down so a dead/limited endpoint is not hammered (and Ollama's connect timeout is paid once)
                    self._cool[name] = time.time() + (300 if name == "ollama" else 120 if exc.status == 429 else 60)
                    if reserved and self.budget is not None:
                        self.budget.release(reserved)
                        reserved = 0.0
                    continue
                res.tier, res.free = tier, is_free
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
                result = LLMResult(fallback, "offline", "deterministic-engine", live=False, tier=tier, blocked=blocked or routed,
                                   error="; ".join(errors))
                result.tokens_in, result.tokens_out = len(prompt) // 4, len(fallback) // 4
            result.paid_failure, result.routed = paid_failure, routed
            if errors and not result.error:
                result.error = "; ".join(errors)  # a provider failed but a later one answered: keep the diagnosis in the ledger
            if self.recorder:
                self.recorder(result)  # spend is booked BEFORE the reservation is released (no overshoot window)
        finally:
            if reserved and self.budget is not None:
                self.budget.release(reserved)
        return result
