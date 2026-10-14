"""Pluggable LLM layer: Anthropic / OpenAI / Gemini / Ollama, with an offline deterministic fallback.

Every call site passes a `fallback` string so pipelines always produce real artifacts even with no key.
Only the stdlib is used for HTTP, so there is no SDK dependency.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Callable

from config import Settings

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-5-5",
    "openai": "gpt-4o-mini",
    "gemini": "gemini-2.0-flash",
}
# Rough USD per 1M tokens (input, output). Estimates for budgeting only; override by editing here.
PRICING = {
    "anthropic": (3.0, 15.0),
    "openai": (0.15, 0.60),
    "gemini": (0.10, 0.40),
    "ollama": (0.0, 0.0),
    "offline": (0.0, 0.0),
}


@dataclass
class LLMResult:
    text: str
    provider: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    cost_usd: float = 0.0
    live: bool = False


class LLMError(RuntimeError):
    pass


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
    def __init__(self, settings: Settings, recorder: Callable[[LLMResult], None] | None = None):
        self.s = settings
        self.recorder = recorder
        self._ollama_dead = False

    # -- providers -------------------------------------------------------------------------
    def _anthropic(self, system: str, prompt: str, max_tokens: int) -> LLMResult:
        model = self.s.model or DEFAULT_MODELS["anthropic"]
        d = _post(
            "https://api.anthropic.com/v1/messages",
            {"model": model, "max_tokens": max_tokens, "system": system,
             "messages": [{"role": "user", "content": prompt}]},
            {"x-api-key": self.s.api_key, "anthropic-version": "2023-06-01"},
        )
        try:
            text = "".join(b.get("text", "") for b in d["content"])
            u = d.get("usage", {})
        except (KeyError, TypeError) as exc:
            raise LLMError(f"bad anthropic response: {d}") from exc
        return LLMResult(text, "anthropic", model, u.get("input_tokens", 0), u.get("output_tokens", 0), live=True)

    def _openai(self, system: str, prompt: str, max_tokens: int) -> LLMResult:
        model = self.s.model or DEFAULT_MODELS["openai"]
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

    def _gemini(self, system: str, prompt: str, max_tokens: int) -> LLMResult:
        model = self.s.model or DEFAULT_MODELS["gemini"]
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
        return LLMResult(text, "gemini", model, u.get("promptTokenCount", 0), u.get("candidatesTokenCount", 0), live=True)

    def _ollama(self, system: str, prompt: str, max_tokens: int) -> LLMResult:
        d = _post(
            f"{self.s.ollama_host}/api/chat",
            {"model": self.s.ollama_model, "stream": False, "options": {"num_predict": max_tokens},
             "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]},
            {}, timeout=120.0,
        )
        try:
            text = d["message"]["content"]
        except (KeyError, TypeError) as exc:
            raise LLMError(f"bad ollama response: {d}") from exc
        return LLMResult(text, "ollama", self.s.ollama_model, d.get("prompt_eval_count", 0), d.get("eval_count", 0), live=True)

    # -- public ----------------------------------------------------------------------------
    def complete(self, prompt: str, system: str = "You are a precise, concise assistant.",
                 fallback: str = "", max_tokens: int = 800) -> LLMResult:
        """Try the configured provider, then Ollama, then return `fallback` (offline mode)."""
        chain: list[str] = []
        if self.s.provider in {"anthropic", "openai", "gemini"}:
            chain.append(self.s.provider)
        if self.s.provider == "ollama" or (self.s.fallback_ollama and self.s.provider != "offline"):
            chain.append("ollama")
        result: LLMResult | None = None
        for name in chain:
            if name == "ollama" and self._ollama_dead:
                continue
            try:
                result = getattr(self, f"_{name}")(system, prompt, max_tokens)
                break
            except LLMError:
                if name == "ollama":
                    self._ollama_dead = True  # don't re-pay the connection timeout every call
        if result is None:
            result = LLMResult(fallback, "offline", "deterministic-engine", live=False)
            # Estimate size so budgeting still reflects workload; cost is zero offline.
            result.tokens_in, result.tokens_out = len(prompt) // 4, len(fallback) // 4
        pin, pout = PRICING.get(result.provider, (0.0, 0.0))
        result.cost_usd = (result.tokens_in * pin + result.tokens_out * pout) / 1_000_000
        if self.recorder:
            self.recorder(result)
        return result
