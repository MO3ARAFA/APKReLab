"""PM-06 - AI Growth & Cost-Hacking Agent.

Watches what every model call really costs and decides, before each call, where it may run:

  normal    paid provider for everything (the CFO circuit breaker still guards the $10 cap)
  conserve  remaining budget <= CONSERVE_BELOW_PCT: the two most token-hungry projects move to the free lane and the
            flagship tier-2 model is paused for everyone
  free      remaining budget <= FREE_LANE_THRESHOLD_USD, breaker tripped, or the paid provider just refused us
            (no credit / bad key): every call goes to the free lane

The free lane is: local Ollama, then any free-tier provider the owner has *manually* registered and put a key in .env
(Groq, OpenRouter ':free' models, Google AI Studio, Mistral Experiment), each under self-imposed rpm/rpd margins and a
cool-down after errors. When nothing in the lane is available the deterministic templates run, which cost exactly $0.
PM-06 never creates accounts, never touches CAPTCHAs/identity checks and never rotates identities: see docs/FREE_TIERS.md.
"""
from __future__ import annotations

import os
import socket
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Callable

from agents.policy import free_limits
from config import Settings
from llm import FREE_ORDER, FREE_PROVIDERS, LLMCache, LLMClient
from state import AgencyState, now

CONSERVE_EXIT_MARGIN_PCT = 5.0  # hysteresis: leave conserve mode only once remaining% is this far above the entry level
HEAVY_COUNT = 2

# Where the owner registers by hand (official consoles). Nothing here is ever called by the agency.
SIGNUP = {
    "ollama": "https://ollama.com/download",
    "groq": "https://console.groq.com/keys",
    "openrouter": "https://openrouter.ai/settings/keys",
    "gemini_free": "https://aistudio.google.com/apikey",
    "mistral": "https://console.mistral.ai/api-keys",
}


class GrowthAgent:
    pm_id = "PM-06"

    def __init__(self, state: AgencyState, settings: Settings, cache: LLMCache | None = None,
                 slot: Callable[[str], tuple[bool, str]] | None = None, readonly: bool = False):
        self.state, self.s, self.readonly = state, settings, readonly  # readonly: never writes (used by the web UI)
        self.client = LLMClient(settings, cache=cache)  # only used for lane discovery and probes
        self.slot = slot  # CFO.free_allowed: probes consume the same self-imposed quota as real calls
        self._ollama_seen: tuple[float, bool] = (0.0, False)

    # -- policy ----------------------------------------------------------------------------
    def _ollama_up(self) -> bool:
        """Is a local Ollama server answering on its port? (TCP connect only, cached 30 s.) Without this, the default
        LLM_FALLBACK_OLLAMA=true would make PM-06 believe a free lane exists on every machine."""
        t, up = self._ollama_seen
        if time.time() - t < 30:
            return up
        u = urllib.parse.urlsplit(self.s.ollama_host)
        try:
            with socket.create_connection((u.hostname or "localhost", u.port or 11434), timeout=0.4):
                up = True
        except OSError:
            up = False
        self._ollama_seen = (time.time(), up)
        return up

    def free_lane(self) -> list[str]:
        names = self.client.free_names()
        if self.s.provider == "ollama" and "ollama" not in names:
            names = ["ollama"] + names
        return [n for n in names if n != "ollama" or self._ollama_up()]

    def _paid_live(self) -> bool:
        return self.s.provider in ("anthropic", "openai", "gemini")

    def decide(self, snap: dict) -> dict:
        """Pure policy decision from a state snapshot (no writes)."""
        seed = snap.get("seed_usd", snap.get("budget_usd", 0.0)) or 0.0
        projects = snap["projects"]
        burn = sum(p["spent_usd"] for p in projects.values())
        remaining = seed - burn
        pct = (remaining / seed * 100) if seed > 0 else 0.0
        ranked = sorted(((p["tokens_in"] + p["tokens_out"], pid) for pid, p in projects.items() if p["tokens_in"] + p["tokens_out"] > 0),
                        reverse=True)
        heavy = [pid for _, pid in ranked[:HEAVY_COUNT]]
        lane = self.free_lane()
        prev = (snap.get("policy") or {}).get("mode", "normal")
        flag = (snap.get("policy_flags") or {}).get("paid_failure")
        base = {"heavy": heavy, "free_lane": lane, "remaining_usd": round(remaining, 4), "remaining_pct": round(pct, 1)}

        if not self.s.free_lane or not self._paid_live():
            return {"mode": "normal", "reason": "free lane disabled" if not self.s.free_lane else "no paid provider in use", **base}
        if flag and now() - flag["t"] < self.s.paid_retry_hours * 3600:
            return {"mode": "free", "reason": f"paid provider refused ({flag['reason'][:90]}); retrying in <= {self.s.paid_retry_hours:g} h", **base}
        if remaining <= 1e-4:
            return {"mode": "free", "reason": "hard cap reached: paid calls are blocked", **base}
        if lane:  # diverting only makes sense when there is somewhere free to go
            if remaining <= self.s.free_threshold_usd:
                return {"mode": "free", "reason": f"${remaining:.2f} left (<= ${self.s.free_threshold_usd:.2f}): protecting the last dollars", **base}
            limit = self.s.conserve_pct + (CONSERVE_EXIT_MARGIN_PCT if prev == "conserve" else 0.0)
            if pct <= limit:
                return {"mode": "conserve", "reason": f"{pct:.0f}% of the seed left (<= {self.s.conserve_pct:g}%)", **base}
        return {"mode": "normal", "reason": "budget healthy", **base}

    def assess(self) -> dict:
        """Decide, persist the policy when it changed (and log it in the ledger) and return it."""
        snap = self.state.snapshot()
        pol = self.decide(snap)
        if self.readonly:
            return {**pol, "t": now()}
        old = snap.get("policy") or {}
        if (old.get("mode"), old.get("reason"), old.get("heavy"), old.get("free_lane")) == (pol["mode"], pol["reason"], pol["heavy"], pol["free_lane"]):
            return old
        pol["t"] = now()

        def f(d):
            d["policy"] = pol
            if old.get("mode", "normal") != pol["mode"]:
                d["ledger"].append({"t": now(), "kind": "policy", "from": old.get("mode", "normal"), "to": pol["mode"],
                                    "reason": pol["reason"], "usd": 0.0})
        self.state.update(f)
        return pol

    # -- reports ---------------------------------------------------------------------------
    def cost_report(self) -> dict:
        pol = self.assess()
        snap = self.state.snapshot()
        seed = snap.get("seed_usd", 0.0)
        projects = snap["projects"]
        burn = sum(p["spent_usd"] for p in projects.values())
        paid = [e for e in snap["ledger"] if e["kind"] == "api" and not e.get("free") and e.get("provider") != "offline"]
        by_model: dict[str, dict] = {}
        for e in paid:
            m = by_model.setdefault(f"{e.get('provider')}/{e.get('model')}", {"calls": 0, "tokens_in": 0, "tokens_out": 0, "usd": 0.0})
            m["calls"] += 1
            m["tokens_in"] += e.get("tokens_in", 0)
            m["tokens_out"] += e.get("tokens_out", 0)
            m["usd"] = round(m["usd"] + e.get("usd", 0.0), 8)
        per_call = (sum(e.get("usd", 0.0) for e in paid) / len(paid)) if paid else 0.0
        remaining = seed - burn
        span = (paid[-1]["t"] - paid[0]["t"]) if len(paid) > 1 else 0.0
        per_hour = (sum(e.get("usd", 0.0) for e in paid[1:]) / (span / 3600)) if span > 60 else None
        return {
            "seed_usd": seed, "spent_usd": round(burn, 6), "remaining_usd": round(remaining, 6),
            "remaining_pct": round(remaining / seed * 100, 1) if seed else 0.0,
            "paid_calls": len(paid), "avg_cost_per_call_usd": round(per_call, 6),
            "runway_calls": int(remaining / per_call) if per_call > 0 else None,
            "burn_usd_per_hour": round(per_hour, 4) if per_hour is not None else None,
            "runway_hours": round(remaining / per_hour, 1) if per_hour else None,
            "by_model": [{"model": k, **v} for k, v in sorted(by_model.items(), key=lambda kv: -kv[1]["usd"])],
            "by_project": sorted(({"project": pid, "name": p["name"], "spent_usd": p["spent_usd"],
                                   "tokens": p["tokens_in"] + p["tokens_out"], "free_calls": p.get("free_calls", 0),
                                   "heavy": pid in pol.get("heavy", [])} for pid, p in projects.items()),
                                  key=lambda r: -r["tokens"]),
            "free": {"requests": sum(day.get("requests", 0) for prov in snap.get("free_usage", {}).values() for day in prov.values()),
                     "tokens": sum(day.get("tokens", 0) for prov in snap.get("free_usage", {}).values() for day in prov.values()),
                     "avoided_usd": round(snap.get("free_savings_usd", 0.0), 6)},
            "policy": pol,
        }

    def providers(self) -> list[dict]:
        """Status of every free provider. Reports whether a key is *present*, never the key."""
        snap = self.state.snapshot()
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        active = self.free_lane()
        rows = []
        for name in FREE_ORDER:
            spec = FREE_PROVIDERS[name]
            lim = free_limits(name)
            used = snap.get("free_usage", {}).get(name, {}).get(day, {})
            key_env = spec.get("key_env")
            rows.append({
                "name": name, "label": spec["label"], "local": bool(spec.get("local")),
                "key_env": key_env, "configured": True if spec.get("local") else bool(os.getenv(key_env or "", "").strip()),
                "active": name in active, "model": self.client.free_model(name),
                "requests_today": used.get("requests", 0), "tokens_today": used.get("tokens", 0),
                "rpm": lim.get("rpm"), "rpd": lim.get("rpd"), "data_note": spec.get("data", "stays on your device" if spec.get("local") else ""),
                "signup_url": SIGNUP.get(name, ""),
            })
        return rows

    def probe(self, names: list[str] | None = None) -> list[dict]:
        """One tiny call per active free provider (cost $0, uses a little of its quota). Used by `--free-tiers --check`."""
        out = []
        for name in names or self.free_lane():
            if self.slot is not None:
                ok, why = self.slot(name)
                if not ok:
                    out.append({"name": name, "ok": False, "detail": why})
                    continue
            ok, detail = self.client.probe(name)
            out.append({"name": name, "ok": ok, "detail": detail})
        return out

    def status(self) -> dict:
        return {"policy": self.assess(), "providers": self.providers(), "report": self.cost_report(), "checked": time.time()}
