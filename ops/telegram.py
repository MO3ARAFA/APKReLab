"""Minimal Telegram Bot API bridge (stdlib only) between the AI COO and the owner.

Security model
  * The bot token lives only in .env (TELEGRAM_BOT_TOKEN); it is redacted from every error message and log line.
  * Exactly one chat is trusted (TELEGRAM_CHAT_ID). Updates from any other chat or user are dropped without a reply.
  * Messages are sent as PLAIN TEXT (no parse_mode): company names and findings come from scraped websites, so they must
    never be interpreted as markup. Buttons carry only a server-side proposal id, never a command.
  * Long polling (getUpdates): nothing listens on the phone, no webhook, no open port.
Telegram bot chats are not end-to-end encrypted; briefings therefore contain business facts but never API keys.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
from typing import Callable

API = "https://api.telegram.org"
MAX_LEN = 3900  # Telegram's hard limit is 4096 characters
TOKEN_RE = re.compile(r"\d{6,12}:[A-Za-z0-9_-]{30,}")


class TelegramError(RuntimeError):
    pass


def redact(text: str, token: str = "") -> str:
    if token:
        text = text.replace(token, "[redacted]")
    return TOKEN_RE.sub("[redacted]", text)


def _http(token: str) -> Callable[[str, dict, float], dict]:
    def call(method: str, payload: dict, timeout: float) -> dict:
        req = urllib.request.Request(f"{API}/bot{token}/{method}", data=json.dumps(payload).encode(),
                                     headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            try:
                desc = json.loads(exc.read(1000).decode()).get("description", "")
            except (ValueError, OSError):
                desc = ""
            raise TelegramError(redact(f"HTTP {exc.code}: {desc or exc.reason}", token)) from None
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
            raise TelegramError(redact(f"network error: {exc}", token)) from None
    return call


def split_text(text: str, limit: int = MAX_LEN) -> list[str]:
    """Split on paragraph/line boundaries so a long briefing becomes several readable messages."""
    out, cur = [], ""
    for line in text.split("\n"):
        while len(line) > limit:
            if cur:
                out.append(cur)
                cur = ""
            out.append(line[:limit])
            line = line[limit:]
        if len(cur) + len(line) + 1 > limit:
            out.append(cur)
            cur = line
        else:
            cur = f"{cur}\n{line}" if cur else line
    if cur:
        out.append(cur)
    return out or [""]


class Telegram:
    def __init__(self, token: str, chat_id: str | int, call: Callable[[str, dict, float], dict] | None = None):
        self.token, self.chat_id = token.strip(), str(chat_id).strip()
        self._call = call or _http(self.token)

    @staticmethod
    def from_env(call=None) -> "Telegram | None":
        token, chat = os.getenv("TELEGRAM_BOT_TOKEN", "").strip(), os.getenv("TELEGRAM_CHAT_ID", "").strip()
        return Telegram(token, chat, call) if token and chat else None

    def _api(self, method: str, payload: dict, timeout: float = 20.0) -> dict:
        try:
            d = self._call(method, payload, timeout)
        except TelegramError:
            raise
        except Exception as exc:  # a custom transport must not leak the token either
            raise TelegramError(redact(f"{type(exc).__name__}: {exc}", self.token)) from None
        if not d.get("ok"):
            raise TelegramError(redact(f"API error: {d.get('description', 'unknown')}", self.token))
        return d.get("result")

    # -- sending ---------------------------------------------------------------------------
    def send(self, text: str, buttons: list[list[tuple[str, str]]] | None = None, silent: bool = False) -> int | None:
        """Send plain text. `buttons` = rows of (label, callback_data); they attach to the LAST part. Returns its message id."""
        parts = split_text(redact(text, self.token))
        mid = None
        for i, part in enumerate(parts):
            payload = {"chat_id": self.chat_id, "text": part, "disable_notification": bool(silent),
                       "disable_web_page_preview": True}
            if buttons and i == len(parts) - 1:
                payload["reply_markup"] = {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in buttons]}
            mid = (self._api("sendMessage", payload) or {}).get("message_id")
        return mid

    def clear_buttons(self, message_id: int | None) -> None:
        if message_id:
            try:
                self._api("editMessageReplyMarkup", {"chat_id": self.chat_id, "message_id": message_id,
                                                     "reply_markup": {"inline_keyboard": []}})
            except TelegramError:
                pass  # message too old / already edited: harmless

    def answer(self, callback_id: str, text: str = "") -> None:
        try:
            self._api("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:180]})
        except TelegramError:
            pass

    # -- receiving -------------------------------------------------------------------------
    def updates(self, offset: int = 0, timeout: int = 20) -> list[dict]:
        return self._api("getUpdates", {"offset": offset, "timeout": timeout,
                                        "allowed_updates": ["message", "callback_query"]}, timeout + 10) or []

    def is_owner(self, update: dict) -> bool:
        """True only for the paired chat AND the same user (private chat: chat id == user id)."""
        node = update.get("callback_query") or update.get("message") or {}
        chat = (node.get("message") or node).get("chat", {})
        sender = node.get("from", {})
        return str(chat.get("id", "")) == self.chat_id and str(sender.get("id", "")) == self.chat_id


def pair(token: str, say: Callable[[str], None] = print, call=None, wait_s: int = 180, clock=time.time) -> str | None:
    """One-time setup: the owner proves they hold the terminal by sending `/pair <code>` to the bot. Returns the chat id.

    A stranger who finds the bot username cannot hijack the pairing without the code shown only in this terminal."""
    probe = Telegram(token, "0", call)
    me = probe._api("getMe", {})
    code = f"{secrets.randbelow(10**6):06d}"
    say(f"Bot: @{me.get('username', '?')}. Open it in Telegram and send exactly:  /pair {code}   (waiting up to {wait_s}s)")
    end, offset = clock() + wait_s, 0
    while clock() < end:
        for u in probe.updates(offset, timeout=5):
            offset = u["update_id"] + 1
            m = u.get("message") or {}
            if (m.get("text") or "").strip() == f"/pair {code}" and m.get("chat", {}).get("type") == "private":
                chat = str(m["chat"]["id"])
                Telegram(token, chat, call).send("Paired. This chat is now the only one the agency will talk to.")
                return chat
    return None
