# Unattended operation: the AI COO and Telegram (Phase 7)

`python main.py --daemon` turns the agency into something that runs on a schedule and reports to you. You make decisions with a tap; you never have to drive it.

## What runs by itself, what asks you, what never happens

- **By itself ($0):** a full auto-pilot cycle every `DAEMON_CYCLE_HOURS` (12 by default), on offline templates or on the free lane (PM-06). It cannot spend: these cycles run with a spending cap of zero.
- **Asks you first:** any cycle that could spend real money. You get a message with **Approve / No**. Approve runs it with a hard cap (`DAEMON_LIVE_CAP_USD`, $0.10). **No** is never a dead end: the same cycle runs in $0 mode. A question left unanswered for `DAEMON_PROPOSAL_TTL_HOURS` expires and is never executed late.
- **Daily ceiling:** `DAEMON_DAILY_CAP_USD` ($0.15) limits everything the daemon spends in a local day, including the COO's own briefings (at most half a cent each).
- **Never automatic:** contacting a prospect. When a cycle produces sendable messages, the COO asks "Release to me?". If you tap yes, each message is delivered to *your* chat to review and send yourself. The agency never contacts anyone and never sends email. Add your postal address and an opt-out line (CAN-SPAM, GDPR).
- **Self-protection:** after `DAEMON_MAX_FAILURES` (3) failed cycles in a row the daemon pauses itself and tells you; `/resume` restarts it. Only one daemon runs at a time, and web/CLI runs wait while a cycle is writing the state file (they get a 409 instead of corrupting it).

## One-time Telegram setup (about 3 minutes)

1. In Telegram, talk to **@BotFather**, send `/newbot`, and copy the token it gives you.
2. Add it to `.env` (never share it): `TELEGRAM_BOT_TOKEN=...`
3. Run `python main.py --telegram-setup`. It prints a code like `/pair 123456`. Send exactly that to your new bot. The code is shown only in your terminal, so a stranger who finds the bot cannot take it over.
4. Add the line it prints to `.env`: `TELEGRAM_CHAT_ID=...`
5. Check it: `python main.py --briefing --send`

Only that chat can command the bot. Messages from anyone else are ignored without a reply. The agency talks to Telegram by long polling, so nothing listens on your phone.

## Run it on Termux

```bash
cd APKReLab && git pull
termux-wake-lock                       # keep the CPU awake while the screen is off
nohup python main.py --daemon > daemon.log 2>&1 &
tail -f daemon.log
```

Stop it with `pkill -f "main.py --daemon"` or ask from Telegram with `/pause`. Android may still kill background apps: in the phone's battery settings exclude Termux from optimisation. To start it after a reboot install Termux:Boot and put the same commands in `~/.termux/boot/agency.sh`.

## Telegram commands

- `/status` quick facts, `/report` full briefing with the COO's analysis, `/decisions` what waits for you
- `/run` run a cycle now ($0 ones start immediately, paid ones ask), `/pause`, `/resume`
- `/sent N` and `/replies N` tell the COO how your outreach is going, so the briefing can show a real reply rate and warn when 20+ messages brought no replies
- `/revenue PRJ-02 39 Gumroad sale` logs *verified* revenue after you confirm; the first Group A revenue unlocks the reserve vault

## How the briefing is built (so you can trust it)

The numbers (budget, spend today, pipeline, funnel, project status) are computed from the state file and printed as they are. A model never touches them. Below them, the **COO analysis** (assessment, main risk, recommendation) is written by a model when one is available within the caps, otherwise by plain rules; it is labelled, length-capped and stripped of links, and it cannot start anything: decisions come only from fixed rules in the daemon. Company names and findings come from scraped websites, so they are sanitised before they reach a prompt and are sent as plain text (never markup).

## Settings

`DAEMON_CYCLE_HOURS`, `DAEMON_QUIET_HOURS` (default `23-8`: notifications arrive silently), `DAEMON_DAILY_CAP_USD`, `DAEMON_LIVE_CAP_USD`, `DAEMON_MAX_FAILURES`, `DAEMON_PROPOSAL_TTL_HOURS`, `DAEMON_REJECT_COOLDOWN_HOURS`.

## Privacy

Telegram bot chats are not end-to-end encrypted. Briefings contain business facts (company names, counts, spend) but never API keys or the bot token (both are redacted from every message and log). If you use a free-tier model for the analysis, the facts in the briefing go to that provider as well (see `docs/FREE_TIERS.md`).

## Limits

Automation keeps the machine running; it does not create customers. Reply and revenue numbers only exist if you report them (`/sent`, `/replies`, `/revenue`). The daemon cannot outlive a phone that is switched off or an OS that kills Termux.
