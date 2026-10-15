#!/usr/bin/env python3
"""Autonomous AI Agency CLI.

  python main.py --web [--port 8080]         local web command center at http://127.0.0.1:8080 (localhost only)
  python main.py --ceo-autopilot [--live]    AI CEO runs the whole campaign: seed targets -> audit -> sprint -> sell sheet
  python main.py --daemon [--every 12]       AI COO: unattended cycles + Telegram briefings/approvals (see docs/AUTOPILOT.md)
  python main.py --dashboard                 render the executive table from persisted state
  python main.py --run-all [--live]          sprint across all 5 projects (PM -> CFO -> CEO)
                                             --live enables PAID LLM calls (key from .env); default is free/offline
  python main.py --project PRJ-01            run one project; artifacts land in output/PRJ-01/
  python main.py --log-revenue PRJ-01 --amount 250   record real revenue (unlocks Group B reinvestment)
"""
from __future__ import annotations

import argparse
import sys

from dataclasses import replace

from rich.console import Console

from config import Settings
from orchestrator import Orchestrator


def report_llm_usage(console: Console, entries: list[dict]) -> None:
    """Make live-call outcomes explicit so a silent fallback to offline output is never mistaken for a live run."""
    api = [e for e in entries if e["kind"] == "api" and e.get("provider") not in ("offline",)]
    cached = [e for e in entries if e["kind"] == "cache_hit"]
    blocked = [e for e in entries if e["kind"] == "blocked"]
    errors = [e for e in entries if e.get("error")]
    if not (api or cached or blocked or errors):
        return
    spent = sum(e.get("usd", 0.0) for e in entries if e["kind"] == "api")
    console.print(f"[bold]LLM calls this run:[/bold] {len(api)} live (${spent:.5f}), {len(cached)} cache hits ($0), "
                  f"{len(blocked)} blocked by breaker, {len(errors)} provider errors")
    for e in errors[:3]:
        console.print(f"  [red]error[/red] {e['project']}: {e['error']}")
    for e in blocked[:3]:
        console.print(f"  [yellow]blocked[/yellow] {e['project']}: {e.get('reason', '')}")


def run_autopilot_cli(console: Console, orch: Orchestrator, args) -> int:
    live = orch.s.provider != "offline"
    if args.live and not live:
        console.print("[yellow]--live requested but no API key found in .env - running the offline chain.[/yellow]")
    mode = ("[green]FREE LANE[/green] ($0.00)" if orch.s.provider == "free" else "[red]LIVE[/red] (cap $%.2f)" % args.max_spend) if live else "offline, $0.00"
    console.print(f"[bold]AI CEO auto-pilot[/bold] - {mode}")
    icon = {"done": "[green]✓[/green]", "failed": "[red]✗[/red]", "running": "…"}
    printed = {"n": 0}

    def on_step(steps):  # print each step once, when it finishes
        while printed["n"] < len(steps) and steps[printed["n"]]["status"] != "running":
            s = steps[printed["n"]]
            console.print(f"  {icon[s['status']]} {s['label']} - {s['detail']}")
            printed["n"] += 1
    result = orch.run_autopilot(live=live, discover=args.discover_targets and live, rotate=args.rotate_targets, on_step=on_step)
    orch.ceo.render_dashboard(console)
    l = result["llm"]
    console.print(f"[bold]LLM:[/bold] {l['live_calls']} live (${l['spent_usd']:.5f}), {l['cache_hits']} cached, "
                  f"{l['blocked']} blocked, {l['errors']} errors")
    if result["status"] == "complete":
        console.print(f"[green]Auto-pilot complete. Sell sheet: {result['sell_sheet']}[/green]")
        return 0
    console.print(f"[red]Auto-pilot finished with failed steps: {', '.join(result['failed_steps'])}[/red]")
    return 1


def run_ops_cli(console: Console, settings: Settings, args) -> int:
    import os
    from ops.daemon import Daemon
    from ops.telegram import Telegram, TelegramError, pair
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    if args.telegram_setup:
        if not token:
            console.print("Create a bot with @BotFather in Telegram, then add  TELEGRAM_BOT_TOKEN=...  to .env and rerun.")
            return 2
        try:
            chat = pair(token, say=console.print)
        except TelegramError as exc:
            console.print(f"[red]Telegram error: {exc}[/red]")
            return 1
        if not chat:
            console.print("[yellow]Timed out waiting for the pairing message. Run --telegram-setup again.[/yellow]")
            return 1
        console.print(f"[green]Paired.[/green] Add this line to .env:  TELEGRAM_CHAT_ID={chat}")
        return 0
    if args.every:
        settings = replace(settings, daemon_cycle_hours=args.every)
    tg = Telegram.from_env()
    if bool(token) != bool(os.getenv("TELEGRAM_CHAT_ID", "").strip()):
        console.print("[yellow]Telegram needs BOTH TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID (run --telegram-setup). Continuing without it.[/yellow]")
    d = Daemon(settings, tg, log=console.print)
    if args.briefing:
        text = d.briefing(analysis=True, title="Briefing", send=False)
        console.print(text, markup=False, highlight=False)
        if args.send:
            if not tg:
                console.print("[yellow]No Telegram configured; nothing sent.[/yellow]")
                return 1
            d.send(text, interactive=True)
        return 0
    if not tg:
        console.print("[yellow]No Telegram configured: only $0 cycles will run (paid cycles need your approval there).[/yellow]")
    if args.once:
        d.tick(poll=0)
        return 0
    console.print(f"[bold]AI COO daemon[/bold] - cycle every {settings.daemon_cycle_hours:g}h, daily cap ${settings.daemon_daily_cap_usd:.2f}. Ctrl+C to stop.")
    return d.run_forever()


def run_growth_cli(console: Console, orch: Orchestrator, args) -> int:
    from rich.table import Table
    g = orch.growth
    pol = g.assess()
    if args.growth:
        r = g.cost_report()
        style = {"normal": "green", "conserve": "yellow", "free": "cyan"}[pol["mode"]]
        console.print(f"[bold]PM-06 policy:[/bold] [{style}]{pol['mode'].upper()}[/{style}] - {pol['reason']}")
        console.print(f"Budget: ${r['remaining_usd']:.2f} left of ${r['seed_usd']:.2f} ({r['remaining_pct']}%) | paid calls {r['paid_calls']}"
                      f" | avg ${r['avg_cost_per_call_usd']:.5f}/call"
                      + (f" | runway ~{r['runway_calls']} calls" if r["runway_calls"] is not None else "")
                      + (f" | burn ${r['burn_usd_per_hour']:.4f}/h (~{r['runway_hours']} h)" if r["runway_hours"] else ""))
        t = Table("Project", "Tokens", "Spent", "Free calls", "")
        for x in r["by_project"]:
            t.add_row(f"{x['project']} {x['name']}", str(x["tokens"]), f"${x['spent_usd']:.6f}", str(x["free_calls"]), "heavy" if x["heavy"] else "")
        console.print(t)
        if r["by_model"]:
            m = Table("Model", "Calls", "Tokens in/out", "Cost")
            for x in r["by_model"]:
                m.add_row(x["model"], str(x["calls"]), f"{x['tokens_in']}/{x['tokens_out']}", f"${x['usd']:.6f}")
            console.print(m)
        f = r["free"]
        console.print(f"Free lane so far: {f['requests']} requests, {f['tokens']} tokens, ~${f['avoided_usd']:.4f} of paid cost avoided")
    if args.free_tiers:
        t = Table("Provider", "Key", "Model", "Today (req/limit)", "Data use", "Register by hand")
        for p in g.providers():
            state = "ACTIVE" if p["active"] else ("off" if p["configured"] else "no key")
            t.add_row(p["label"], state, p["model"] or "-", f"{p['requests_today']}/{p['rpd'] or '-'}", p["data_note"] or "-", p["signup_url"])
        console.print(t)
        console.print("Guide (official links, limits, data-use caveats): docs/FREE_TIERS.md - accounts must be created by you, one per person; "
                      "PM-06 never signs up for anything.")
        if args.check:
            res = g.probe([n for n in g.free_lane()])
            if not res:
                console.print("[yellow]No free provider is configured yet - add a key to .env first (see the guide).[/yellow]")
            for x in res:
                console.print(f"  {'[green]OK[/green]' if x['ok'] else '[red]FAILED[/red]'} {x['name']}: {x['detail']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Autonomous AI Agency & Master Orchestrator")
    ap.add_argument("--web", action="store_true", help="start the local web command center (127.0.0.1 only)")
    ap.add_argument("--port", type=int, default=8080, help="port for --web (default 8080)")
    ap.add_argument("--dashboard", action="store_true", help="render the live Executive Dashboard")
    ap.add_argument("--run-all", action="store_true", help="run a sprint across all 5 projects")
    ap.add_argument("--project", metavar="PRJ-0X", help="run a single project")
    ap.add_argument("--ceo-autopilot", action="store_true",
                    help="AI CEO runs the full chain (target dispatch, PRJ-03 audit, PRJ-01/02 sprint, sell sheet); "
                         "add --live for paid LLM drafts (default cap $0.10)")
    ap.add_argument("--discover-targets", action="store_true", help="with --ceo-autopilot --live: let the AI suggest extra prospects")
    ap.add_argument("--rotate-targets", action="store_true", help="with --ceo-autopilot: load the next batch even if targets.csv has un-audited rows")
    ap.add_argument("--growth", action="store_true", help="PM-06 cost report: spend per model/project, runway, routing policy")
    ap.add_argument("--free-tiers", action="store_true",
                    help="PM-06: show which free-tier providers are configured (and how to register by hand: docs/FREE_TIERS.md)")
    ap.add_argument("--check", action="store_true", help="with --free-tiers: send one tiny request to each configured provider")
    ap.add_argument("--daemon", action="store_true",
                    help="AI COO: run cycles on a schedule and report to Telegram; paid cycles wait for your approval")
    ap.add_argument("--once", action="store_true", help="with --daemon: one pass (poll Telegram, run a cycle if due), then exit")
    ap.add_argument("--every", type=float, metavar="HOURS", help="with --daemon: hours between cycles (default DAEMON_CYCLE_HOURS=12)")
    ap.add_argument("--telegram-setup", action="store_true", help="pair this agency with your Telegram chat (needs TELEGRAM_BOT_TOKEN)")
    ap.add_argument("--briefing", action="store_true", help="print the COO briefing now (add --send to also deliver it to Telegram)")
    ap.add_argument("--send", action="store_true", help="with --briefing: deliver it to Telegram")
    ap.add_argument("--live", action="store_true",
                    help="enable paid LLM calls using the key in .env (default: offline deterministic, $0)")
    ap.add_argument("--watch", action="store_true", help="live-refresh the dashboard while running")
    ap.add_argument("--max-spend", type=float, metavar="USD",
                    help="hard cap on what THIS run may spend (on top of the seed cap)")
    ap.add_argument("--sequential", action="store_true", help="disable parallel execution")
    ap.add_argument("--log-revenue", metavar="PRJ-0X", help="log revenue for a project")
    ap.add_argument("--amount", type=float, help="revenue amount in USD (with --log-revenue)")
    ap.add_argument("--reset", action="store_true", help="reset persisted state before running")
    args = ap.parse_args(argv)

    if args.web:
        if not 1024 <= args.port <= 65535:
            ap.error("--port must be between 1024 and 65535")
        try:
            from web_dashboard import serve
        except ImportError as exc:
            ap.error(f"--web needs FastAPI and uvicorn: pip install fastapi uvicorn ({exc})")
        return serve(args.port)

    if (args.once or args.every) and not args.daemon:
        ap.error("--once / --every only apply with --daemon")
    if args.send and not args.briefing:
        ap.error("--send only applies with --briefing")
    if args.check and not args.free_tiers:
        ap.error("--check only applies with --free-tiers")
    if (args.discover_targets or args.rotate_targets) and not args.ceo_autopilot:
        ap.error("--discover-targets / --rotate-targets only apply with --ceo-autopilot")
    if args.discover_targets and not args.live:
        ap.error("--discover-targets asks the AI for prospects, so it needs --live")
    if not (args.dashboard or args.run_all or args.project or args.log_revenue or args.ceo_autopilot or args.growth or args.free_tiers
            or args.daemon or args.telegram_setup or args.briefing):
        ap.print_help()
        return 2

    console = Console()
    settings = Settings.load()
    if args.telegram_setup or args.daemon or args.briefing:
        return run_ops_cli(console, settings, args)
    if args.growth or args.free_tiers:  # read-mostly PM-06 views: never run a sprint, never spend
        return run_growth_cli(console, Orchestrator(settings), args)
    if not args.live:
        settings = replace(settings, provider="offline")  # never spend without an explicit --live
    orch = Orchestrator(settings)
    if args.ceo_autopilot and args.live and args.max_spend is None:
        args.max_spend = 0.10  # a paid autonomous chain is never uncapped
    if args.reset:
        orch.state.path.unlink(missing_ok=True)
        orch = Orchestrator(settings)
    if args.max_spend is not None:
        orch.cfo.set_run_cap(args.max_spend)
    ledger_start = len(orch.state.snapshot()["ledger"])

    if args.ceo_autopilot:
        return run_autopilot_cli(console, orch, args)

    if args.log_revenue:
        if args.amount is None:
            ap.error("--log-revenue requires --amount")
        try:
            orch.cfo.log_revenue(args.log_revenue.upper(), args.amount)
        except ValueError as exc:
            ap.error(str(exc))
        console.print(f"[green]Logged ${args.amount:.2f} for {args.log_revenue.upper()}[/green]; "
                      f"reinvested into Group B so far: ${orch.state.snapshot()['reinvested_usd']:.4f}")

    run_ids = None
    if args.run_all:
        run_ids = orch.ceo.dispatch_plan()
    elif args.project:
        run_ids = [args.project.upper()]

    if run_ids:
        if orch.s.provider == "offline":
            console.print("[bold]LLM:[/bold] offline deterministic engines ($0)"
                          + ("  [yellow]--live requested but no API key found in .env[/yellow]" if args.live else
                             "  (pass --live to enable paid calls)"))
        elif orch.s.provider == "free":
            console.print(f"[bold]LLM:[/bold] [green]FREE LANE[/green] {', '.join(orch.growth.free_lane()) or 'none'} ($0.00)")
        else:
            console.print(f"[bold]LLM:[/bold] [red]LIVE[/red] {orch.s.provider}  "
                          f"tier1={orch.pms['PRJ-01'].llm.model_for(orch.s.provider, 1)} "
                          f"tier2={orch.pms['PRJ-01'].llm.model_for(orch.s.provider, 2)}"
                          + (f"  run cap ${args.max_spend:.2f}" if args.max_spend is not None else ""))
        try:
            if args.watch:
                with orch.ceo.live(console):
                    orch.run_sprint(run_ids, parallel=not args.sequential)
            else:
                orch.run_sprint(run_ids, parallel=not args.sequential)
        except ValueError as exc:
            ap.error(str(exc))
        orch.ceo.render_dashboard(console)
        report_llm_usage(console, orch.state.snapshot()["ledger"][ledger_start:])
    elif args.dashboard:
        orch.ceo.render_dashboard(console)

    snap = orch.state.snapshot()
    if run_ids:
        bad = [p for p in run_ids if snap["projects"][p]["ceo_status"] != "APPROVED"]
        if bad:
            console.print(f"[red]Not approved: {', '.join(bad)}[/red]")
            return 1
        console.print(f"[green]All requested projects approved. Artifacts: {orch.s.output_dir}[/green]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
