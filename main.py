#!/usr/bin/env python3
"""Autonomous AI Agency CLI.

  python main.py --web [--port 8080]         local web command center at http://127.0.0.1:8080 (localhost only)
  python main.py --ceo-autopilot [--live]    AI CEO runs the whole campaign: seed targets -> audit -> sprint -> sell sheet
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
    console.print(f"[bold]AI CEO auto-pilot[/bold] - {'[red]LIVE[/red] (cap $%.2f)' % args.max_spend if live else 'offline, $0.00'}")
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

    if (args.discover_targets or args.rotate_targets) and not args.ceo_autopilot:
        ap.error("--discover-targets / --rotate-targets only apply with --ceo-autopilot")
    if args.discover_targets and not args.live:
        ap.error("--discover-targets asks the AI for prospects, so it needs --live")
    if not (args.dashboard or args.run_all or args.project or args.log_revenue or args.ceo_autopilot):
        ap.print_help()
        return 2

    console = Console()
    settings = Settings.load()
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
