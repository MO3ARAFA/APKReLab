#!/usr/bin/env python3
"""Autonomous AI Agency CLI.

  python main.py --dashboard                 render the executive table from persisted state
  python main.py --run-all [--live]          sprint across all 5 projects (PM -> CFO -> CEO)
  python main.py --project PRJ-01            run one project; artifacts land in output/PRJ-01/
  python main.py --log-revenue PRJ-01 --amount 250   record real revenue (unlocks Group B reinvestment)
"""
from __future__ import annotations

import argparse
import sys

from rich.console import Console

from orchestrator import Orchestrator


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Autonomous AI Agency & Master Orchestrator")
    ap.add_argument("--dashboard", action="store_true", help="render the live Executive Dashboard")
    ap.add_argument("--run-all", action="store_true", help="run a sprint across all 5 projects")
    ap.add_argument("--project", metavar="PRJ-0X", help="run a single project")
    ap.add_argument("--live", action="store_true", help="live-refresh the dashboard while running")
    ap.add_argument("--sequential", action="store_true", help="disable parallel execution")
    ap.add_argument("--log-revenue", metavar="PRJ-0X", help="log revenue for a project")
    ap.add_argument("--amount", type=float, help="revenue amount in USD (with --log-revenue)")
    ap.add_argument("--reset", action="store_true", help="reset persisted state before running")
    args = ap.parse_args(argv)

    if not (args.dashboard or args.run_all or args.project or args.log_revenue):
        ap.print_help()
        return 2

    console = Console()
    orch = Orchestrator()
    if args.reset:
        orch.state.path.unlink(missing_ok=True)
        orch = Orchestrator()

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
        console.print(f"[bold]LLM provider:[/bold] {orch.s.provider}"
                      + ("  (offline deterministic engines; set API_KEY in .env for LLM enrichment)"
                         if orch.s.provider == "offline" else ""))
        try:
            if args.live or args.dashboard:
                with orch.ceo.live(console):
                    orch.run_sprint(run_ids, parallel=not args.sequential)
            else:
                orch.run_sprint(run_ids, parallel=not args.sequential)
        except ValueError as exc:
            ap.error(str(exc))
        if not (args.live or args.dashboard):
            orch.ceo.render_dashboard(console)
        elif args.live:
            orch.ceo.render_dashboard(console)
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
