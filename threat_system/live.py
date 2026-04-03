"""
live.py — Live mode: watches logs/live_traffic.jsonl in real time while
Docker attack containers run.  Starts its own HTTP + WebSocket servers
(same ports as server.py) so the browser visualizer works without a
separate terminal.

Usage:
    py -m threat_system.live
    py -m threat_system.live --policy strict_policy.json
    py -m threat_system.live --active

Open http://localhost:8765 in a browser to watch events arrive live.
Run attacks with:  python docker/run_attack.py --attack all
Stop with Ctrl-C.
"""
from __future__ import annotations

import argparse
import os

from rich.console import Console

console = Console()


def main() -> None:
    parser = argparse.ArgumentParser(description="AA-IDS live traffic watcher")
    parser.add_argument("--policy", default="default_policy.json",
                        help="Policy file name (default: default_policy.json)")
    parser.add_argument("--active", action="store_true",
                        help="Enable active enforcement mode")
    args = parser.parse_args()

    from .config.settings import settings
    settings.validate()

    from .visualizer import ws_server
    from .visualizer.ws_server import start_server, broadcast
    from .visualizer import narrator as narr
    from .framework.pipeline import ThreatPipeline
    from .framework.sentinel import Sentinel
    from .main import _make_live_stage_handler, _run_pipeline_for_web

    # Start HTTP (8765) + WebSocket (8766) servers in background threads
    start_server()
    ws_server.register_run_handler(_run_pipeline_for_web)

    console.print("[cyan]AA-IDS live mode started.[/cyan]")
    console.print("[green]  Browser  -> http://localhost:8765[/green]")
    console.print("[green]  WebSocket -> ws://localhost:8766[/green]")
    console.print("[green]  Watching -> logs/live_traffic.jsonl[/green]")
    console.print("[dim]  Ctrl-C to stop.\n[/dim]")

    log_path = os.path.join(os.path.dirname(__file__), "logs", "live_traffic.jsonl")
    on_stage = _make_live_stage_handler(broadcast, narr)

    pipeline = ThreatPipeline(
        policy_file=args.policy,
        active_mode=args.active,
        on_stage_complete=on_stage,
    )

    def on_event(event) -> None:
        console.rule(f"[bold cyan]Event: {event.event_id}[/bold cyan] — {event.src_ip}")
        ws_server.run_started(event.event_id)
        action = pipeline.run_event(event)
        ws_server.run_complete({
            "event_id":       event.event_id,
            "target":         event.src_ip,
            "final_action":   action.final_action,
            "classification": action.policy_decision,
            "confidence":     ws_server._current_confidence,
        })
        console.print(f"[bold]Action:[/bold] {action.final_action}\n")

    # Blocks until Ctrl-C; processes events one at a time (same pattern as
    # run_pipeline()).  The 60 s per-(ip,rule) cooldown in watch() prevents
    # duplicate events from queuing while the pipeline processes a prior one.
    Sentinel().watch(log_path, on_event)


if __name__ == "__main__":
    main()
