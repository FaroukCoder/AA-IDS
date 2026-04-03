"""
server.py — Standalone operations server for AA-IDS.

Starts the HTTP + WebSocket servers and waits forever.
The browser at http://localhost:8765 becomes the permanent operations terminal.

Usage
-----
    py -m threat_system.server

Then open http://localhost:8765 and leave it open. Use the browser controls
to trigger runs, investigate IPs, or run the evaluation — no CLI needed.
"""
from __future__ import annotations

import threading

from rich.console import Console

console = Console()


def main() -> None:
    from .config.settings import settings
    settings.validate()

    from .visualizer.ws_server import start_server, register_run_handler
    from .main import _run_pipeline_for_web

    start_server()
    register_run_handler(_run_pipeline_for_web)

    console.print("[cyan]AA-IDS operations server running.[/cyan]")
    console.print("[green]  Browser -> http://localhost:8765[/green]")
    console.print("[dim]  Ctrl-C to stop.[/dim]\n")

    # Block the main thread forever — servers run as daemon threads,
    # so we need to keep the process alive.
    threading.Event().wait()


if __name__ == "__main__":
    main()
