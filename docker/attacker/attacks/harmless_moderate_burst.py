#!/usr/bin/env python3
"""
harmless_moderate_burst.py — Harmless: 60 HTTP GETs over 30s, below spike threshold.

Sentinel's traffic_spike rule requires >100 packets in 10s.
60 requests over 30s peaks at ~20/10s window — well below threshold.
No detection fires. Normal elevated-but-not-suspicious web traffic.

Usage:
    python3 harmless_moderate_burst.py [--target http://172.20.0.10/] [--count 60]
"""
from __future__ import annotations

import argparse
import random
import time

import requests  # type: ignore[import]
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/119.0.0.0 Safari/537.36",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Moderate HTTP burst (below spike threshold)")
    parser.add_argument("--target", default="http://172.20.0.10/")
    parser.add_argument("--count",  type=int, default=60)
    args = parser.parse_args()

    duration = 30
    interval = duration / args.count

    console.print(Panel(
        f"  [dim]Target:   [/dim]  [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Requests: [/dim]  [white]{args.count} GETs over {duration}s[/white]  [dim](~{args.count // 10}/10s peak — threshold is 100/10s)[/dim]\n"
        f"  [dim]Expected: [/dim]  [bold green]NO DETECTION[/bold green]  [dim](well below traffic_spike threshold)[/dim]",
        title="[bold yellow]🟡  HARMLESS ALARM: MODERATE HTTP BURST[/bold yellow]",
        border_style="yellow",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  [bold][[STEP 1/2][/bold]  Starting moderate burst  [dim]({args.count} req / {duration}s)[/dim]...")
    console.print(f"  [bold][[STEP 2/2][/bold]  Sending requests...")

    for i in range(args.count):
        try:
            headers = {"User-Agent": random.choice(_USER_AGENTS)}
            requests.get(args.target, headers=headers, timeout=2)
        except Exception:
            pass
        if (i + 1) % 15 == 0:
            pct = int((i + 1) / args.count * 100)
            console.print(f"    [dim]→[/dim]  {i + 1}/{args.count} requests  [dim]({pct}%)[/dim]")
        time.sleep(interval)

    console.print(f"\n  [bold green]✓  Done[/bold green]  │  {args.count} requests sent  │  Expected: [bold green]NO detection fired[/bold green]  [dim](peak ~{args.count // 10}/10s, threshold 100)[/dim]\n")


if __name__ == "__main__":
    main()
