#!/usr/bin/env python3
"""
quick_http_flood.py — HTTP keep-alive flood, 115 requests over ONE TCP connection.

Triggers ONLY the traffic_spike rule (>100 requests in 10 s).
Using HTTP/1.1 keep-alive means only ONE TCP SYN is sent for all 115 requests,
so the failed_conn rule (>20 SYN/RST packets) never fires. ONE Sentinel event — one run.

Usage:
    python3 quick_http_flood.py [--target 172.20.0.10] [--port 80]
"""
from __future__ import annotations

import argparse
import http.client
import time

from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

COUNT = 115  # > 100 threshold, single TCP connection


def main() -> None:
    parser = argparse.ArgumentParser(description="Quick HTTP keep-alive flood")
    parser.add_argument("--target", default="172.20.0.10")
    parser.add_argument("--port",   type=int, default=80)
    args = parser.parse_args()

    console.print(Panel(
        f"  [dim]Target:  [/dim]  [bold cyan]{args.target}:{args.port}[/bold cyan]\n"
        f"  [dim]Requests:[/dim]  [white]{COUNT} over one persistent connection[/white]  "
        f"[dim](triggers traffic_spike rule only)[/dim]",
        title="[bold red]🌊  QUICK HTTP FLOOD[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  Opening keep-alive connection → {args.target}:{args.port}...\n")

    start = time.time()
    sent = 0
    try:
        conn = http.client.HTTPConnection(args.target, args.port, timeout=5)
        conn.connect()
        for i in range(COUNT):
            try:
                conn.request("GET", "/", headers={"Connection": "keep-alive"})
                resp = conn.getresponse()
                resp.read()
                sent += 1
                if sent % 25 == 0:
                    console.print(f"  [dim]→[/dim]  {sent}/{COUNT}")
            except Exception:
                # If server closed connection, reopen
                conn.close()
                conn = http.client.HTTPConnection(args.target, args.port, timeout=5)
                conn.connect()
        conn.close()
    except Exception as exc:
        console.print(f"  [yellow]Connection error: {exc}[/yellow]")

    elapsed = time.time() - start
    console.print(
        f"\n  [bold green]✓  Done[/bold green]  │  {sent} requests  │  {elapsed:.1f}s\n"
    )


if __name__ == "__main__":
    main()
