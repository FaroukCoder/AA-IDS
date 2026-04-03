#!/usr/bin/env python3
"""
benign_slow_touch.py — True false alarm: touches 5 ports so slowly no rule fires.

Sentinel's port_scan rule requires >10 unique ports in 10s.
This script touches only 5 ports at 1 per 15s — far below the threshold.
No detection event is ever raised. The system correctly ignores this traffic.

Usage:
    python3 benign_slow_touch.py [--target 172.20.0.10]
"""
from __future__ import annotations

import argparse
import time

from rich.console import Console
from rich.panel import Panel
from rich import box
from scapy.all import IP, TCP, conf, send  # type: ignore[import]

conf.verb = 0
console = Console()

_PORTS    = [80, 443, 22, 8080, 3306]
_INTERVAL = 15  # seconds between each port — keeps total below >10/10s threshold


def main() -> None:
    parser = argparse.ArgumentParser(description="Benign slow port touch (no detection fires)")
    parser.add_argument("--target", default="172.20.0.10")
    args = parser.parse_args()

    total    = len(_PORTS)
    duration = total * _INTERVAL

    console.print(Panel(
        f"  [dim]Target:   [/dim]  [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Ports:    [/dim]  [white]{total} ports[/white]  [dim](1 every {_INTERVAL}s — below >10/10s threshold)[/dim]\n"
        f"  [dim]Duration: [/dim]  [white]~{duration}s total[/white]\n"
        f"  [dim]Expected: [/dim]  [bold green]NO DETECTION[/bold green]  [dim](system correctly ignores this)[/dim]",
        title="[bold green]🟢  FALSE ALARM: SLOW PORT TOUCH[/bold green]",
        border_style="green",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print()
    for i, port in enumerate(_PORTS):
        console.print(
            f"  [bold][[STEP {i + 1}/{total}][/bold]  Touching port [cyan]{port}[/cyan]...  ",
            end="",
        )
        pkt = IP(dst=args.target) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        console.print("[bold green]✓[/bold green]")
        if i < total - 1:
            console.print(f"    [dim](waiting {_INTERVAL}s before next port...)[/dim]")
            time.sleep(_INTERVAL)

    console.print(f"\n  [bold green]✓  Done[/bold green]  │  {total} ports touched  │  Expected: [bold green]NO detection fired[/bold green]\n")


if __name__ == "__main__":
    main()
