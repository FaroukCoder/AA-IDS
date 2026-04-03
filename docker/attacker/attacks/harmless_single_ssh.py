#!/usr/bin/env python3
"""
harmless_single_ssh.py — Harmless: single SSH SYN packet, no rule fires.

Sentinel's failed_conn rule requires >20 failed attempts in 30s.
Sentinel's port_scan rule requires >10 unique ports in 10s.
A single SYN to port 22 satisfies neither — the system correctly ignores it.

Usage:
    python3 harmless_single_ssh.py [--target 172.20.0.10]
"""
from __future__ import annotations

import argparse

from rich.console import Console
from rich.panel import Panel
from rich import box
from scapy.all import IP, TCP, conf, send  # type: ignore[import]

conf.verb = 0
console = Console()


def main() -> None:
    parser = argparse.ArgumentParser(description="Single SSH SYN (no detection fires)")
    parser.add_argument("--target", default="172.20.0.10")
    args = parser.parse_args()

    console.print(Panel(
        f"  [dim]Target:      [/dim]  [bold cyan]{args.target}:22[/bold cyan]\n"
        f"  [dim]Packets:     [/dim]  [white]1 SYN packet[/white]  [dim](far below >20/30s threshold)[/dim]\n"
        f"  [dim]Expected:    [/dim]  [bold green]NO DETECTION[/bold green]  [dim](single packet, system correctly ignores)[/dim]",
        title="[bold yellow]🟡  HARMLESS ALARM: SINGLE SSH ATTEMPT[/bold yellow]",
        border_style="yellow",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  [bold][[STEP 1/1][/bold]  Sending 1 SYN to [cyan]{args.target}:22[/cyan]...  ", end="")
    pkt = IP(dst=args.target) / TCP(dport=22, flags="S")
    send(pkt, verbose=0)
    console.print("[bold green]✓[/bold green]")

    console.print(f"\n  [bold green]✓  Done[/bold green]  │  1 packet sent  │  Expected: [bold green]NO detection fired[/bold green]  [dim](1 packet, all thresholds above 20)[/dim]\n")


if __name__ == "__main__":
    main()
