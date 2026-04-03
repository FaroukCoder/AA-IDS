#!/usr/bin/env python3
"""
harmless_slow_scan.py — Harmless alarm: barely triggers port_scan, low confidence.

Sends SYN to exactly 12 web-only ports in ~8s — just above the >10 unique
ports in 10s threshold. Spoofed from a Yahoo CDN IP with clean reputation.
LLM should return MONITOR or ALERT_ADMIN (not ESCALATE_HUMAN).

Usage:
    python3 harmless_slow_scan.py [--target 172.20.0.10]
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

_SPOOF_IP = "67.193.197.75"  # Yahoo/Oath CDN — clean reputation, known organization
# 12 web/API ports only — no credential-access ports (SSH/SMB/RDP)
_PORTS = [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9000, 9090, 9200, 9300]


def main() -> None:
    parser = argparse.ArgumentParser(description="Harmless slow scan (low confidence detection)")
    parser.add_argument("--target", default="172.20.0.10")
    args = parser.parse_args()

    total    = len(_PORTS)
    interval = 8.0 / total  # spread across 8s — all within 10s window

    console.print(Panel(
        f"  [dim]Spoofed src: [/dim]  [bold yellow]{_SPOOF_IP}[/bold yellow]  [dim](Yahoo/Oath CDN — clean reputation)[/dim]\n"
        f"  [dim]Target:      [/dim]  [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Ports:       [/dim]  [white]{total} web ports in ~8s[/white]  [dim](just above >10/10s threshold)[/dim]\n"
        f"  [dim]Expected:    [/dim]  [bold yellow]MONITOR / ALERT_ADMIN[/bold yellow]  [dim](fires but low confidence)[/dim]",
        title="[bold yellow]🟡  HARMLESS ALARM: SLOW SCAN[/bold yellow]",
        border_style="yellow",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  [bold][[STEP 1/2][/bold]  Spoofing [yellow]{_SPOOF_IP}[/yellow] (Yahoo CDN)...")
    console.print(f"  [bold][[STEP 2/2][/bold]  Scanning {total} ports over ~8s...")

    for i, port in enumerate(_PORTS):
        pkt = IP(src=_SPOOF_IP, dst=args.target) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        console.print(f"    [dim]→[/dim]  port [cyan]{port}[/cyan]  [{i + 1}/{total}]")
        time.sleep(interval)

    console.print(f"\n  [bold green]✓  Done[/bold green]  │  {total} ports scanned  │  Expected: [bold yellow]MONITOR or ALERT_ADMIN[/bold yellow]\n")


if __name__ == "__main__":
    main()
