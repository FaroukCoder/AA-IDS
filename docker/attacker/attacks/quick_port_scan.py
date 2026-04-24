#!/usr/bin/env python3
"""
quick_port_scan.py — Fast SYN scan of exactly 15 unique ports.

Triggers ONLY the port_scan rule (>10 unique ports in 10 s).
15 SYN packets is safely below the failed_conn threshold (>20), so
only ONE Sentinel event fires — one investigation run.

Usage:
    python3 quick_port_scan.py [--target 172.20.0.10]
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

# 15 high-signal ports — enough to trip port_scan rule (>10), not failed_conn (>20)
TARGET_PORTS = [21, 22, 23, 25, 80, 110, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]


def main() -> None:
    parser = argparse.ArgumentParser(description="Quick 15-port SYN scan")
    parser.add_argument("--target", default="172.20.0.10")
    args = parser.parse_args()

    console.print(Panel(
        f"  [dim]Target:[/dim]  [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Ports: [/dim]  [white]{len(TARGET_PORTS)} high-signal ports[/white]  "
        f"[dim](triggers port_scan rule only)[/dim]",
        title="[bold red]🎯  QUICK PORT SCAN[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  Sending SYN to {len(TARGET_PORTS)} ports...\n")

    for port in TARGET_PORTS:
        pkt = IP(dst=args.target) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        time.sleep(0.05)

    console.print(f"  [bold green]✓  Done[/bold green]  │  {len(TARGET_PORTS)} SYN packets sent\n")


if __name__ == "__main__":
    main()
