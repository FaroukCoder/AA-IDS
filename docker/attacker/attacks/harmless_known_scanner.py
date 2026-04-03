#!/usr/bin/env python3
"""
harmless_known_scanner.py — Harmless alarm: port scan spoofed from Shodan scanner IP.

Triggers Sentinel's port_scan rule but the LLM should classify as MONITOR
(not ESCALATE_HUMAN): 66.240.192.138 is Shodan's well-known scanning
infrastructure — a legitimate internet security scanner, not a criminal actor.

Usage:
    python3 harmless_known_scanner.py [--target 172.20.0.10]
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

_SHODAN_IP = "66.240.192.138"  # Shodan scanning infrastructure
_PORTS = [21, 22, 23, 25, 80, 110, 143, 443, 993, 3306, 3389, 5432, 6379, 8080, 8443]


def main() -> None:
    parser = argparse.ArgumentParser(description="Known scanner (Shodan) port scan")
    parser.add_argument("--target", default="172.20.0.10")
    args = parser.parse_args()

    total = len(_PORTS)

    console.print(Panel(
        f"  [dim]Spoofed src: [/dim]  [bold yellow]{_SHODAN_IP}[/bold yellow]  [dim](Shodan.io scanner — legitimate internet security tool)[/dim]\n"
        f"  [dim]Target:      [/dim]  [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Ports:       [/dim]  [white]{total} ports[/white]  [dim](typical Shodan probe set)[/dim]\n"
        f"  [dim]Expected:    [/dim]  [bold yellow]MONITOR[/bold yellow]  [dim](port_scan fires — but Shodan is known benign scanner)[/dim]",
        title="[bold yellow]🟡  HARMLESS ALARM: KNOWN SCANNER[/bold yellow]",
        border_style="yellow",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  [bold][[STEP 1/2][/bold]  Spoofing [yellow]{_SHODAN_IP}[/yellow] (Shodan.io)...")
    console.print(f"  [bold][[STEP 2/2][/bold]  Scanning {total} ports...")

    for i, port in enumerate(_PORTS):
        pkt = IP(src=_SHODAN_IP, dst=args.target) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        if (i + 1) % 5 == 0:
            console.print(f"    [dim]→[/dim]  {i + 1}/{total} ports sent")
        time.sleep(0.3)

    console.print(f"\n  [bold green]✓  Done[/bold green]  │  {total} ports scanned  │  Expected: [bold yellow]MONITOR[/bold yellow]  [dim](known scanner, not criminal)[/dim]\n")


if __name__ == "__main__":
    main()
