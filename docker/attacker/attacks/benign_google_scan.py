#!/usr/bin/env python3
"""
benign_google_scan.py — False alarm: port scan spoofed from 8.8.8.8 (Google DNS).

Triggers Sentinel's port_scan rule (>10 unique ports in 10s) but the LLM
should classify LOG_ONLY: Google LLC IP, zero abuse history, web-only ports.

Usage:
    python3 benign_google_scan.py [--target 172.20.0.10]
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

# 15 web/API ports only — no SSH/SMB/RDP credential-access ports
_WEB_PORTS = [80, 443, 8080, 8443, 3000, 3001, 4000, 5000, 5173, 8000, 9000, 9200, 9300, 9090, 4200]
_SPOOF_IP  = "8.8.8.8"


def main() -> None:
    parser = argparse.ArgumentParser(description="Benign Google DNS scan (false alarm)")
    parser.add_argument("--target", default="172.20.0.10")
    args = parser.parse_args()

    total = len(_WEB_PORTS)

    console.print(Panel(
        f"  [dim]Spoofed src: [/dim]  [bold green]{_SPOOF_IP}[/bold green]  [dim](Google Public DNS — 0% abuse)[/dim]\n"
        f"  [dim]Target:      [/dim]  [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Ports:       [/dim]  [white]{total} web-only ports[/white]  [dim](no credential-access ports)[/dim]\n"
        f"  [dim]Expected:    [/dim]  [bold green]LOG_ONLY[/bold green]  [dim](IDS detects but clears as benign)[/dim]",
        title="[bold green]🟢  FALSE ALARM: GOOGLE DNS SCAN[/bold green]",
        border_style="green",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  [bold][[STEP 1/2][/bold]  Spoofing [green]{_SPOOF_IP}[/green] (Google LLC)...")
    console.print(f"  [bold][[STEP 2/2][/bold]  Sending SYN to {total} web ports...")

    for i, port in enumerate(_WEB_PORTS):
        pkt = IP(src=_SPOOF_IP, dst=args.target) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        if (i + 1) % 5 == 0:
            console.print(f"    [dim]→[/dim]  {i + 1}/{total} ports sent")
        time.sleep(0.3)

    console.print(f"\n  [bold green]✓  Done[/bold green]  │  {total} packets sent  │  Expected: [bold green]LOG_ONLY[/bold green]\n")


if __name__ == "__main__":
    main()
