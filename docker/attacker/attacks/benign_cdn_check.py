#!/usr/bin/env python3
"""
benign_cdn_check.py — False alarm: HTTP flood spoofed from 104.16.0.1 (Cloudflare CDN).

Triggers Sentinel's traffic_spike rule (>100 packets in 10s) but the LLM
should classify LOG_ONLY: Cloudflare CDN IP, legitimate health-check pattern.

Usage:
    python3 benign_cdn_check.py [--target 172.20.0.10]
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

_CDN_IP = "104.16.0.1"   # Cloudflare CDN range
_COUNT  = 110             # just above traffic_spike threshold of 100


def main() -> None:
    parser = argparse.ArgumentParser(description="Benign CDN health check flood (false alarm)")
    parser.add_argument("--target", default="172.20.0.10")
    args = parser.parse_args()

    console.print(Panel(
        f"  [dim]Spoofed src: [/dim]  [bold green]{_CDN_IP}[/bold green]  [dim](Cloudflare CDN — known legitimate provider)[/dim]\n"
        f"  [dim]Target:      [/dim]  [bold cyan]{args.target}:80[/bold cyan]\n"
        f"  [dim]Packets:     [/dim]  [white]{_COUNT} SYN to port 80[/white]  [dim](single port — no scan pattern)[/dim]\n"
        f"  [dim]Expected:    [/dim]  [bold green]LOG_ONLY[/bold green]  [dim](traffic_spike fires but CDN cleared)[/dim]",
        title="[bold green]🟢  FALSE ALARM: CDN HEALTH CHECK[/bold green]",
        border_style="green",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  [bold][[STEP 1/2][/bold]  Spoofing [green]{_CDN_IP}[/green] (Cloudflare Inc.)...")
    console.print(f"  [bold][[STEP 2/2][/bold]  Sending {_COUNT} packets to port 80...")

    for i in range(_COUNT):
        pkt = IP(src=_CDN_IP, dst=args.target) / TCP(dport=80, flags="S")
        send(pkt, verbose=0)
        if (i + 1) % 25 == 0:
            console.print(f"    [dim]→[/dim]  {i + 1}/{_COUNT} packets sent")
        time.sleep(0.05)

    console.print(f"\n  [bold green]✓  Done[/bold green]  │  {_COUNT} packets sent  │  Expected: [bold green]LOG_ONLY[/bold green]\n")


if __name__ == "__main__":
    main()
