#!/usr/bin/env python3
"""
port_scan.py — TCP SYN scan via Scapy raw packets.

Sends a TCP SYN to each port in the given range at ~50 ports/second.
Does NOT use nmap — all traffic is generated directly in Python.

Usage:
    python3 port_scan.py [--target 172.20.0.10] [--ports 20-1024]
"""
from __future__ import annotations

import argparse
import time

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box
from scapy.all import IP, TCP, conf, sr1  # type: ignore[import]

conf.verb = 0
console = Console()


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP SYN port scanner")
    parser.add_argument("--target", default="172.20.0.10")
    parser.add_argument("--ports",  default="20-1024")
    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))
    ports = list(range(start_port, end_port + 1))
    total = len(ports)

    console.print(Panel(
        f"  [dim]Target:[/dim]  [bold cyan]{args.target}[/bold cyan]\n"
        f"  [dim]Ports: [/dim]  [white]{args.ports}[/white]  [dim]({total} total)[/dim]",
        title="[bold red]🎯  TCP SYN PORT SCAN[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  [bold][[STEP 1/2][/bold]  Building target list...  [cyan]{total} ports[/cyan]")
    console.print(f"  [bold][[STEP 2/2][/bold]  Sending SYN packets...")

    start_time = time.time()
    for i, port in enumerate(ports):
        pkt = IP(dst=args.target) / TCP(dport=port, flags="S")
        sr1(pkt, timeout=0.02, verbose=0)

        if i > 0 and i % 50 == 0:
            pct = int(i / total * 100)
            console.print(f"    [dim]→[/dim]  {i}/{total}  [dim]({pct}%)[/dim]")

        time.sleep(0.02)

    elapsed = time.time() - start_time
    console.print(f"\n  [bold green]✓  Done[/bold green]  │  {total} SYN packets sent  │  {elapsed:.1f}s\n")


if __name__ == "__main__":
    main()
