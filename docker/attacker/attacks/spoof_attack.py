#!/usr/bin/env python3
"""
spoof_attack.py — Send TCP packets with a spoofed source IP using Scapy.

Designed to trigger exactly ONE Sentinel rule per attack type:
  port_scan   → 15 SYN  to 15 distinct ports  (port_scan rule only)
  ssh_spray   → 22 SYN  to port 22             (failed_conn rule only)
  http_flood  → 115 ACK to port 80             (traffic_spike rule only;
                ACK = status "OTHER" — not in failed_statuses set)

Usage (inside container):
    python3 /attacks/spoof_attack.py --src-ip 8.8.8.8 --attack port_scan
"""
from __future__ import annotations

import argparse
import random
import time

from rich import box
from rich.console import Console
from rich.panel import Panel
from scapy.all import IP, TCP, send  # type: ignore[import]

console = Console()

TARGET = "172.20.0.10"

# 15 high-signal ports — matches quick_port_scan.py list
PORT_SCAN_PORTS = [
    21, 22, 23, 25, 80, 110, 139, 443, 445,
    1433, 3306, 3389, 5432, 8080, 8443,
]


def _syn(src_ip: str, dst_port: int) -> None:
    pkt = IP(src=src_ip, dst=TARGET) / TCP(
        dport=dst_port,
        sport=random.randint(1024, 65535),
        flags="S",
    )
    send(pkt, verbose=False)


def _ack(src_ip: str, dst_port: int) -> None:
    """ACK-only packets → status "OTHER" in capture.py → skipped by failed_conn rule."""
    pkt = IP(src=src_ip, dst=TARGET) / TCP(
        dport=dst_port,
        sport=random.randint(1024, 65535),
        flags="A",
    )
    send(pkt, verbose=False)


# ── Attack implementations ─────────────────────────────────────────────────────

def port_scan(src_ip: str) -> None:
    console.print(
        f"\n  Sending SYN to {len(PORT_SCAN_PORTS)} ports "
        f"from [bold cyan]{src_ip}[/bold cyan]...\n"
    )
    for port in PORT_SCAN_PORTS:
        _syn(src_ip, port)
        time.sleep(0.05)
    console.print(
        f"  [bold green]✓  Done[/bold green]  │  "
        f"{len(PORT_SCAN_PORTS)} ports  │  rule: port_scan\n"
    )


def ssh_spray(src_ip: str) -> None:
    count = 22
    console.print(
        f"\n  Sending {count} SYN packets to port 22 "
        f"from [bold cyan]{src_ip}[/bold cyan]...\n"
    )
    for _ in range(count):
        _syn(src_ip, 22)
        time.sleep(0.08)
    console.print(
        f"  [bold green]✓  Done[/bold green]  │  "
        f"{count} SYN packets  │  rule: failed_conn\n"
    )


def http_flood(src_ip: str) -> None:
    count = 115
    console.print(
        f"\n  Sending {count} ACK packets to port 80 "
        f"from [bold cyan]{src_ip}[/bold cyan]...\n"
    )
    for i in range(count):
        _ack(src_ip, 80)
        if (i + 1) % 25 == 0:
            console.print(f"  [dim]→[/dim]  {i + 1}/{count}")
        time.sleep(0.02)
    console.print(
        f"  [bold green]✓  Done[/bold green]  │  "
        f"{count} ACK packets  │  rule: traffic_spike\n"
    )


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Spoofed-IP attack via Scapy")
    parser.add_argument("--src-ip", required=True, help="Spoofed source IP address")
    parser.add_argument(
        "--attack",
        required=True,
        choices=["port_scan", "ssh_spray", "http_flood"],
    )
    args = parser.parse_args()

    console.print(Panel(
        f"  [dim]Spoofed src:[/dim]  [bold cyan]{args.src_ip}[/bold cyan]\n"
        f"  [dim]Target:     [/dim]  [white]{TARGET}[/white]\n"
        f"  [dim]Attack:     [/dim]  [white]{args.attack}[/white]",
        title="[bold red]🎭  SPOOFED ATTACK[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    if args.attack == "port_scan":
        port_scan(args.src_ip)
    elif args.attack == "ssh_spray":
        ssh_spray(args.src_ip)
    elif args.attack == "http_flood":
        http_flood(args.src_ip)


if __name__ == "__main__":
    main()
