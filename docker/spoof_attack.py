#!/usr/bin/env python3
"""
spoof_attack.py — Interactive launcher for spoofed-IP attacks.

Presents numbered menus for source IP and attack type, then delegates
to the container-side /attacks/spoof_attack.py via `docker exec`.

Usage:
    python docker/spoof_attack.py
"""
from __future__ import annotations

import io
import subprocess
import sys

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule

# Force UTF-8 on Windows terminals
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

console = Console(legacy_windows=False)

CONTAINER = "threat-lab-attacker"

# ── Preset IPs ─────────────────────────────────────────────────────────────────
# (label, ip, expected_verdict_hint)
PRESET_IPS: list[tuple[str, str, str]] = [
    ("Google DNS",             "8.8.8.8",          "Major tech — expect BENIGN"),
    ("Cloudflare DNS",         "1.1.1.1",           "Major CDN — expect BENIGN"),
    ("Known AbuseIPDB abuser", "185.220.101.34",    "Tor exit node — expect MALICIOUS"),
    ("Unknown obscure IP",     "45.79.119.202",     "No public reputation — uncertain"),
]

# ── Attack types ───────────────────────────────────────────────────────────────
ATTACK_TYPES: list[tuple[str, str]] = [
    ("port_scan",  "15 SYN  → 15 ports  │ triggers port_scan rule"),
    ("ssh_spray",  "22 SYN  → port 22   │ triggers failed_conn rule"),
    ("http_flood", "115 ACK → port 80   │ triggers traffic_spike rule"),
]


def _pick_ip() -> str:
    console.print()
    console.print("[bold cyan]Select source IP:[/bold cyan]")
    for i, (label, ip, note) in enumerate(PRESET_IPS, 1):
        console.print(
            f"  [bold]{i}.[/bold]  {label:<28} "
            f"[cyan]{ip:<18}[/cyan] [dim]{note}[/dim]"
        )
    custom_idx = len(PRESET_IPS) + 1
    console.print(f"  [bold]{custom_idx}.[/bold]  Custom IP")
    console.print()

    while True:
        raw = input("  Choice: ").strip()
        try:
            choice = int(raw)
        except ValueError:
            console.print("  [red]Enter a number.[/red]")
            continue

        if 1 <= choice <= len(PRESET_IPS):
            _, ip, _ = PRESET_IPS[choice - 1]
            return ip
        if choice == custom_idx:
            ip = input("  Enter IP address: ").strip()
            if ip:
                return ip
            console.print("  [red]IP cannot be empty.[/red]")
        else:
            console.print(f"  [red]Enter a number between 1 and {custom_idx}.[/red]")


def _pick_attack() -> str:
    console.print()
    console.print("[bold cyan]Select attack type:[/bold cyan]")
    for i, (name, desc) in enumerate(ATTACK_TYPES, 1):
        console.print(f"  [bold]{i}.[/bold]  [white]{name:<14}[/white] [dim]{desc}[/dim]")
    console.print()

    while True:
        raw = input("  Choice: ").strip()
        try:
            choice = int(raw)
        except ValueError:
            console.print("  [red]Enter a number.[/red]")
            continue

        if 1 <= choice <= len(ATTACK_TYPES):
            return ATTACK_TYPES[choice - 1][0]
        console.print(f"  [red]Enter a number between 1 and {len(ATTACK_TYPES)}.[/red]")


def main() -> None:
    console.print(Panel(
        "  Craft real TCP packets with a spoofed source IP\n"
        "  [dim]Scapy runs inside the attacker container — no simulation[/dim]",
        title="[bold red]🎭  AA-IDS SPOOF ATTACK RUNNER[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    src_ip = _pick_ip()
    attack = _pick_attack()

    console.print()
    console.print(Rule(f"[bold]{attack}  from  {src_ip}[/bold]", style="red"))

    rc = subprocess.run(
        [
            "docker", "exec", CONTAINER,
            "python3", "/attacks/spoof_attack.py",
            "--src-ip", src_ip,
            "--attack", attack,
        ],
        check=False,
    ).returncode

    sys.exit(rc)


if __name__ == "__main__":
    main()
