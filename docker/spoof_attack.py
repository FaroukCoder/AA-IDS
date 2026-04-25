#!/usr/bin/env python3
"""
spoof_attack.py — Interactive spoofed-IP attack launcher.

Presents a numbered menu to choose:
  1. Source IP  (preset identities OR a custom IP you type)
  2. Attack type (port_scan / ssh_spray / http_flood)

Then runs  spoof_attack.py  inside the attacker container with the chosen
parameters via  docker exec.

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
from rich.table import Table

# ── Force UTF-8 so box-drawing works on Windows terminals ─────────────────────
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

console = Console(legacy_windows=False)

CONTAINER = "threat-lab-attacker"

# ── Preset source-IP identities ────────────────────────────────────────────────
SOURCE_IPS: list[tuple[str, str, str]] = [
    ("Google DNS",              "8.8.8.8",        "Major tech — expect BENIGN"),
    ("Cloudflare DNS",          "1.1.1.1",        "Major CDN — expect BENIGN"),
    ("Known AbuseIPDB abuser",  "185.220.101.34", "Tor exit node — expect MALICIOUS"),
    ("Unknown obscure IP",      "45.79.119.202",  "No public reputation — uncertain"),
    ("Custom IP",               "",               ""),
]

# ── Attack type menu entries ───────────────────────────────────────────────────
ATTACK_TYPES: list[tuple[str, str, str]] = [
    ("port_scan",  "15 SYN  → 15 ports", "triggers port_scan rule"),
    ("ssh_spray",  "22 SYN  → port 22",  "triggers failed_conn rule"),
    ("http_flood", "115 ACK → port 80",  "triggers traffic_spike rule"),
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def _print_banner() -> None:
    console.print()
    console.print(Panel(
        "  [bold red]🎭  SPOOFED-IP ATTACK LAUNCHER[/bold red]\n"
        "  [dim]Packets are injected with a forged source address via Scapy.[/dim]\n"
        "  [dim]The IDS sees the spoofed IP — not your real host.[/dim]",
        border_style="red",
        box=box.DOUBLE,
        padding=(0, 2),
    ))
    console.print()


def _pick_source_ip() -> str:
    """Show the source-IP menu and return the chosen IP string."""
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("idx",    style="bold cyan",  no_wrap=True)
    table.add_column("label",  style="white",       no_wrap=True)
    table.add_column("ip",     style="bold yellow", no_wrap=True)
    table.add_column("note",   style="dim",         no_wrap=True)

    for i, (label, ip, note) in enumerate(SOURCE_IPS, start=1):
        ip_display = ip if ip else "[italic](enter below)[/italic]"
        table.add_row(f"{i}.", label, ip_display, note)

    console.print("[bold]Select source IP:[/bold]")
    console.print(table)

    while True:
        raw = console.input("  [cyan]>[/cyan] ").strip()
        if not raw.isdigit():
            console.print("  [red]Please enter a number.[/red]")
            continue
        choice = int(raw)
        if not (1 <= choice <= len(SOURCE_IPS)):
            console.print(f"  [red]Enter a number between 1 and {len(SOURCE_IPS)}.[/red]")
            continue

        label, ip, _ = SOURCE_IPS[choice - 1]
        if ip:  # preset
            console.print(f"  [dim]Using[/dim] [bold cyan]{ip}[/bold cyan] [dim]({label})[/dim]")
            return ip

        # Custom IP
        while True:
            custom = console.input("  Enter IP address: ").strip()
            if custom:
                return custom
            console.print("  [red]IP cannot be empty.[/red]")


def _pick_attack_type() -> str:
    """Show the attack-type menu and return the chosen attack name."""
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("idx",    style="bold cyan", no_wrap=True)
    table.add_column("name",   style="white",      no_wrap=True)
    table.add_column("detail", style="yellow",     no_wrap=True)
    table.add_column("note",   style="dim",        no_wrap=True)

    for i, (name, detail, note) in enumerate(ATTACK_TYPES, start=1):
        table.add_row(f"{i}.", name, detail, f"| {note}")

    console.print()
    console.print("[bold]Select attack type:[/bold]")
    console.print(table)

    while True:
        raw = console.input("  [cyan]>[/cyan] ").strip()
        if not raw.isdigit():
            console.print("  [red]Please enter a number.[/red]")
            continue
        choice = int(raw)
        if not (1 <= choice <= len(ATTACK_TYPES)):
            console.print(f"  [red]Enter a number between 1 and {len(ATTACK_TYPES)}.[/red]")
            continue
        name, _, _ = ATTACK_TYPES[choice - 1]
        return name


def _confirm(src_ip: str, attack: str) -> bool:
    console.print()
    console.print(Panel(
        f"  [dim]Spoofed src:[/dim]  [bold cyan]{src_ip}[/bold cyan]\n"
        f"  [dim]Attack:     [/dim]  [bold white]{attack}[/bold white]",
        title="[bold red]Ready to fire[/bold red]",
        border_style="red",
        box=box.ROUNDED,
        padding=(0, 1),
    ))
    ans = console.input("\n  Launch? [[bold green]y[/bold green]/[bold red]n[/bold red]]: ").strip().lower()
    return ans in ("y", "yes", "")


def _run(src_ip: str, attack: str) -> None:
    console.print()
    console.print(Rule(f"[bold red]Launching {attack}[/bold red]", style="red"))
    result = subprocess.run(
        [
            "docker", "exec", CONTAINER,
            "python3", "/attacks/spoof_attack.py",
            "--src-ip", src_ip,
            "--attack", attack,
        ],
        check=False,
    )
    console.print()
    if result.returncode == 0:
        console.print(Panel(
            "  [bold green]✓  Attack complete[/bold green]",
            border_style="green",
            box=box.DOUBLE,
            padding=(0, 1),
        ))
    else:
        console.print(Panel(
            f"  [bold red]✗  Attack exited with code {result.returncode}[/bold red]\n"
            "  [dim]Is the attacker container running?  "
            "Try: docker compose -f docker/docker-compose.yml up -d[/dim]",
            border_style="red",
            box=box.DOUBLE,
            padding=(0, 1),
        ))


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    _print_banner()
    src_ip = _pick_source_ip()
    attack = _pick_attack_type()

    if _confirm(src_ip, attack):
        _run(src_ip, attack)
    else:
        console.print("\n  [dim]Aborted.[/dim]")


if __name__ == "__main__":
    main()
