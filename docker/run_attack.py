#!/usr/bin/env python3
"""
run_attack.py — Convenience script to run attack scripts inside the
already-running attacker container.

Real attacks (trigger detection + escalation):
    python docker/run_attack.py --attack port_scan
    python docker/run_attack.py --attack traffic_spike
    python docker/run_attack.py --attack brute_force

False alarms (trigger detection but LLM classifies LOG_ONLY):
    python docker/run_attack.py --attack benign_google_scan
    python docker/run_attack.py --attack benign_cdn_check
    python docker/run_attack.py --attack benign_slow_touch

Harmless alarms (below threshold or low-confidence detection):
    python docker/run_attack.py --attack harmless_slow_scan
    python docker/run_attack.py --attack harmless_single_ssh
    python docker/run_attack.py --attack harmless_moderate_burst
    python docker/run_attack.py --attack harmless_known_scanner

Run all or random:
    python docker/run_attack.py --attack all
    python docker/run_attack.py --attack random
"""
from __future__ import annotations

import argparse
import io
import random
import subprocess
import sys
import time

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text
from rich import box

# Force UTF-8 output so Rich box-drawing characters work on Windows terminals
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

console = Console(legacy_windows=False)

CONTAINER = "threat-lab-attacker"

REAL_ATTACKS = ["port_scan", "traffic_spike", "brute_force"]

BENIGN_ATTACKS = [
    "benign_google_scan",
    "benign_cdn_check",
    "benign_slow_touch",
]

HARMLESS_ATTACKS = [
    "harmless_slow_scan",
    "harmless_single_ssh",
    "harmless_moderate_burst",
    "harmless_known_scanner",
]

ALL_ATTACKS = REAL_ATTACKS + BENIGN_ATTACKS + HARMLESS_ATTACKS

_ATTACK_LABELS: dict[str, str] = {
    "port_scan":               "🔴  port_scan          [dim](real — ESCALATE_HUMAN expected)[/dim]",
    "traffic_spike":           "🔴  traffic_spike       [dim](real — ESCALATE_HUMAN expected)[/dim]",
    "brute_force":             "🔴  brute_force         [dim](real — ESCALATE_HUMAN expected)[/dim]",
    "benign_google_scan":      "🟢  benign_google_scan  [dim](false alarm — LOG_ONLY expected)[/dim]",
    "benign_cdn_check":        "🟢  benign_cdn_check    [dim](false alarm — LOG_ONLY expected)[/dim]",
    "benign_slow_touch":       "🟢  benign_slow_touch   [dim](false alarm — NO detection)[/dim]",
    "harmless_slow_scan":      "🟡  harmless_slow_scan  [dim](harmless — MONITOR expected)[/dim]",
    "harmless_single_ssh":     "🟡  harmless_single_ssh [dim](harmless — NO detection)[/dim]",
    "harmless_moderate_burst": "🟡  harmless_moderate_burst [dim](harmless — NO detection)[/dim]",
    "harmless_known_scanner":  "🟡  harmless_known_scanner  [dim](harmless — MONITOR expected)[/dim]",
}


def run_attack(attack: str) -> int:
    result = subprocess.run(
        ["docker", "exec", CONTAINER, "python3", f"/attacks/{attack}.py"],
        check=False,
    )
    return result.returncode


def _print_header(mode: str, attacks: list[str]) -> None:
    body_lines = []
    for i, a in enumerate(attacks):
        label = _ATTACK_LABELS.get(a, a)
        body_lines.append(f"  {i + 1:>2}.  {label}")
    body = "\n".join(body_lines)

    console.print(Panel(
        body,
        title=f"[bold cyan]AA-IDS ATTACK RUNNER  │  Mode: {mode}  │  {len(attacks)} attacks[/bold cyan]",
        border_style="cyan",
        box=box.DOUBLE,
        padding=(0, 1),
    ))
    console.print()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run attack scripts in Docker attacker container")
    parser.add_argument(
        "--attack", required=True,
        choices=ALL_ATTACKS + ["all", "random"],
        help="Attack name, 'all' to run all sequentially, or 'random' to pick 3 at random",
    )
    args = parser.parse_args()

    if args.attack == "all":
        _print_header("all", ALL_ATTACKS)
        total = len(ALL_ATTACKS)
        for i, attack in enumerate(ALL_ATTACKS):
            console.print(Rule(f"[bold][{i + 1}/{total}]  {attack}[/bold]", style="cyan"))
            rc = run_attack(attack)
            if rc != 0:
                console.print(f"  [red]WARNING: {attack} exited with code {rc}[/red]", file=sys.stderr)
            if i < total - 1:
                console.print(f"\n  [dim]Pausing 5s before next attack...[/dim]", )
                time.sleep(5)
        console.print()
        console.print(Panel(
            f"  [bold green]✓  All {total} attacks complete[/bold green]",
            border_style="green", box=box.DOUBLE, padding=(0, 1),
        ))

    elif args.attack == "random":
        chosen = random.sample(ALL_ATTACKS, 3)
        _print_header("random", chosen)
        for i, attack in enumerate(chosen):
            console.print(Rule(f"[bold][{i + 1}/3]  {attack}[/bold]", style="cyan"))
            rc = run_attack(attack)
            if rc != 0:
                console.print(f"  [red]WARNING: {attack} exited with code {rc}[/red]", file=sys.stderr)
            if i < 2:
                console.print(f"\n  [dim]Pausing 5s before next attack...[/dim]", )
                time.sleep(5)
        console.print()
        console.print(Panel(
            "  [bold green]✓  Random run complete  (3/3 attacks done)[/bold green]",
            border_style="green", box=box.DOUBLE, padding=(0, 1),
        ))

    else:
        label = _ATTACK_LABELS.get(args.attack, args.attack)
        console.print(Rule(f"[bold]{args.attack}[/bold]", style="cyan"))
        sys.exit(run_attack(args.attack))


if __name__ == "__main__":
    main()
