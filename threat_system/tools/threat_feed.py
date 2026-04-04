"""
threat_feed.py — Real-world validation via AbuseIPDB blacklist.

Fetches the top 50 most-reported IPs from the AbuseIPDB global blacklist,
runs each through the full AA-IDS pipeline, and saves results to
threat_system/docs/threat_feed_results.json.

Usage:
    python -m threat_system.tools.threat_feed
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any

import requests
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

console = Console()

DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs")
RESULTS_PATH = os.path.join(DOCS_DIR, "threat_feed_results.json")

# Typical attacker probe set — matches what AbuseIPDB port-scan reports target
_ATTACKER_PORTS = [22, 80, 443, 3306, 3389, 8080]


# ── LLM pre-flight ────────────────────────────────────────────────────────

def _check_llm() -> None:
    """Make one minimal LLM call to verify the API key works before running 50 IPs.
    Raises RuntimeError with the actual SDK error if the API is down or auth fails."""
    from ..framework import llm_client
    try:
        llm_client.call(
            system="You are a test. Respond with valid JSON only.",
            user='Return exactly: {"ok": true}',
        )
        console.print("[green]LLM API: OK[/green]")
    except Exception as exc:
        raise RuntimeError(
            f"\n[bold red]LLM API check failed:[/bold red] {type(exc).__name__}: {exc}\n\n"
            "Likely causes:\n"
            "  • ANTHROPIC_API_KEY in config/.env is invalid, expired, or has no credits\n"
            "  • Model 'claude-sonnet-4-6' is unavailable on your plan\n"
            "  • Network connectivity issue\n\n"
            "Check https://console.anthropic.com → API Keys → Usage"
        ) from exc


# ── API ────────────────────────────────────────────────────────────────────

def fetch_blacklist(limit: int = 50, min_confidence: int = 90) -> list[dict[str, Any]]:
    """Return up to `limit` IPs from AbuseIPDB with confidence >= min_confidence."""
    from ..config.settings import settings

    if not settings.abuseipdb_key:
        raise RuntimeError(
            "ABUSEIPDB_KEY is not set. Add it to config/.env before running the threat feed."
        )

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
            params={"confidenceMinimum": min_confidence, "limit": limit},
            timeout=15,
        )
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"AbuseIPDB blacklist request failed: {e}") from e

    if response.status_code in (401, 403):
        raise RuntimeError(
            f"AbuseIPDB returned {response.status_code}. "
            "Check that your ABUSEIPDB_KEY is valid and your plan includes blacklist access."
        )

    response.raise_for_status()
    data = response.json().get("data", [])
    return data


# ── Event factory ──────────────────────────────────────────────────────────

def _make_event(entry: dict[str, Any], idx: int):
    """Convert a blacklist entry into a synthetic port_scan Event."""
    from ..framework.models import Event

    return Event(
        event_id=f"feed_{idx:03d}",
        src_ip=entry["ipAddress"],
        event_type="port_scan",
        ports_targeted=_ATTACKER_PORTS,
        frequency=15,
        time_window_s=8.0,
        severity="high",
    )


# ── Main runner ────────────────────────────────────────────────────────────

def run_feed(limit: int = 50, min_confidence: int = 90) -> dict[str, Any]:
    """
    Fetch blacklist → run each IP through ThreatPipeline → save + return results.
    """
    from ..config.settings import settings
    from ..framework.pipeline import ThreatPipeline

    settings.validate()

    # Pre-flight: verify the LLM API is reachable before spending time on 50 IPs
    _check_llm()

    console.print(f"\n[bold cyan]AA-IDS Threat Feed[/bold cyan] — fetching top {limit} IPs "
                  f"(confidence ≥ {min_confidence}) from AbuseIPDB blacklist...")

    entries = fetch_blacklist(limit=limit, min_confidence=min_confidence)
    if not entries:
        raise RuntimeError("AbuseIPDB blacklist returned 0 IPs. Check your API key and plan.")

    console.print(f"[green]Fetched {len(entries)} IPs.[/green]")

    # Pre-fetch full AbuseIPDB /check data for each IP so the reputation agent
    # always has rich cached data (totalReports, ISP, categories, countryCode).
    # Without this, reputation may be a fallback agent → synthesis drops confidence.
    console.print("[yellow]Pre-fetching reputation data for all IPs (populates tool cache)...[/yellow]")
    from ..tools.abuseipdb_tool import AbuseIPDBTool
    rep_tool = AbuseIPDBTool()
    for entry in entries:
        rep_tool.fetch(entry["ipAddress"])  # caches in logs/api_cache.json

    console.print("[green]Running full pipeline...[/green]\n")
    pipeline = ThreatPipeline(policy_file="default_policy.json", active_mode=False)

    results: list[dict[str, Any]] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Processing IPs", total=len(entries))

        for idx, entry in enumerate(entries):
            ip = entry.get("ipAddress", "unknown")
            score = entry.get("abuseConfidenceScore", 0)
            progress.update(task, description=f"[cyan]{ip}[/cyan]", advance=1)

            event = _make_event(entry, idx)
            t_start = time.time()

            try:
                action = pipeline.run_event(event)
                latency = round(time.time() - t_start, 2)

                # Recover InvestigatorResult fields from action_log via the action record
                # (pipeline returns ActionRecord; we capture what we need from it)
                results.append({
                    "ip": ip,
                    "abuse_confidence_score": score,
                    "final_action": action.final_action,
                    "policy_decision": action.policy_decision,
                    "classification": action.llm_action,  # what LLM recommended before policy
                    "latency_s": latency,
                })

            except Exception as exc:
                latency = round(time.time() - t_start, 2)
                console.print(f"  [red]Error on {ip}: {exc}[/red]")
                results.append({
                    "ip": ip,
                    "abuse_confidence_score": score,
                    "final_action": "error",
                    "policy_decision": "ERROR",
                    "classification": "error",
                    "latency_s": latency,
                })

    # ── Summary stats ───────────────────────────────────────────────────────
    blocked   = sum(1 for r in results if r["final_action"] == "block_ip")
    alerted   = sum(1 for r in results if r["final_action"] == "alert_admin")
    escalated = sum(1 for r in results if r["final_action"] == "escalate_human")
    logged    = sum(1 for r in results if r["final_action"] == "log_only")
    errors    = sum(1 for r in results if r["final_action"] == "error")

    total = len(results)
    detected = blocked + alerted + escalated
    detection_rate = round(detected / total, 4) if total > 0 else 0.0
    latencies = [r["latency_s"] for r in results if r["final_action"] != "error"]
    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    summary = {
        "blocked": blocked,
        "alerted": alerted,
        "escalated": escalated,
        "logged": logged,
        "errors": errors,
        "avg_latency_s": avg_latency,
        "detection_rate": detection_rate,
    }

    output = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": f"AbuseIPDB blacklist (confidenceMinimum={min_confidence}, limit={limit})",
        "total_ips": total,
        "results": results,
        "summary": summary,
    }

    # ── Save ────────────────────────────────────────────────────────────────
    os.makedirs(DOCS_DIR, exist_ok=True)
    with open(RESULTS_PATH, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    # ── Terminal table ───────────────────────────────────────────────────────
    _print_results_table(results, summary)

    console.print(f"\n[green]Results saved to[/green] {RESULTS_PATH}")
    return output


def _print_results_table(results: list[dict], summary: dict) -> None:
    table = Table(title="AbuseIPDB Threat Feed — Pipeline Results", show_lines=False)
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Abuse Score", justify="right")
    table.add_column("Final Action", justify="center")
    table.add_column("Policy", justify="center")
    table.add_column("Latency (s)", justify="right")

    _action_color = {
        "block_ip": "red",
        "alert_admin": "yellow",
        "escalate_human": "magenta",
        "log_only": "dim",
        "error": "red dim",
    }

    for r in results:
        color = _action_color.get(r["final_action"], "white")
        table.add_row(
            r["ip"],
            str(r["abuse_confidence_score"]),
            f"[{color}]{r['final_action']}[/{color}]",
            r["policy_decision"],
            str(r["latency_s"]),
        )

    console.print(table)
    console.print(
        f"\n[bold]Detection rate:[/bold] [green]{summary['detection_rate']*100:.1f}%[/green]  "
        f"[bold]Blocked:[/bold] {summary['blocked']}  "
        f"[bold]Alerted:[/bold] {summary['alerted']}  "
        f"[bold]Escalated:[/bold] {summary['escalated']}  "
        f"[bold]Avg latency:[/bold] {summary['avg_latency_s']}s"
    )


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    run_feed()
