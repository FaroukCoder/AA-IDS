"""
terminal_display.py — Clean Rich terminal output for live mode.

Used by live.py only. No JSON dumps, no thought bubbles.
Those stay in the web UI (display.py + narrator.py).
"""
from __future__ import annotations

import io
import sys
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

# Force UTF-8 output so Rich box-drawing characters work on Windows terminals
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

console = Console(legacy_windows=False)

# ── Color helpers ────────────────────────────────────────────────────────────

_RISK_COLOR: dict[str, str] = {
    "high": "red", "critical": "red", "malicious": "red",
    "medium": "yellow", "suspicious": "yellow",
    "low": "green", "clean": "green", "benign": "green", "unknown": "dim white",
}

_ACTION_COLOR: dict[str, str] = {
    "escalate_human": "bold red",
    "block_ip":       "bold red",
    "alert_admin":    "bold yellow",
    "monitor":        "bold cyan",
    "log_only":       "bold green",
}

_ACTION_ICON: dict[str, str] = {
    "escalate_human": "🚨",
    "block_ip":       "🚫",
    "alert_admin":    "⚠️ ",
    "monitor":        "👁 ",
    "log_only":       "📋",
}

_RISK_ICON: dict[str, str] = {
    "high": "🔴", "critical": "🔴", "malicious": "🔴",
    "medium": "🟡", "suspicious": "🟡",
    "low": "🟢", "clean": "🟢", "benign": "🟢",
}


def _rc(risk: str) -> str:
    return _RISK_COLOR.get((risk or "").lower(), "dim white")


def _ri(risk: str) -> str:
    return _RISK_ICON.get((risk or "").lower(), "⚪")


# ── Stage renderers ───────────────────────────────────────────────────────────

def render_event(event: Any) -> None:
    """Double-border panel shown when Sentinel fires a rule."""
    sev = (getattr(event, "severity", "unknown") or "unknown").lower()
    sev_color = _rc(sev)

    ports = getattr(event, "ports_targeted", []) or []
    port_str = str(ports[:8]) + ("..." if len(ports) > 8 else "")

    body = Text()
    body.append("  Source IP:  ", style="dim")
    body.append(f"{event.src_ip}\n", style="bold cyan")
    body.append("  Type:       ", style="dim")
    body.append(f"{event.event_type}", style="bold white")
    body.append("  │  ", style="dim")
    body.append(f"{event.frequency} connections / {event.time_window_s:.1f}s\n", style="white")
    body.append("  Severity:   ", style="dim")
    body.append(f"{sev.upper()}", style=f"bold {sev_color}")
    if ports:
        body.append("\n  Ports:      ", style="dim")
        body.append(port_str, style="white")

    console.print()
    console.print(Panel(
        body,
        title=f"[bold cyan]🔍  THREAT DETECTED  │  {event.event_id}[/bold cyan]",
        border_style="cyan",
        box=box.DOUBLE,
        padding=(0, 1),
    ))


def render_dispatch(agents: list[str]) -> None:
    """Single line showing which agents will run."""
    names = "  ·  ".join(a.upper() for a in agents)
    console.print(f"\n  [dim]Agents:[/dim]  [bold]{names}[/bold]\n")


def render_agent_result(report: Any, index: int, total: int) -> None:
    """Banner + one-line result for each agent as it completes."""
    name = (report.agent_name or "unknown").lower()
    findings = report.findings or {}
    conf = report.confidence or 0.0
    fallback = report.fallback

    # Extract key summary per agent type
    risk = (findings.get("risk_level") or "unknown").lower()

    if name == "whois":
        org = findings.get("org") or findings.get("hosting_provider") or "Unknown org"
        summary = org
    elif name == "dns":
        hostname = findings.get("hostname") or ""
        has_ptr = findings.get("has_ptr_record", False)
        summary = hostname if hostname else ("No PTR record" if not has_ptr else "PTR resolved")
    elif name == "reputation":
        score = findings.get("abuse_score", "?")
        reports = findings.get("total_reports", 0)
        summary = f"AbuseIPDB {score}%  ·  {reports} reports"
    elif name == "port_intel":
        services = findings.get("services_targeted") or []
        techniques = findings.get("mitre_techniques") or []
        svc = ", ".join(str(s) for s in services[:3]) if services else "unknown"
        tech = ", ".join(str(t) for t in techniques[:2]) if techniques else "none"
        summary = f"{svc}  ·  {tech}"
    else:
        summary = str(findings)[:60]

    label = name.upper().replace("_", " ")
    console.print(Rule(f"[dim][{index}/{total}] {label}[/dim]", style="dim"))

    line = Text()
    line.append("  ✓  ", style="bold green")
    line.append(f"{label:<12}", style=f"bold {_rc(risk)}")
    line.append("  │  ", style="dim")
    line.append(summary, style="white")
    line.append("  │  ", style="dim")
    line.append(f"{_ri(risk)} ", style="")
    line.append(risk.upper(), style=f"bold {_rc(risk)}")
    line.append(f"  ({conf:.0%})", style="dim")
    if fallback:
        line.append("  [fallback]", style="dim red")
    console.print(line)


def render_investigation(result: Any) -> None:
    """Classification + confidence + recommended action."""
    cls = (getattr(result, "classification", "unknown") or "unknown").lower()
    conf = getattr(result, "confidence", 0.0) or 0.0
    action = (getattr(result, "recommended_action", "unknown") or "unknown").lower()
    action_label = action.replace("_", " ").upper()

    console.print()
    console.print(Rule(style="dim"))
    line = Text()
    line.append("  ORCHESTRATOR  │  ", style="dim")
    line.append(cls.upper(), style=f"bold {_rc(cls)}")
    line.append(f"  │  {conf:.0%} confidence\n", style="white")
    line.append("  Recommended:  ", style="dim")
    line.append(action_label, style=_ACTION_COLOR.get(action, "bold white"))
    console.print(line)


def render_policy(result: Any) -> None:
    """Policy decision line."""
    decision = getattr(result, "decision", "?") or "?"
    final = (getattr(result, "final_action", "?") or "?").lower()
    final_label = final.replace("_", " ").upper()

    console.print(Rule(style="dim"))
    line = Text()
    line.append("  POLICY  │  ", style="dim")
    line.append(decision, style="bold white")
    line.append("  →  ", style="dim")
    line.append(final_label, style=_ACTION_COLOR.get(final, "bold white"))
    console.print(line)


def render_final_action(record: Any) -> None:
    """Large double-border panel with the final action."""
    action = (getattr(record, "final_action", "unknown") or "unknown").lower()
    action_label = action.replace("_", " ").upper()
    color = _ACTION_COLOR.get(action, "bold white").replace("bold ", "")
    icon = _ACTION_ICON.get(action, "•")

    body = Text(justify="center")
    body.append(f"\n  {icon}  FINAL ACTION:  ", style="dim")
    body.append(action_label, style=_ACTION_COLOR.get(action, "bold white"))
    body.append("\n")

    console.print()
    console.print(Panel(
        body,
        border_style=color,
        box=box.DOUBLE,
        padding=(0, 1),
    ))
    console.print()
