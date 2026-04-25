"""
display.py — Rich terminal output for the AA-IDS pipeline.

Covers two use-cases:
  1. Scenario / evaluation mode  — JSON stage panels + thought bubbles
                                   (render_stage, render_thought_bubble,
                                    render_evaluation_table)
  2. Live Docker mode             — clean, compact banners with no JSON
                                   (render_event, render_dispatch,
                                    render_agent_result, render_investigation,
                                    render_policy, render_final_action)

Previously split across display.py and terminal_display.py; merged here so
main.py only needs one import.
"""
from __future__ import annotations

import io
import json
import os
import sys
from typing import Any

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

# Force UTF-8 on Windows terminals so box-drawing characters render correctly
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

console = Console(legacy_windows=False)

# ── Stage → colour map (scenario mode) ───────────────────────────────────────

STAGE_COLORS = {
    "event":               "cyan",
    "dispatch_order":      "yellow",
    "agent_report":        "blue",
    "investigator_result": "magenta",
    "policy_result":       "green",
    "action_record":       "red",
}

DECISION_COLORS = {
    "ALLOW":      "green",
    "DOWNGRADE":  "yellow",
    "ESCALATE":   "orange1",
    "BLOCK":      "red",
    "malicious":  "red",
    "suspicious": "yellow",
    "benign":     "green",
}

# ── Risk / action helpers (live mode) ────────────────────────────────────────

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


# ── Scenario-mode renderers ───────────────────────────────────────────────────

def render_stage(stage_name: str, data: Any) -> None:
    color = STAGE_COLORS.get(stage_name, "white")
    title = stage_name.replace("_", " ").upper()

    if hasattr(data, "__dict__"):
        content = json.dumps(data.__dict__, indent=2, default=str)
    elif isinstance(data, dict):
        content = json.dumps(data, indent=2, default=str)
    else:
        content = str(data)

    if stage_name == "policy_result" and hasattr(data, "decision"):
        decision_color = DECISION_COLORS.get(data.decision, "white")
        title_text = Text(f"[{title}]  Decision: ", style=color)
        title_text.append(data.decision, style=decision_color)
        console.print(Panel(content, title=title_text, border_style=color))
    elif stage_name == "investigator_result" and hasattr(data, "classification"):
        cls_color = DECISION_COLORS.get(data.classification, "white")
        title_text = Text(f"[{title}]  Classification: ", style=color)
        title_text.append(data.classification.upper(), style=cls_color)
        console.print(Panel(content, title=title_text, border_style=color))
    else:
        console.print(Panel(content, title=f"[{color}][{title}][/{color}]", border_style=color))


def render_evaluation_table(report_path: str) -> None:
    if not os.path.isfile(report_path):
        console.print("[yellow]No evaluation report found.[/yellow]")
        return

    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)

    table = Table(title="Evaluation Results", box=box.ROUNDED, border_style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("LLM Pipeline", style="bold green")
    table.add_column("Rule Baseline", style="bold yellow")
    table.add_column("Target", style="bold magenta")

    metrics = [
        ("Precision",            "precision",          "> 0.85"),
        ("Recall",               "recall",             "> 0.80"),
        ("False Positive Rate",  "false_positive_rate","< 0.15"),
        ("Avg Latency (s)",      "avg_latency_s",      "< 5.0"),
        ("Policy Overrides",     "policy_overrides",   "> 0"),
    ]

    llm_metrics      = report.get("llm_pipeline", {})
    baseline_metrics = report.get("rule_baseline", {})

    for label, key, target in metrics:
        llm_val  = llm_metrics.get(key, "N/A")
        base_val = baseline_metrics.get(key, "N/A")
        table.add_row(
            label,
            f"{llm_val:.3f}"  if isinstance(llm_val, float)  else str(llm_val),
            f"{base_val:.3f}" if isinstance(base_val, float) else str(base_val),
            target,
        )

    console.print(table)


def render_thought_bubble(narration: dict) -> None:
    """Render a speech-bubble Rich Panel for an agent's inner voice."""
    try:
        agent       = narration.get("agent", "?")
        archetype   = narration.get("archetype", agent.title())
        catchphrase = narration.get("catchphrase", "")
        inner_voice = narration.get("inner_voice", "")
        confidence  = float(narration.get("confidence", 0.0))
        color       = narration.get("color", "white")
        verdict     = narration.get("verdict", "")

        verdict_colors = {
            "malicious":  "red",
            "suspicious": "yellow",
            "clean":      "green",
            "escalated":  "orange1",
            "pending":    "cyan",
            "unknown":    "dim white",
        }
        v_color = verdict_colors.get(verdict, "white")

        filled = round(confidence * 20)
        bar = "█" * filled + "░" * (20 - filled)

        content = Text()
        if catchphrase:
            content.append(f'  "{catchphrase}"\n\n', style=f"italic {color}")
        content.append(f"  {inner_voice}\n\n", style="white")
        content.append("  Confidence  ", style="dim")
        content.append(f"[{bar}]", style=color)
        content.append(f"  {confidence:.0%}", style="bold")
        if verdict:
            content.append("   verdict: ", style="dim")
            content.append(verdict.upper(), style=f"bold {v_color}")

        title = Text()
        title.append("💭  ", style="white")
        title.append(archetype.upper(), style=f"bold {color}")
        title.append(f"  —  {agent}", style=f"dim {color}")

        console.print(Panel(content, title=title, border_style=color, padding=(0, 0)))
    except Exception:
        pass  # visualizer is cosmetic — never crash the pipeline


# ── Live-mode terminal renderers ─────────────────────────────────────────────

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
    name     = (report.agent_name or "unknown").lower()
    findings = report.findings or {}
    conf     = report.confidence or 0.0
    fallback = report.fallback

    risk = (findings.get("risk_level") or "unknown").lower()

    if name == "whois":
        org     = findings.get("org") or findings.get("hosting_provider") or "Unknown org"
        summary = org
    elif name == "dns":
        hostname = findings.get("hostname") or ""
        has_ptr  = findings.get("has_ptr_record", False)
        summary  = hostname if hostname else ("No PTR record" if not has_ptr else "PTR resolved")
    elif name == "reputation":
        score   = findings.get("abuse_score", "?")
        reports = findings.get("total_reports", 0)
        summary = f"AbuseIPDB {score}%  ·  {reports} reports"
    elif name == "port_intel":
        services   = findings.get("services_targeted") or []
        techniques = findings.get("mitre_techniques") or []
        svc        = ", ".join(str(s) for s in services[:3]) if services else "unknown"
        tech       = ", ".join(str(t) for t in techniques[:2]) if techniques else "none"
        summary    = f"{svc}  ·  {tech}"
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
    cls    = (getattr(result, "classification", "unknown") or "unknown").lower()
    conf   = getattr(result, "confidence", 0.0) or 0.0
    action = (getattr(result, "recommended_action", "unknown") or "unknown").lower()

    console.print()
    console.print(Rule(style="dim"))
    line = Text()
    line.append("  ORCHESTRATOR  │  ", style="dim")
    line.append(cls.upper(), style=f"bold {_rc(cls)}")
    line.append(f"  │  {conf:.0%} confidence\n", style="white")
    line.append("  Recommended:  ", style="dim")
    line.append(action.replace("_", " ").upper(), style=_ACTION_COLOR.get(action, "bold white"))
    console.print(line)


def render_policy(result: Any) -> None:
    """Policy decision line."""
    decision = getattr(result, "decision", "?") or "?"
    final    = (getattr(result, "final_action", "?") or "?").lower()

    console.print(Rule(style="dim"))
    line = Text()
    line.append("  POLICY  │  ", style="dim")
    line.append(decision, style="bold white")
    line.append("  →  ", style="dim")
    line.append(final.replace("_", " ").upper(), style=_ACTION_COLOR.get(final, "bold white"))
    console.print(line)


def render_final_action(record: Any) -> None:
    """Large double-border panel with the final action."""
    action       = (getattr(record, "final_action", "unknown") or "unknown").lower()
    action_label = action.replace("_", " ").upper()
    color        = _ACTION_COLOR.get(action, "bold white").replace("bold ", "")
    icon         = _ACTION_ICON.get(action, "•")

    body = Text(justify="center")
    body.append(f"\n  {icon}  FINAL ACTION:  ", style="dim")
    body.append(action_label, style=_ACTION_COLOR.get(action, "bold white"))
    body.append("\n")

    console.print()
    console.print(Panel(body, border_style=color, box=box.DOUBLE, padding=(0, 1)))
    console.print()
