from __future__ import annotations
import json
import os
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

STAGE_COLORS = {
    "event": "cyan",
    "dispatch_order": "yellow",
    "agent_report": "blue",
    "investigator_result": "magenta",
    "policy_result": "green",
    "action_record": "red",
}

DECISION_COLORS = {
    "ALLOW": "green",
    "DOWNGRADE": "yellow",
    "ESCALATE": "orange1",
    "BLOCK": "red",
    "malicious": "red",
    "suspicious": "yellow",
    "benign": "green",
}


def render_stage(stage_name: str, data: Any) -> None:
    color = STAGE_COLORS.get(stage_name, "white")
    title = stage_name.replace("_", " ").upper()

    if hasattr(data, "__dict__"):
        content = json.dumps(data.__dict__, indent=2, default=str)
    elif isinstance(data, dict):
        content = json.dumps(data, indent=2, default=str)
    else:
        content = str(data)

    # Apply color hints to key fields
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
        ("Precision", "precision", "> 0.85"),
        ("Recall", "recall", "> 0.80"),
        ("False Positive Rate", "false_positive_rate", "< 0.15"),
        ("Avg Latency (s)", "avg_latency_s", "< 5.0"),
        ("Policy Overrides", "policy_overrides", "> 0"),
    ]

    llm_metrics = report.get("llm_pipeline", {})
    baseline_metrics = report.get("rule_baseline", {})

    for label, key, target in metrics:
        llm_val = llm_metrics.get(key, "N/A")
        base_val = baseline_metrics.get(key, "N/A")
        table.add_row(
            label,
            f"{llm_val:.3f}" if isinstance(llm_val, float) else str(llm_val),
            f"{base_val:.3f}" if isinstance(base_val, float) else str(base_val),
            target,
        )

    console.print(table)


# ---------------------------------------------------------------------------
# Thought-bubble renderer (called by the visualizer hook in main.py)
# ---------------------------------------------------------------------------

def render_thought_bubble(narration: dict) -> None:
    """Render a speech-bubble Rich Panel for an agent's inner voice.

    narration keys: agent, archetype, catchphrase, inner_voice,
                    confidence, verdict, color
    """
    try:
        agent      = narration.get("agent", "?")
        archetype  = narration.get("archetype", agent.title())
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

        # Unicode confidence bar  ██████░░░░  (20 chars)
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

        console.print(Panel(
            content,
            title=title,
            border_style=color,
            padding=(0, 0),
        ))
    except Exception:
        pass  # visualizer is cosmetic — never crash the pipeline
