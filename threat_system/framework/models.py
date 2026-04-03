from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Event:
    event_id: str
    src_ip: str
    event_type: str
    ports_targeted: list[int] = field(default_factory=list)
    frequency: int = 0
    time_window_s: float = 0.0
    severity: str = "low"


@dataclass
class AgentReport:
    agent_name: str
    findings: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    error: str = ""
    fallback: bool = False


@dataclass
class InvestigatorResult:
    classification: str = "unknown"
    confidence: float = 0.0
    technique: str = ""
    agents_invoked: list[str] = field(default_factory=list)
    reasoning: str = ""
    recommended_action: str = "log_only"
    auto_escalated: bool = False


@dataclass
class PolicyResult:
    decision: str = "ALLOW"
    original_action: str = ""
    final_action: str = ""
    reason: str = ""
    policy_file: str = ""


@dataclass
class ActionRecord:
    event_id: str = ""
    timestamp: str = ""
    llm_action: str = ""
    policy_decision: str = ""
    final_action: str = ""
    target: str = ""
    mode: str = "advisory"
    reversed: bool = False
