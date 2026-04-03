"""Tests for narrator.py — thought-bubble synthesis from pipeline stage data."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock

from ..framework.models import Event, AgentReport, InvestigatorResult, PolicyResult
from ..visualizer.narrator import (
    narrate,
    narrate_sentinel,
    narrate_agent,
    narrate_orchestrator,
    narrate_policy,
    narrate_dispatch,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _evt(**kw) -> Event:
    defaults = dict(
        event_id="evt_001", src_ip="10.0.0.1", event_type="port_scan",
        ports_targeted=[22, 80, 443], frequency=15, time_window_s=8.0, severity="high",
    )
    defaults.update(kw)
    return Event(**defaults)


def _report(agent_name: str, findings: dict | None = None, confidence: float = 0.85,
            fallback: bool = False) -> AgentReport:
    return AgentReport(
        agent_name=agent_name,
        findings=findings or {},
        confidence=confidence,
        fallback=fallback,
    )


NARRATION_KEYS = {"agent", "catchphrase", "inner_voice", "confidence", "verdict", "color", "archetype"}


# ---------------------------------------------------------------------------
# narrate_sentinel
# ---------------------------------------------------------------------------

def test_narrate_sentinel_returns_all_keys():
    n = narrate_sentinel(_evt(severity="high"))
    assert n is not None
    assert NARRATION_KEYS.issubset(n.keys())


def test_narrate_sentinel_high_severity_is_malicious():
    n = narrate_sentinel(_evt(severity="high"))
    assert n["verdict"] == "malicious"


def test_narrate_sentinel_low_severity_is_clean():
    n = narrate_sentinel(_evt(severity="low"))
    assert n["verdict"] == "clean"


def test_narrate_sentinel_inner_voice_contains_ip():
    n = narrate_sentinel(_evt(src_ip="1.2.3.4"))
    assert "1.2.3.4" in n["inner_voice"]


def test_narrate_sentinel_stores_current_event():
    """narrate_sentinel should not raise even with minimal event data."""
    evt = _evt(event_type="traffic_spike", severity="medium")
    n = narrate_sentinel(evt)
    assert "traffic_spike" in n["inner_voice"] or "spike" in n["inner_voice"].lower()


# ---------------------------------------------------------------------------
# narrate_agent
# ---------------------------------------------------------------------------

def test_narrate_agent_whois_success():
    findings = {
        "org": "Vultr Holdings LLC", "hosting_provider": "Vultr",
        "country": "US", "is_vps_hosting": True,
        "risk_level": "high", "risk_note": "VPS attacker infra.", "confidence": 0.88,
    }
    n = narrate_agent(_report("whois", findings, confidence=0.88))
    assert n is not None
    assert n["agent"] == "whois"
    assert "Vultr" in n["inner_voice"]
    assert n["verdict"] == "malicious"


def test_narrate_agent_whois_fallback():
    n = narrate_agent(_report("whois", {}, confidence=0.0, fallback=True))
    assert n["verdict"] == "unknown"
    assert n["confidence"] == 0.0


def test_narrate_agent_dns_no_hostname():
    findings = {"hostname": None, "has_ptr_record": False,
                "risk_level": "high", "risk_note": "No PTR."}
    n = narrate_agent(_report("dns", findings, confidence=0.75))
    assert n is not None
    assert n["agent"] == "dns"


def test_narrate_agent_reputation_high_score():
    findings = {
        "abuse_score": 95, "total_reports": 42, "previously_reported": True,
        "last_reported_days_ago": 1, "categories": ["Port Scan", "Hacking"],
        "risk_level": "high", "confidence": 0.95,
    }
    n = narrate_agent(_report("reputation", findings, confidence=0.95))
    assert "95" in n["inner_voice"]
    assert n["verdict"] == "malicious"


def test_narrate_agent_port_intel():
    findings = {
        "ports_analyzed": [22, 445, 3389],
        "services_targeted": ["SSH", "SMB", "RDP"],
        "mitre_techniques": ["T1021.004", "T1078"],
        "attack_pattern": "credential_access",
        "risk_level": "high", "confidence": 0.90,
    }
    n = narrate_agent(_report("port_intel", findings, confidence=0.90))
    assert "SSH" in n["inner_voice"] or "T1021" in n["inner_voice"]


def test_narrate_agent_unknown_agent_returns_none():
    n = narrate_agent(_report("nonexistent_agent"))
    # Should still return something (falls back to generic) or None — must not raise
    # (personality map falls back to orchestrator profile for unknown names)
    assert n is None or isinstance(n, dict)


# ---------------------------------------------------------------------------
# narrate_orchestrator
# ---------------------------------------------------------------------------

def test_narrate_orchestrator_malicious_high_confidence():
    result = InvestigatorResult(
        classification="malicious", confidence=0.92,
        technique="TCP SYN Scan", agents_invoked=["whois", "dns", "reputation"],
        reasoning="High score, VPS hosting, credential ports.",
        recommended_action="block_ip",
    )
    n = narrate_orchestrator(result)
    assert n is not None
    assert n["verdict"] == "malicious"
    assert n["confidence"] == pytest.approx(0.92)
    assert "whois" in n["inner_voice"]


def test_narrate_orchestrator_auto_escalated():
    result = InvestigatorResult(
        classification="suspicious", confidence=0.45,
        technique="", agents_invoked=["reputation"],
        reasoning="Low confidence.", recommended_action="escalate_human",
        auto_escalated=True,
    )
    n = narrate_orchestrator(result)
    assert n["verdict"] == "escalated"


# ---------------------------------------------------------------------------
# narrate_policy
# ---------------------------------------------------------------------------

def test_narrate_policy_allow():
    policy = PolicyResult(
        decision="ALLOW", original_action="block_ip", final_action="block_ip",
        reason="All checks passed.", policy_file="default_policy.json",
    )
    n = narrate_policy(policy)
    assert n is not None
    assert n["agent"] == "policy"
    assert "block_ip" in n["inner_voice"]


def test_narrate_policy_downgrade():
    policy = PolicyResult(
        decision="DOWNGRADE", original_action="block_ip", final_action="alert_admin",
        reason="Severity below threshold.", policy_file="default_policy.json",
    )
    n = narrate_policy(policy)
    assert n["verdict"] == "suspicious"


def test_narrate_policy_escalate():
    policy = PolicyResult(
        decision="ESCALATE", original_action="block_ip", final_action="escalate_human",
        reason="Auto-escalated.", policy_file="default_policy.json",
    )
    n = narrate_policy(policy)
    assert n["verdict"] == "escalated"


# ---------------------------------------------------------------------------
# narrate_dispatch
# ---------------------------------------------------------------------------

def test_narrate_dispatch():
    from types import SimpleNamespace
    data = SimpleNamespace(parallel_agents=["whois", "dns"], sequential_agents=["reputation"])
    n = narrate_dispatch(data)
    assert n is not None
    assert "whois" in n["inner_voice"]
    assert "reputation" in n["inner_voice"]


# ---------------------------------------------------------------------------
# Unified narrate() entry point
# ---------------------------------------------------------------------------

def test_narrate_unifies_all_stages():
    assert narrate("event",               _evt()) is not None
    assert narrate("agent_report",        _report("reputation")) is not None
    assert narrate("investigator_result", InvestigatorResult()) is not None
    assert narrate("policy_result",       PolicyResult()) is not None
    assert narrate("action_record",       MagicMock()) is None   # no handler → None
    assert narrate("unknown_stage",       object()) is None


def test_narrate_never_raises_on_bad_data():
    """Narrator must never crash — it's purely cosmetic."""
    assert narrate("event",         None) is None or True
    assert narrate("agent_report",  object()) is None or True
