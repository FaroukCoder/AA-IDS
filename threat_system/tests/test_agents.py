"""Tests for specialist agents — success path and fallback path."""
from __future__ import annotations
import pytest
from unittest.mock import MagicMock, patch

from ..framework.models import Event, AgentReport


DEMO_EVENT = Event(
    event_id="evt_test_001",
    src_ip="203.0.113.45",
    event_type="port_scan",
    ports_targeted=[22, 80, 443],
    frequency=15,
    time_window_s=8.0,
    severity="high",
)


# ---------- WHOIS Agent ----------

def test_whois_agent_success():
    from ..agents.whois_agent import WHOISAgent
    from ..tools.whois_tool import MockWHOISTool

    mock_llm_result = {
        "asn": "AS20473",
        "org": "Vultr Holdings LLC",
        "hosting_provider": "Vultr",
        "country": "US",
        "is_vps_hosting": True,
        "is_cloud_provider": True,
        "risk_level": "high",
        "risk_note": "VPS provider Vultr — common attacker infrastructure",
        "confidence": 0.88,
    }

    agent = WHOISAgent(tool=MockWHOISTool())
    with patch("threat_system.framework.llm_client.call", return_value=mock_llm_result):
        report = agent.run(DEMO_EVENT)

    assert isinstance(report, AgentReport)
    assert report.agent_name == "whois"
    assert report.fallback is False
    assert report.confidence == pytest.approx(0.88)
    assert report.findings["is_vps_hosting"] is True


def test_whois_agent_fallback_on_tool_failure():
    from ..agents.whois_agent import WHOISAgent

    failing_tool = MagicMock()
    failing_tool.fetch.side_effect = ConnectionError("Network unreachable")

    agent = WHOISAgent(tool=failing_tool)
    report = agent.run(DEMO_EVENT)

    assert report.fallback is True
    assert report.confidence == 0.0
    assert report.findings == {}
    assert "Network unreachable" in report.error


# ---------- DNS Agent ----------

def test_dns_agent_success():
    from ..agents.dns_agent import DNSAgent
    from ..tools.dns_tool import MockDNSTool

    mock_llm_result = {
        "hostname": "203.0.113.45.vultr.com",
        "has_ptr_record": True,
        "hostname_pattern": "vps",
        "suspicious_tld": False,
        "risk_level": "high",
        "risk_note": "Vultr VPS hostname — attacker-controlled node",
        "confidence": 0.85,
    }

    agent = DNSAgent(tool=MockDNSTool())
    with patch("threat_system.framework.llm_client.call", return_value=mock_llm_result):
        report = agent.run(DEMO_EVENT)

    assert report.agent_name == "dns"
    assert report.fallback is False
    assert report.confidence == pytest.approx(0.85)


def test_dns_agent_fallback():
    from ..agents.dns_agent import DNSAgent

    failing_tool = MagicMock()
    failing_tool.fetch.side_effect = OSError("DNS timeout")

    agent = DNSAgent(tool=failing_tool)
    report = agent.run(DEMO_EVENT)

    assert report.fallback is True
    assert report.confidence == 0.0


# ---------- Reputation Agent ----------

def test_reputation_agent_success():
    from ..agents.reputation_agent import ReputationAgent
    from ..tools.abuseipdb_tool import MockAbuseIPDBTool

    mock_llm_result = {
        "abuse_score": 87,
        "total_reports": 23,
        "categories": ["Port Scan", "Hacking"],
        "previously_reported": True,
        "last_reported_days_ago": 2,
        "risk_level": "high",
        "risk_note": "High-confidence malicious actor, 23 prior reports",
        "confidence": 0.91,
    }

    agent = ReputationAgent(tool=MockAbuseIPDBTool())
    with patch("threat_system.framework.llm_client.call", return_value=mock_llm_result):
        report = agent.run(DEMO_EVENT)

    assert report.agent_name == "reputation"
    assert report.fallback is False
    assert report.findings["abuse_score"] == 87


def test_reputation_agent_with_prior_findings():
    from ..agents.reputation_agent import ReputationAgent
    from ..tools.abuseipdb_tool import MockAbuseIPDBTool

    prior = [AgentReport(agent_name="whois", findings={"org": "Vultr"}, confidence=0.88)]
    mock_result = {"abuse_score": 87, "total_reports": 23, "categories": [], "previously_reported": True,
                   "last_reported_days_ago": 2, "risk_level": "high", "risk_note": "test", "confidence": 0.9}

    agent = ReputationAgent(tool=MockAbuseIPDBTool())
    with patch("threat_system.framework.llm_client.call", return_value=mock_result) as mock_call:
        report = agent.run(DEMO_EVENT, prior_findings=prior)
        # Verify prior findings were injected (check call args contain "Vultr")
        call_args = mock_call.call_args
        assert "Vultr" in str(call_args)

    assert report.fallback is False


# ---------- Port Intel Agent ----------

def test_port_intel_agent_success():
    from ..agents.port_intel_agent import PortIntelAgent
    from ..tools.port_db_tool import MockPortDBTool

    mock_llm_result = {
        "ports_analyzed": [22, 80, 443],
        "services_targeted": ["SSH", "HTTP", "HTTPS"],
        "mitre_techniques": ["T1021.004", "T1071.001"],
        "attack_pattern": "reconnaissance",
        "risk_level": "medium",
        "risk_note": "Port scan targeting web and SSH services",
        "confidence": 0.80,
    }

    agent = PortIntelAgent(tool=MockPortDBTool())
    with patch("threat_system.framework.llm_client.call", return_value=mock_llm_result):
        report = agent.run(DEMO_EVENT)

    assert report.agent_name == "port_intel"
    assert report.fallback is False
    assert "SSH" in report.findings["services_targeted"]
