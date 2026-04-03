"""Tests for OrchestratorAgent dispatch validation, ordering, and synthesis."""
from __future__ import annotations
import pytest
from unittest.mock import patch, MagicMock

from ..framework.models import Event, AgentReport, InvestigatorResult


DEMO_EVENT = Event(
    event_id="evt_orch_001",
    src_ip="203.0.113.45",
    event_type="port_scan",
    ports_targeted=[22, 80, 443],
    frequency=15,
    time_window_s=8.0,
    severity="high",
)

DISPATCH_RESULT = {"agents_to_invoke": ["reputation", "whois", "port_intel"]}

SYNTHESIS_RESULT = {
    "classification": "malicious",
    "confidence": 0.92,
    "technique": "TCP SYN Port Scan (MITRE T1046)",
    "agents_invoked": ["reputation", "whois", "port_intel"],
    "reasoning": "High abuse score + VPS hosting + credential-access port pattern",
    "recommended_action": "block_ip",
}


def _make_mock_agent(name: str, confidence: float = 0.85):
    agent = MagicMock()
    agent.run.return_value = AgentReport(
        agent_name=name,
        findings={"risk_level": "high"},
        confidence=confidence,
    )
    return agent


def test_orchestrator_respects_llm_chosen_order():
    call_order = []

    def mock_agent_factory(name: str):
        cls = MagicMock()
        instance = MagicMock()
        instance.run.side_effect = lambda event, prior_findings=None: (
            call_order.append(name),
            AgentReport(agent_name=name, findings={}, confidence=0.8),
        )[1]
        cls.return_value = instance
        return cls

    mock_registry = {
        "reputation": mock_agent_factory("reputation"),
        "whois": mock_agent_factory("whois"),
        "port_intel": mock_agent_factory("port_intel"),
        "dns": mock_agent_factory("dns"),
    }

    llm_responses = [DISPATCH_RESULT, SYNTHESIS_RESULT]
    call_count = 0

    def mock_llm_call(system, user):
        nonlocal call_count
        result = llm_responses[call_count]
        call_count += 1
        return result

    from ..agents.orchestrator import OrchestratorAgent
    with patch("threat_system.agents.orchestrator.get_registry", return_value=mock_registry):
        with patch("threat_system.framework.llm_client.call", side_effect=mock_llm_call):
            orchestrator = OrchestratorAgent()
            result = orchestrator.run(DEMO_EVENT)

    assert call_order == ["reputation", "whois", "port_intel"]
    assert result.classification == "malicious"


def test_orchestrator_rejects_unregistered_agents():
    malicious_dispatch = {"agents_to_invoke": ["reputation", "exec_shell", "whois"]}
    mock_registry = {
        "reputation": MagicMock(return_value=MagicMock(
            run=MagicMock(return_value=AgentReport(agent_name="reputation", findings={}, confidence=0.8))
        )),
        "whois": MagicMock(return_value=MagicMock(
            run=MagicMock(return_value=AgentReport(agent_name="whois", findings={}, confidence=0.8))
        )),
    }

    llm_responses = [malicious_dispatch, SYNTHESIS_RESULT]
    call_count = 0

    def mock_llm_call(system, user):
        nonlocal call_count
        result = llm_responses[call_count]
        call_count += 1
        return result

    from ..agents.orchestrator import OrchestratorAgent
    with patch("threat_system.agents.orchestrator.get_registry", return_value=mock_registry):
        with patch("threat_system.framework.llm_client.call", side_effect=mock_llm_call):
            orchestrator = OrchestratorAgent()
            result = orchestrator.run(DEMO_EVENT)

    # "exec_shell" should be silently dropped — only registered agents run
    assert result.classification == "malicious"


def test_orchestrator_auto_escalates_low_confidence():
    low_confidence_synthesis = {**SYNTHESIS_RESULT, "confidence": 0.45, "recommended_action": "block_ip"}

    llm_responses = [DISPATCH_RESULT, low_confidence_synthesis]
    call_count = 0

    def mock_llm_call(system, user):
        nonlocal call_count
        result = llm_responses[call_count]
        call_count += 1
        return result

    mock_registry = {
        "reputation": MagicMock(return_value=MagicMock(
            run=MagicMock(return_value=AgentReport(agent_name="reputation", findings={}, confidence=0.4))
        )),
        "whois": MagicMock(return_value=MagicMock(
            run=MagicMock(return_value=AgentReport(agent_name="whois", findings={}, confidence=0.4))
        )),
        "port_intel": MagicMock(return_value=MagicMock(
            run=MagicMock(return_value=AgentReport(agent_name="port_intel", findings={}, confidence=0.4))
        )),
    }

    from ..agents.orchestrator import OrchestratorAgent
    with patch("threat_system.agents.orchestrator.get_registry", return_value=mock_registry):
        with patch("threat_system.framework.llm_client.call", side_effect=mock_llm_call):
            orchestrator = OrchestratorAgent()
            result = orchestrator.run(DEMO_EVENT)

    assert result.auto_escalated is True
    assert result.recommended_action == "escalate_human"


def test_orchestrator_parallel_dispatch_schema():
    """Parallel agents receive empty prior_findings; sequential agent receives parallel reports."""
    parallel_dispatch = {
        "parallel_agents": ["whois", "dns", "port_intel"],
        "sequential_agents": ["reputation"],
    }

    prior_findings_seen: dict[str, list] = {}

    def mock_agent_factory(name: str):
        cls = MagicMock()
        instance = MagicMock()

        def run(event, prior_findings=None):
            prior_findings_seen[name] = list(prior_findings or [])
            return AgentReport(agent_name=name, findings={"name": name}, confidence=0.8)

        instance.run.side_effect = run
        cls.return_value = instance
        return cls

    mock_registry = {
        "whois":      mock_agent_factory("whois"),
        "dns":        mock_agent_factory("dns"),
        "port_intel": mock_agent_factory("port_intel"),
        "reputation": mock_agent_factory("reputation"),
    }

    llm_responses = [parallel_dispatch, SYNTHESIS_RESULT]
    call_count = 0

    def mock_llm_call(system, user):
        nonlocal call_count
        result = llm_responses[call_count]
        call_count += 1
        return result

    from ..agents.orchestrator import OrchestratorAgent
    with patch("threat_system.agents.orchestrator.get_registry", return_value=mock_registry):
        with patch("threat_system.framework.llm_client.call", side_effect=mock_llm_call):
            orchestrator = OrchestratorAgent()
            result = orchestrator.run(DEMO_EVENT)

    # Phase 1 agents ran with no prior context
    assert prior_findings_seen["whois"] == []
    assert prior_findings_seen["dns"] == []
    assert prior_findings_seen["port_intel"] == []

    # Phase 2 agent received all three Phase 1 reports
    rep_prior = prior_findings_seen["reputation"]
    assert len(rep_prior) == 3
    parallel_names = {r.agent_name for r in rep_prior}
    assert parallel_names == {"whois", "dns", "port_intel"}

    assert result.classification == "malicious"


def test_orchestrator_includes_fallback_agents_in_synthesis():
    fallback_report = AgentReport(
        agent_name="reputation", findings={}, confidence=0.0, fallback=True, error="API down"
    )

    mock_registry = {
        "reputation": MagicMock(return_value=MagicMock(run=MagicMock(return_value=fallback_report))),
        "whois": MagicMock(return_value=MagicMock(
            run=MagicMock(return_value=AgentReport(agent_name="whois", findings={}, confidence=0.8))
        )),
        "port_intel": MagicMock(return_value=MagicMock(
            run=MagicMock(return_value=AgentReport(agent_name="port_intel", findings={}, confidence=0.8))
        )),
    }

    synthesis_calls = []

    def mock_llm_call(system, user):
        synthesis_calls.append(user)
        if len(synthesis_calls) == 1:
            return DISPATCH_RESULT
        return SYNTHESIS_RESULT

    from ..agents.orchestrator import OrchestratorAgent
    with patch("threat_system.framework.registry.get_registry", return_value=mock_registry):
        with patch("threat_system.framework.llm_client.call", side_effect=mock_llm_call):
            orchestrator = OrchestratorAgent()
            result = orchestrator.run(DEMO_EVENT)

    # The synthesis prompt should mention the fallback agent
    synthesis_prompt = synthesis_calls[1]
    assert "reputation" in synthesis_prompt
