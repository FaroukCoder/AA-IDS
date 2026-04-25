"""Tests for LLM resilience and boundary edge cases in the Orchestrator."""
from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock

from ..framework.models import Event, InvestigatorResult
from ..agents.orchestrator import OrchestratorAgent
from ..agents.whois_agent import WHOISAgent
from ..agents.dns_agent import DNSAgent
from ..framework.llm_client import LLMOutputError, _parse_json

DEMO_EVENT = Event(
    event_id="evt_test_llm",
    src_ip="203.0.113.99",
    event_type="traffic_spike",
    ports_targeted=[80],
    frequency=150,
    time_window_s=10.0,
    severity="high",
)


# ── _parse_json hardening (B1) ─────────────────────────────────────────────

def test_parse_json_rejects_null():
    """_parse_json must raise LLMOutputError for JSON null, not return None."""
    with pytest.raises(LLMOutputError, match="JSON object"):
        _parse_json("null")


def test_parse_json_rejects_array():
    """_parse_json must raise LLMOutputError for JSON array."""
    with pytest.raises(LLMOutputError, match="JSON object"):
        _parse_json("[]")


def test_parse_json_rejects_string():
    """_parse_json must raise LLMOutputError for a bare JSON string."""
    with pytest.raises(LLMOutputError, match="JSON object"):
        _parse_json('"just a string"')


def test_parse_json_rejects_number():
    """_parse_json must raise for a bare number."""
    with pytest.raises(LLMOutputError, match="JSON object"):
        _parse_json("42")


def test_parse_json_accepts_valid_object():
    """_parse_json must accept a normal JSON object."""
    result = _parse_json('{"risk_level": "high", "confidence": 0.9}')
    assert result == {"risk_level": "high", "confidence": 0.9}


def test_parse_json_accepts_fenced_object():
    """_parse_json must strip markdown fences and parse the inner object."""
    result = _parse_json('```json\n{"risk_level": "low"}\n```')
    assert result["risk_level"] == "low"


# ── Orchestrator dispatch / synthesis failures ─────────────────────────────

def test_orchestrator_handles_llm_dispatch_failure():
    """If the LLM fails during dispatch, orchestrator returns auto_escalated result."""
    agent = OrchestratorAgent()
    with patch("threat_system.framework.llm_client.call", side_effect=LLMOutputError("Bad JSON")):
        result = agent.run(DEMO_EVENT)
        assert result.confidence == 0.0
        assert result.auto_escalated is True
        assert result.recommended_action == "escalate_human"


def test_orchestrator_handles_llm_synthesis_failure():
    """If synthesis LLM call fails, orchestrator returns auto_escalated result."""
    agent = OrchestratorAgent()

    def _mock_call(system, user):
        if "coordinator" in system.lower():
            return {"parallel_agents": [], "sequential_agents": []}
        raise LLMOutputError("Synthesis failed")

    with patch("threat_system.framework.llm_client.call", side_effect=_mock_call):
        result = agent.run(DEMO_EVENT)
        assert result.confidence == 0.0
        assert result.auto_escalated is True
        assert result.recommended_action == "escalate_human"


def test_orchestrator_handles_missing_keys_in_synthesis():
    """LLM returns valid JSON with missing fields — defaults applied, low confidence escalates."""
    agent = OrchestratorAgent()

    def _mock_call(system, user):
        if "coordinator" in system.lower():
            return {"parallel_agents": [], "sequential_agents": []}
        return {"classification": "suspicious"}

    with patch("threat_system.framework.llm_client.call", side_effect=_mock_call):
        result = agent.run(DEMO_EVENT)
        assert result.classification == "suspicious"
        assert result.confidence == 0.0
        assert result.auto_escalated is True
        assert result.recommended_action == "escalate_human"


# ── Agent confidence type safety (B3) ─────────────────────────────────────

def test_whois_agent_confidence_string_returns_zero():
    """If LLM returns confidence as a string, agent sets confidence=0.0 without crashing."""
    from ..tools.whois_tool import MockWHOISTool
    agent = WHOISAgent(tool=MockWHOISTool())
    mock_response = {"risk_level": "high", "confidence": "high", "org": "Test"}
    with patch("threat_system.framework.llm_client.call", return_value=mock_response):
        report = agent.run(DEMO_EVENT)
    assert report.confidence == 0.0
    assert not report.fallback


def test_dns_agent_confidence_string_returns_zero():
    """DNSAgent handles string confidence gracefully."""
    from ..tools.dns_tool import MockDNSTool
    agent = DNSAgent(tool=MockDNSTool())
    mock_response = {"risk_level": "medium", "confidence": "medium"}
    with patch("threat_system.framework.llm_client.call", return_value=mock_response):
        report = agent.run(DEMO_EVENT)
    assert report.confidence == 0.0
    assert not report.fallback


def test_whois_agent_empty_llm_response_is_fallback():
    """If _parse_json raises on empty/non-dict output, agent returns fallback."""
    from ..tools.whois_tool import MockWHOISTool
    agent = WHOISAgent(tool=MockWHOISTool())
    with patch("threat_system.framework.llm_client.call", side_effect=LLMOutputError("null")):
        report = agent.run(DEMO_EVENT)
    assert report.fallback is True
    assert report.confidence == 0.0


# ── _clean_content: thinking model artifact stripping ─────────────────────

def test_clean_content_strips_think_tags():
    """<think>…</think> blocks from reasoning models are removed before JSON parsing."""
    from ..framework.llm_client import _clean_content
    raw = "<think>\nLet me reason about this...\n</think>\n{\"risk_level\": \"high\"}"
    assert _clean_content(raw) == '{"risk_level": "high"}'


def test_clean_content_leaves_plain_text_unchanged():
    """_clean_content must not alter responses that contain no think tags."""
    from ..framework.llm_client import _clean_content
    assert _clean_content('{"ok": true}') == '{"ok": true}'
