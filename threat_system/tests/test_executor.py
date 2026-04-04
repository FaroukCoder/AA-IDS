"""Tests for ActionAdvisor (executor) — IP validation and action whitelist."""
from __future__ import annotations

import json
import os
import tempfile

import pytest

from ..framework.models import Event, InvestigatorResult, PolicyResult
from ..framework.executor import ActionAdvisor
from ..framework.policy_agent import ConfigError


# ── Helpers ────────────────────────────────────────────────────────────────

def _make_event(src_ip: str = "1.2.3.4") -> Event:
    return Event(
        event_id="evt_exec_001",
        src_ip=src_ip,
        event_type="port_scan",
        ports_targeted=[22],
        frequency=12,
        time_window_s=5.0,
        severity="high",
    )


def _make_result(action: str = "block_ip") -> InvestigatorResult:
    return InvestigatorResult(
        classification="malicious",
        confidence=0.9,
        technique="recon",
        agents_invoked=["whois"],
        reasoning="port scan from known attacker",
        recommended_action=action,
        auto_escalated=False,
    )


def _make_policy(action: str = "block_ip") -> PolicyResult:
    return PolicyResult(
        decision="ALLOW",
        original_action=action,
        final_action=action,
        reason="All checks passed",
        policy_file="default_policy.json",
    )


# ── B8: Invalid IP must NOT be written to blocked_ips.txt ─────────────────

def test_invalid_ip_not_written_to_blocked_list(tmp_path, monkeypatch):
    """An invalid src_ip (e.g. shell injection payload) must not appear in blocked_ips.txt."""
    blocked_path = str(tmp_path / "blocked_ips.txt")
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)
    monkeypatch.setattr(executor_mod, "BLOCKED_IPS_LOG", blocked_path)

    advisor = ActionAdvisor(active_mode=True)
    event = _make_event(src_ip="not-an-ip; rm -rf /")
    policy = _make_policy("block_ip")
    result = _make_result("block_ip")

    advisor.execute(policy, result, event)

    # File should either not exist or not contain the malicious string
    if os.path.exists(blocked_path):
        content = open(blocked_path).read()
        assert "not-an-ip" not in content
        assert "rm -rf" not in content


def test_empty_string_ip_not_written(tmp_path, monkeypatch):
    """Empty src_ip must not be written to blocked_ips.txt."""
    blocked_path = str(tmp_path / "blocked_ips.txt")
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)
    monkeypatch.setattr(executor_mod, "BLOCKED_IPS_LOG", blocked_path)

    advisor = ActionAdvisor(active_mode=True)
    event = _make_event(src_ip="")
    policy = _make_policy("block_ip")
    result = _make_result("block_ip")

    # Should not raise
    advisor.execute(policy, result, event)

    if os.path.exists(blocked_path):
        content = open(blocked_path).read()
        assert content.strip() == "" or "\n\n" not in content


def test_valid_ip_written_to_blocked_list(tmp_path, monkeypatch):
    """A valid IPv4 address must be written to blocked_ips.txt in active mode."""
    blocked_path = str(tmp_path / "blocked_ips.txt")
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)
    monkeypatch.setattr(executor_mod, "BLOCKED_IPS_LOG", blocked_path)

    advisor = ActionAdvisor(active_mode=True)
    event = _make_event(src_ip="203.0.113.45")
    policy = _make_policy("block_ip")
    result = _make_result("block_ip")

    advisor.execute(policy, result, event)

    assert os.path.exists(blocked_path)
    content = open(blocked_path).read()
    assert "203.0.113.45" in content


def test_valid_ipv6_written_to_blocked_list(tmp_path, monkeypatch):
    """A valid IPv6 address must be written to blocked_ips.txt in active mode."""
    blocked_path = str(tmp_path / "blocked_ips.txt")
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)
    monkeypatch.setattr(executor_mod, "BLOCKED_IPS_LOG", blocked_path)

    advisor = ActionAdvisor(active_mode=True)
    event = _make_event(src_ip="2001:db8::1")
    policy = _make_policy("block_ip")
    result = _make_result("block_ip")

    advisor.execute(policy, result, event)

    assert os.path.exists(blocked_path)
    content = open(blocked_path).read()
    assert "2001:db8::1" in content


def test_advisory_mode_does_not_write_blocked_list(tmp_path, monkeypatch):
    """In advisory (non-active) mode, blocked_ips.txt must never be written."""
    blocked_path = str(tmp_path / "blocked_ips.txt")
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)
    monkeypatch.setattr(executor_mod, "BLOCKED_IPS_LOG", blocked_path)

    advisor = ActionAdvisor(active_mode=False)
    event = _make_event(src_ip="203.0.113.45")
    policy = _make_policy("block_ip")
    result = _make_result("block_ip")

    advisor.execute(policy, result, event)

    assert not os.path.exists(blocked_path)


# ── Action whitelist enforcement ───────────────────────────────────────────

def test_invalid_action_raises_config_error(tmp_path, monkeypatch):
    """A final_action not in ALLOWED_ACTIONS must raise ConfigError."""
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)

    advisor = ActionAdvisor(active_mode=False)
    event = _make_event()
    result = _make_result("block_ip")
    # Craft a policy with a forged/injected action
    bad_policy = _make_policy("drop_table_users")

    with pytest.raises(ConfigError):
        advisor.execute(bad_policy, result, event)


def test_sql_injection_action_raises_config_error(tmp_path, monkeypatch):
    """SQL-injection-style action string raises ConfigError, not silent pass."""
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)

    advisor = ActionAdvisor(active_mode=False)
    event = _make_event()
    result = _make_result("block_ip")
    bad_policy = _make_policy("block_ip; DROP TABLE users; --")

    with pytest.raises(ConfigError):
        advisor.execute(bad_policy, result, event)


def test_empty_action_raises_config_error(tmp_path, monkeypatch):
    """An empty string final_action raises ConfigError."""
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)

    advisor = ActionAdvisor(active_mode=False)
    event = _make_event()
    result = _make_result("log_only")
    bad_policy = _make_policy("")

    with pytest.raises(ConfigError):
        advisor.execute(bad_policy, result, event)


# ── ActionRecord is written to log ────────────────────────────────────────

def test_action_record_written_to_log(tmp_path, monkeypatch):
    """execute() must append a record to action_log.json."""
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)
    monkeypatch.setattr(executor_mod, "BLOCKED_IPS_LOG", str(tmp_path / "blocked.txt"))

    advisor = ActionAdvisor(active_mode=False)
    event = _make_event(src_ip="10.0.0.1")
    policy = _make_policy("alert_admin")
    result = _make_result("alert_admin")

    record = advisor.execute(policy, result, event)

    assert record.event_id == "evt_exec_001"
    assert record.final_action == "alert_admin"
    assert record.mode == "advisory"

    assert os.path.exists(action_path)
    with open(action_path) as f:
        log = json.load(f)
    assert len(log) == 1
    assert log[0]["event_id"] == "evt_exec_001"


# ── Rollback ───────────────────────────────────────────────────────────────

def test_rollback_marks_entry_reversed(tmp_path, monkeypatch):
    """rollback() must set reversed=True for the matching event_id."""
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)
    monkeypatch.setattr(executor_mod, "BLOCKED_IPS_LOG", str(tmp_path / "blocked.txt"))

    advisor = ActionAdvisor(active_mode=False)
    event = _make_event()
    policy = _make_policy("log_only")
    result = _make_result("log_only")

    advisor.execute(policy, result, event)
    found = advisor.rollback("evt_exec_001")

    assert found is True
    with open(action_path) as f:
        log = json.load(f)
    assert log[0]["reversed"] is True


def test_rollback_unknown_id_returns_false(tmp_path, monkeypatch):
    """rollback() must return False when event_id doesn't exist in log."""
    action_path = str(tmp_path / "action_log.json")

    import threat_system.framework.executor as executor_mod
    monkeypatch.setattr(executor_mod, "ACTION_LOG", action_path)

    advisor = ActionAdvisor(active_mode=False)
    result = advisor.rollback("evt_does_not_exist")
    assert result is False
