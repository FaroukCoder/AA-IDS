from __future__ import annotations
import json
import os
from typing import Any

from .models import InvestigatorResult, Event, PolicyResult

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


class ConfigError(Exception):
    pass


class PolicyAgent:
    REQUIRED_KEYS = {
        "allowed_actions",
        "protected_ips",
        "min_severity_to_block",
        "require_human_approval_above",
        "min_confidence_to_act",
    }

    def __init__(self, policy_file: str = "default_policy.json") -> None:
        config_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config")
        policy_path = os.path.join(config_dir, policy_file)

        with open(policy_path, encoding="utf-8") as f:
            try:
                policy: dict[str, Any] = json.load(f)
            except json.JSONDecodeError as e:
                raise ConfigError(f"Malformed policy JSON in {policy_file}: {e}") from e

        missing = self.REQUIRED_KEYS - set(policy.keys())
        if missing:
            raise ConfigError(f"Policy file {policy_file} missing keys: {missing}")

        self._policy = policy
        self._policy_file = policy_file

    def check(self, result: InvestigatorResult, event: Event) -> PolicyResult:
        allowed = self._policy["allowed_actions"]
        protected = self._policy["protected_ips"]
        min_sev_to_block = self._policy["min_severity_to_block"]
        require_human_above = self._policy["require_human_approval_above"]

        original_action = result.recommended_action

        # 1. BLOCK — source IP is protected (never act on it)
        if event.src_ip in protected:
            final = "log_only"
            if final not in allowed:
                final = allowed[0]
            return PolicyResult(
                decision="BLOCK",
                original_action=original_action,
                final_action=final,
                reason=f"src_ip={event.src_ip} is a protected IP — action suppressed",
                policy_file=self._policy_file,
            )

        # 2. ESCALATE — auto_escalated by orchestrator OR severity above threshold
        if result.auto_escalated:
            final = "escalate_human"
            if final not in allowed:
                final = allowed[0]
            return PolicyResult(
                decision="ESCALATE",
                original_action=original_action,
                final_action=final,
                reason="auto_escalated=True (confidence below threshold)",
                policy_file=self._policy_file,
            )

        if SEVERITY_ORDER.get(event.severity, 0) > SEVERITY_ORDER.get(require_human_above, 99):
            final = "escalate_human"
            if final not in allowed:
                final = allowed[0]
            return PolicyResult(
                decision="ESCALATE",
                original_action=original_action,
                final_action=final,
                reason=f"severity={event.severity} above require_human_approval_above={require_human_above}",
                policy_file=self._policy_file,
            )

        # 3. DOWNGRADE — LLM recommended block but severity below min_severity_to_block
        if (
            original_action == "block_ip"
            and SEVERITY_ORDER.get(event.severity, 0) < SEVERITY_ORDER.get(min_sev_to_block, 0)
        ):
            final = "alert_admin"
            if final not in allowed:
                final = allowed[0]
            return PolicyResult(
                decision="DOWNGRADE",
                original_action=original_action,
                final_action=final,
                reason=f"severity={event.severity} below min_severity_to_block={min_sev_to_block}",
                policy_file=self._policy_file,
            )

        # 4. ALLOW — all checks passed
        final = original_action
        if final not in allowed:
            raise ConfigError(
                f"Action '{final}' not in allowed_actions {allowed}"
            )
        return PolicyResult(
            decision="ALLOW",
            original_action=original_action,
            final_action=final,
            reason="All policy checks passed",
            policy_file=self._policy_file,
        )
