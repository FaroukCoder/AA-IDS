from __future__ import annotations
import json
import os
from datetime import datetime, timezone

from .models import InvestigatorResult, PolicyResult, ActionRecord
from .policy_agent import ConfigError

ACTION_LOG = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "action_log.json"
)
BLOCKED_IPS_LOG = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "blocked_ips.txt"
)


def _load_log() -> list[dict]:
    if os.path.isfile(ACTION_LOG):
        with open(ACTION_LOG, encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return []
    return []


def _save_log(records: list[dict]) -> None:
    os.makedirs(os.path.dirname(ACTION_LOG), exist_ok=True)
    with open(ACTION_LOG, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)


class ActionAdvisor:
    ALLOWED_ACTIONS = {"block_ip", "alert_admin", "log_only", "escalate_human"}

    def __init__(self, active_mode: bool = False) -> None:
        self._active = active_mode

    def execute(
        self,
        policy: PolicyResult,
        result: InvestigatorResult,
        event,
    ) -> ActionRecord:
        final = policy.final_action

        # Defence-in-depth: validate final_action even after policy
        if final not in self.ALLOWED_ACTIONS:
            raise ConfigError(
                f"Final action '{final}' is not in allowed actions {self.ALLOWED_ACTIONS}"
            )

        mode = "active" if self._active else "advisory"
        record = ActionRecord(
            event_id=event.event_id,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            llm_action=result.recommended_action,
            policy_decision=policy.decision,
            final_action=final,
            target=event.src_ip,
            mode=mode,
            reversed=False,
        )

        # Append to log
        log = _load_log()
        log.append(record.__dict__)
        _save_log(log)

        # Active mode: append IP to blocked list
        if self._active and final == "block_ip":
            os.makedirs(os.path.dirname(BLOCKED_IPS_LOG), exist_ok=True)
            with open(BLOCKED_IPS_LOG, "a", encoding="utf-8") as f:
                f.write(f"{event.src_ip}\n")

        return record

    def rollback(self, event_id: str) -> bool:
        log = _load_log()
        found = False
        for entry in log:
            if entry.get("event_id") == event_id and not entry.get("reversed"):
                entry["reversed"] = True
                found = True
        if found:
            _save_log(log)
        return found
