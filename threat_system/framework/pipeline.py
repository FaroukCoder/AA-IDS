from __future__ import annotations
from typing import Callable, Any

from .models import Event, ActionRecord


class ThreatPipeline:
    def __init__(
        self,
        policy_file: str = "default_policy.json",
        active_mode: bool = False,
        on_stage_complete: Callable[[str, Any], None] | None = None,
    ) -> None:
        from ..agents.orchestrator import OrchestratorAgent
        from .policy_agent import PolicyAgent
        from .executor import ActionAdvisor

        # Pass the same callback into the orchestrator so it can emit
        # "dispatch" and per-"agent_report" events to the visualizer.
        self.orchestrator = OrchestratorAgent(on_agent_complete=on_stage_complete)
        self.policy_agent = PolicyAgent(policy_file)
        self.executor = ActionAdvisor(active_mode)
        self.on_stage = on_stage_complete

    def run_event(self, event: Event) -> ActionRecord:
        if self.on_stage:
            self.on_stage("event", event)

        result = self.orchestrator.run(event)
        if self.on_stage:
            self.on_stage("investigator_result", result)

        policy = self.policy_agent.check(result, event)
        if self.on_stage:
            self.on_stage("policy_result", policy)

        action = self.executor.execute(policy, result, event)
        if self.on_stage:
            self.on_stage("action_record", action)

        return action
