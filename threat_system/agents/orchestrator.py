from __future__ import annotations
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# B7: strip control characters and newlines from values inserted into prompts.
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f\n\r]")

from ..framework.base_agent import BaseAgent
from ..framework.models import Event, AgentReport, InvestigatorResult
from ..framework import llm_client
from ..framework.registry import get_registry
from ..config.settings import settings


def _load_prompt(name: str) -> str:
    path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "prompts", f"{name}.txt"
    )
    with open(path, encoding="utf-8") as f:
        return f.read()


def _event_for_prompt(event: Event) -> dict:
    """Strip volatile fields and sanitize src_ip for safe prompt insertion."""
    d = event.__dict__.copy()
    d.pop("event_id", None)
    # B7: remove control chars/newlines from src_ip so they can't inject new
    # prompt lines into the LLM context.
    d["src_ip"] = _CTRL_RE.sub("", str(d.get("src_ip", "")))
    return d


def _run_agent(
    agent_name: str,
    registry: dict,
    event: Event,
    prior_findings: list[AgentReport],
) -> AgentReport:
    agent = registry[agent_name]()
    return agent.run(event, prior_findings=prior_findings)


class OrchestratorAgent(BaseAgent):
    name = "orchestrator"

    def __init__(self, on_agent_complete=None) -> None:
        # Optional callback(stage: str, data) invoked for dispatch + per-agent events.
        # Used by the visualizer; ignored if None.
        self._on_agent = on_agent_complete

    def run(
        self,
        event: Event,
        prior_findings: list[AgentReport] | None = None,
    ) -> InvestigatorResult:
        registry = get_registry()

        # Pass 1 — Dispatch: LLM assigns agents to parallel and sequential groups.
        dispatch_prompt = _load_prompt("orchestrator_dispatch").format(
            event=json.dumps(_event_for_prompt(event)),
            available_agents=json.dumps(list(registry.keys())),
        )
        dispatch_system = (
            "You are a security investigation coordinator. "
            "Respond with valid JSON only. No prose. No markdown fences."
        )
        try:
            dispatch = llm_client.call(system=dispatch_system, user=dispatch_prompt)
        except Exception as e:
            return InvestigatorResult(
                classification="unknown",
                confidence=0.0,
                technique="",
                agents_invoked=[],
                reasoning=f"LLM Dispatch Failed: {e}",
                recommended_action="escalate_human",
                auto_escalated=True,
            )

        # Validate — reject any unregistered agent names.
        raw_parallel = dispatch.get("parallel_agents", [])
        raw_sequential = dispatch.get("sequential_agents", [])

        # Fall back to flat list if LLM returned the old schema.
        if not raw_parallel and not raw_sequential:
            flat = dispatch.get("agents_to_invoke", list(registry.keys()))
            raw_parallel = flat[:-1] if len(flat) > 1 else flat
            raw_sequential = flat[-1:] if len(flat) > 1 else []

        parallel_agents = [a for a in raw_parallel if a in registry]
        sequential_agents = [a for a in raw_sequential if a in registry]

        # Emit dispatch event so the visualizer can build the tree skeleton.
        if self._on_agent:
            from types import SimpleNamespace
            self._on_agent("dispatch", SimpleNamespace(
                parallel_agents=parallel_agents,
                sequential_agents=sequential_agents,
            ))

        reports: list[AgentReport] = []

        # Phase 1 — parallel: agents run simultaneously, no prior context.
        if parallel_agents:
            futures = {}
            with ThreadPoolExecutor(max_workers=len(parallel_agents)) as pool:
                for agent_name in parallel_agents:
                    future = pool.submit(
                        _run_agent, agent_name, registry, event, []
                    )
                    futures[future] = agent_name

            # Preserve dispatch order in results (not completion order).
            parallel_results: dict[str, AgentReport] = {}
            for future in as_completed(futures):
                parallel_results[futures[future]] = future.result()
            for name in parallel_agents:
                reports.append(parallel_results[name])
                if self._on_agent:
                    self._on_agent("agent_report", parallel_results[name])

        # Phase 2 — sequential: each agent receives all prior reports as context.
        for agent_name in sequential_agents:
            report = _run_agent(agent_name, registry, event, reports)
            reports.append(report)
            if self._on_agent:
                self._on_agent("agent_report", report)

        # Pass 2 — Synthesis: LLM synthesizes all AgentReports into final verdict.
        synthesis_prompt = _load_prompt("orchestrator_synthesis").format(
            event=json.dumps(_event_for_prompt(event)),
            agent_reports=json.dumps([r.findings for r in reports]),
            fallback_agents=json.dumps([r.agent_name for r in reports if r.fallback]),
        )
        synthesis_system = (
            "You are a senior security analyst. "
            "Respond with valid JSON only. No prose. No markdown fences."
        )
        try:
            verdict = llm_client.call(system=synthesis_system, user=synthesis_prompt)
        except Exception as e:
            return InvestigatorResult(
                classification="unknown",
                confidence=0.0,
                technique="",
                agents_invoked=parallel_agents + sequential_agents,
                reasoning=f"LLM Synthesis Failed: {e}",
                recommended_action="escalate_human",
                auto_escalated=True,
            )

        result = InvestigatorResult(
            classification=verdict.get("classification", "unknown"),
            confidence=float(verdict.get("confidence", 0.0)),
            technique=verdict.get("technique", ""),
            agents_invoked=verdict.get("agents_invoked", parallel_agents + sequential_agents),
            reasoning=verdict.get("reasoning", ""),
            recommended_action=verdict.get("recommended_action", "log_only"),
        )

        # Auto-escalate if confidence is below threshold.
        if result.confidence < settings.min_confidence_to_act:
            result.auto_escalated = True
            result.recommended_action = "escalate_human"

        return result
