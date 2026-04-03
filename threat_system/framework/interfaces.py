from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any, Protocol

from .models import Event, AgentReport, InvestigatorResult, PolicyResult, ActionRecord


class IAgent(Protocol):
    name: str

    def run(self, event: Event, prior_findings: list[AgentReport] | None = None) -> AgentReport | InvestigatorResult:
        ...


class ITool(Protocol):
    def fetch(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        ...


class IPolicyAgent(Protocol):
    def check(self, result: InvestigatorResult, event: Event) -> PolicyResult:
        ...


class IExecutor(Protocol):
    def execute(self, policy: PolicyResult, result: InvestigatorResult, event: Event) -> ActionRecord:
        ...
