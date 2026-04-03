from __future__ import annotations
from abc import ABC, abstractmethod

from .models import Event, AgentReport, InvestigatorResult


class BaseAgent(ABC):
    name: str = "base"

    @abstractmethod
    def run(
        self,
        event: Event,
        prior_findings: list[AgentReport] | None = None,
    ) -> AgentReport | InvestigatorResult:
        raise NotImplementedError(
            f"{self.__class__.__name__}.run() must be implemented by subclass"
        )
