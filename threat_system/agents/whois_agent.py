from __future__ import annotations
import json
import re

from ..framework.base_agent import BaseAgent
from ..framework.models import Event, AgentReport
from ..framework import skill_loader, llm_client

_INJECTION_TOKENS = re.compile(
    r"ignore|disregard|system\s*:|</s>|<\|im_start\|>|<\|im_end\|>",
    re.IGNORECASE,
)
_BRACES = re.compile(r"[{}]")


def _sanitize(value: str) -> str:
    clean = _INJECTION_TOKENS.sub("", str(value))
    clean = _BRACES.sub("", clean)
    return clean.strip()


def _load_prompt(name: str) -> str:
    import os
    path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "prompts", f"{name}.txt"
    )
    with open(path, encoding="utf-8") as f:
        return f.read()


class WHOISAgent(BaseAgent):
    name = "whois"

    def __init__(self, tool=None) -> None:
        if tool is None:
            from ..tools.whois_tool import WHOISTool
            tool = WHOISTool()
        self.tool = tool

    def run(self, event: Event, prior_findings: list[AgentReport] | None = None) -> AgentReport:
        if prior_findings is None:
            prior_findings = []

        skill = skill_loader.load("whois_skill")

        try:
            raw_data = self.tool.fetch(event.src_ip)
        except Exception as e:
            return AgentReport(
                agent_name=self.name,
                findings={},
                confidence=0.0,
                error=str(e),
                fallback=True,
            )

        template = _load_prompt("whois_agent")
        prompt = template.format(
            src_ip=_sanitize(event.src_ip),
            tool_output=json.dumps(raw_data),
            prior_findings=json.dumps([r.findings for r in prior_findings]),
            skill=skill,
        )

        system = (
            "You are a WHOIS intelligence analyst. "
            "Respond with valid JSON only. No prose. No markdown fences."
        )
        try:
            result = llm_client.call(system=system, user=prompt)
        except Exception as e:
            return AgentReport(
                agent_name=self.name,
                findings={},
                confidence=0.0,
                error=str(e),
                fallback=True,
            )

        _raw_conf = result.get("confidence", 0.0)
        confidence = float(_raw_conf) if isinstance(_raw_conf, (int, float)) else 0.0
        return AgentReport(
            agent_name=self.name,
            findings=result,
            confidence=confidence,
        )
