# Agent Design Skill

## BaseAgent Contract

All agents inherit from `framework/base_agent.py::BaseAgent`.

```python
class BaseAgent(ABC):
    name: str  # must be overridden as class attribute

    @abstractmethod
    def run(self, event: Event, prior_findings: list[AgentReport] | None = None) -> AgentReport | InvestigatorResult:
        raise NotImplementedError
```

## AgentReport Schema

```python
@dataclass
class AgentReport:
    agent_name: str
    findings: dict[str, Any]     # LLM-parsed output
    confidence: float             # 0.0–1.0
    error: str = ""               # populated on fallback
    fallback: bool = False        # True if tool.fetch() failed
```

## Implementation Pattern

Every specialist agent follows this exact pattern:
1. Load skill via `skill_loader.load("skill_name")`
2. Try `tool.fetch(ip)` — on exception, return fallback AgentReport
3. Load prompt template via `load_prompt("agent_name")`
4. Call `template.format(src_ip=..., tool_output=..., prior_findings=..., skill=...)`
5. Call `llm_client.call(system=..., user=prompt)`
6. Return `AgentReport(agent_name=self.name, findings=result, confidence=result.get("confidence", 0.0))`

## Fallback Pattern

```python
try:
    raw_data = self.tool.fetch(event.src_ip)
except Exception as e:
    return AgentReport(agent_name=self.name, findings={}, confidence=0.0, error=str(e), fallback=True)
```

Never re-raise. Never skip. Always return a valid AgentReport.

## Injection Sanitization

Before `str.format()`, sanitize all event field values:
- Strip `{` and `}` characters
- Remove known injection tokens: `ignore`, `disregard`, `system:`, `</s>`
