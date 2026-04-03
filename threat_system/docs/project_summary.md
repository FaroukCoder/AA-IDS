# LLM-Orchestrated Network Threat Detection System
**Network Security Project · April 2025**

## Objective
A modular, AI-assisted system that detects suspicious network activity,
investigates events using a sequential multi-agent pipeline, enforces
compliance via a policy layer, and recommends mitigation actions without
autonomous execution.

## Architecture
```
Simulator → Sentinel → Orchestrator → Policy Agent → Executor
                            ↓
              WHOIS → DNS → Reputation → Port Intel
              (LLM-chosen order, each agent sees prior findings)
```

## Key Design Decisions
- **Sequential agents:** each agent receives all prior AgentReports as
  context, producing compounding investigation depth
- **LLM-decided dispatch order:** Orchestrator LLM selects which agents
  to invoke and in what order based on event type
- **Policy enforcement:** every LLM recommendation passes through a
  compliance gate before reaching the Executor — the LLM cannot bypass it
- **Graceful degradation:** tool failures return fallback AgentReports,
  pipeline continues with reduced confidence
- **Secure by design:** no hardcoded credentials, prompt injection
  sanitization, read-only policy files, audit log with rollback

## Evaluation Results
*(fill in after Phase 7 evaluation run)*
- Precision: X.XX vs baseline X.XX
- Recall: X.XX
- False Positive Rate: X.XX
- Avg latency: Xs per event
- Policy overrides: N events (DOWNGRADE/ESCALATE)

## Stack
Python 3.11 · Anthropic claude-sonnet-4-6 · rich · pytest
