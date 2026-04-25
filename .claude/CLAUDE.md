# CLAUDE.md — Threat Detection System

## What this project is
Multi-agent LLM security system. Sentinel detects. Orchestrator
investigates using sequential agents (LLM-chosen order). Policy Agent
enforces compliance. Executor outputs. Full pipeline in ThreatPipeline.

## Stack
Python 3.11 · Anthropic SDK (claude-sonnet-4-6) · rich · pytest

## Key rules
- No LLM calls outside framework/llm_client.py
- No agent imports from another agent
- Skills are .md files loaded at runtime — never Python classes
- Prompts are .txt files with {placeholders} — one str.format() in agent
- All secrets in config/.env — never hardcoded
- Every tool.fetch() must have a mock for tests
- Tool failure → fallback AgentReport(fallback=True) — never raise to caller

## Directory
agents/       LLM actors (inherit BaseAgent)
skills/       .md domain guidelines (no Python)
tools/        raw data fetchers (no LLM, mockable)
prompts/      .txt templates with {placeholders}
framework/    base classes + pipeline infra
config/       settings + policy + .env
logs/         runtime output + caches (gitignored — only .gitkeep committed)
demo.py       demo entry point — run as: py -m threat_system.demo

## Notes
- framework/display.py covers all terminal output (merged from terminal_display.py)
- conftest.py lives at repo root — standard pytest convention, do not move
- logs/ contains only .gitkeep in version control; runtime JSON files are gitignored
