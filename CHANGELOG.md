# Changelog
## AA-IDS — LLM-Orchestrated Network Threat Detection System

---

## [1.0.0] — April 2025

### Added
- Sentinel detection layer with 3 rule-based detectors
  (port scan, traffic spike, failed connections)
- Multi-agent orchestrator with LLM-decided sequential dispatch
- Specialist agents: WHOIS, DNS, Reputation (AbuseIPDB), Port Intel
- Skills system: domain reasoning guidelines as .md files loaded at runtime
- Policy Agent compliance gate (ALLOW / DOWNGRADE / ESCALATE / BLOCK)
- Executor with advisory mode, action log, and rollback support
- LLM response caching (SHA256-keyed) for reproducible evaluation
- AbuseIPDB response caching to preserve API quota
- Docker environment: Kali attacker vs Ubuntu/Nginx victim
- Scapy packet capture on victim eth0 → JSONL for Sentinel
- Browser dashboard with WebSocket real-time pipeline updates
- Disco Elysium-themed visual UI with video state machine
- Cinematic investigation monologue panel with typewriter effect and
  persistent display; burst-run accumulation with separator dividers
- Spoofed-IP attack tool: real Scapy packets with arbitrary src IP
- 3 quick single-rule attack scripts (port scan, SSH spray, HTTP flood)
- 94 unit tests covering all pipeline layers including injection and fuzzing
- Evaluation suite: 60-event dataset with precision/recall vs baseline
- AbuseIPDB top-50 real-world threat evaluation
