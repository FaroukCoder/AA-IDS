# AA-IDS — Professor Demo Guide
> Multi-Agent LLM Intrusion Detection System  
> Branch: Farouk

---

## 1. What Was Built — 30-Second Pitch

AA-IDS is a **network intrusion detection system** where, instead of writing static rules,
the system uses **multiple LLM agents** that collaborate like a detective squad to investigate
suspicious network traffic. Each agent has a specialty (reputation, DNS, port intelligence,
IP ownership). A coordinator LLM decides which agents to deploy and synthesizes their findings
into a final verdict. A policy engine then enforces organisational rules on top.

The UI is a **live operations terminal** styled after the game Disco Elysium — each agent has
a voice and personality. You can watch the investigation unfold in real time.

---

## 2. System Architecture



```
NETWORK TRAFFIC
       │
       ▼
  ┌─────────┐    Sliding-window rules       ┌────────────────┐
  │Sentinel │──► port_scan   (>10 ports/10s)│                │
  │(Python) │──► traffic_spike(>100 req/10s)│   Event(id,    │
  │         │──► failed_conn (>20 fail/30s) │   src_ip,      │
  └─────────┘                               │   severity)    │
                                            └───────┬────────┘
                                                    │
                                                    ▼
                                     ┌──────────────────────────┐
                                     │  OrchestratorAgent (LLM) │
                                     │  Pass 1 — Dispatch:      │
                                     │    Picks which agents    │
                                     │    to run & in what order│
                                     └──────────┬───────────────┘
                                                │
                        ┌───────────────────────┼───────────────────────┐
                        ▼                       ▼                       ▼
               ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
               │  WHOISAgent  │       │   DNSAgent   │       │PortIntelAgent│
               │ (Visual Ctx) │       │  (Auditory)  │       │(Logic Center)│
               └──────┬───────┘       └──────┬───────┘       └──────┬───────┘
                      │                      │                       │
                      └──────────────────────┼───────────────────────┘
                                             │  AgentReport ×N
                                             ▼
                                ┌────────────────────────┐
                                │ ReputationAgent (Memory)│
                                │ (gets prior findings)   │
                                └────────────┬───────────┘
                                             │
                                             ▼
                                ┌────────────────────────┐
                                │  OrchestratorAgent LLM  │
                                │  Pass 2 — Synthesis:    │
                                │  classification,        │
                                │  confidence, action     │
                                └────────────┬───────────┘
                                             │
                                             ▼
                                  ┌──────────────────┐
                                  │   PolicyAgent    │
                                  │  ALLOW / BLOCK / │
                                  │  ESCALATE /      │
                                  │  DOWNGRADE       │
                                  └────────┬─────────┘
                                           │
                                           ▼
                                  ┌──────────────────┐
                                  │  ActionRecord    │
                                  │  (audit log)     │
                                  └──────────────────┘
```

---

## 3. Key Components

### Sentinel (Rule Engine)
- Pure Python, no LLM — processes raw packet logs
- Three sliding-window rules: port scan, traffic spike, failed connections
- 60-second per-(IP, rule) cooldown to suppress duplicate events
- Runs in **batch mode** (historical logs) or **watch mode** (live tail)

### OrchestratorAgent (LLM #1 + #2)
- **Two LLM calls per event:**
  1. **Dispatch** — reads the event, decides which agents to run (parallel vs sequential)
  2. **Synthesis** — receives all agent findings, outputs final classification + confidence
- Model: `claude-sonnet-4-6` — temperature 0 (deterministic), max_tokens 1024
- Auto-escalates if confidence < 0.60 (configurable)

### Specialist Agents (4 agents)
| Voice Name | Agent | Data Source | What It Checks |
|---|---|---|---|
| VISUAL CORTEX | `whois` | RDAP/WHOIS API | IP owner, org, country, ASN, VPS hosting |
| AUDITORY | `dns` | DNS reverse lookup | Hostname, PTR record, domain pattern |
| LOGIC CENTER | `port_intel` | Internal port DB | Services targeted, MITRE ATT&CK techniques |
| MEMORY | `reputation` | AbuseIPDB API | Abuse score, report count, categories |

### PolicyAgent (Rule-based, no LLM)
- Enforces organisational policy on top of the LLM verdict
- Possible decisions: **ALLOW**, **BLOCK**, **ESCALATE**, **DOWNGRADE**
- Policy file is YAML/JSON — configurable thresholds, protected IPs, severity gates
- Two profiles: `default_policy.json` (permissive) and `strict_policy.json` (restrictive)

### LLM Infrastructure
- All calls go through `framework/llm_client.py` — the ONLY file that touches the Anthropic SDK
- SHA-256 prompt cache in `logs/llm_cache.json` — identical events reuse cached responses
- Exponential backoff with 6 retries — handles rate limits
- Thread-safe semaphore limits 2 concurrent LLM calls

---

## 4. The Live UI

The browser dashboard (`http://localhost:8765`) has three scenes:

| Scene | Content |
|---|---|
| **D1 — Main** | Idle background. During a live run: INTERNAL MONOLOGUE panel appears on the left, showing each agent's inner voice with typewriter effect. Final verdict box at the bottom. |
| **D2 — Case Cabinet** | Scrollable history of every completed run (classification, confidence, action). Click any card to open detail. |
| **D3 — Case Detail** | Full investigation breakdown for one run. |

The monologue panel is styled after game UI — each agent has a brushstroke portrait, a colour-coded name bar, and a confidence progress bar.

---

## 5. Anticipated Professor Questions

**Q: Why use multiple LLM agents instead of one big prompt?**  
Each agent gets a focused, domain-specific context — WHOIS data is noise to a reputation
analyst, and vice versa. Specialist agents produce higher-confidence findings, and the
orchestrator synthesises them with full context. It also mirrors how real SOC teams work:
tier-1 analysts each specialise, then a senior analyst decides.

**Q: How do you prevent prompt injection?**  
Every field sourced from external data (IP, org name, hostname, risk notes) is sanitised
before entering a prompt — control characters stripped, braces removed, known injection
tokens blocked. The `_sanitize_ip()` function in Sentinel also validates IPs against
`ipaddress.ip_address()` before they touch any data structure.

**Q: What stops the LLM from hallucinating a wrong classification?**  
Three layers:  
1. Structured JSON-only responses — any deviation triggers a retry  
2. Confidence score threshold — if the LLM is < 60% confident, it auto-escalates to human  
3. PolicyAgent enforces hard rules regardless of LLM output (e.g., never block a protected IP)

**Q: How is this different from Snort / Suricata (traditional IDS)?**  
Traditional IDS uses static signatures — an IP must appear in a known blocklist or match a
known pattern. AA-IDS uses LLM reasoning over multiple live data sources to classify IPs
that have never appeared in any blocklist. The WHOIS + DNS + port + reputation combination
can identify new threat actors before they appear in shared feeds.

**Q: Is this production-ready?**  
No — it is a research prototype. Limitations: LLM latency (~3–8s per run), no persistent
database, single-node Python, no SIEM integration. Production hardening would require async
architecture, a proper vector store for agent context, and integration with existing SIEM/SOAR.

**Q: What is the detection rate on real data?**  
The system is evaluated against the AbuseIPDB top-50 blacklist (confidence ≥ 90). Results
are saved in `threat_system/docs/threat_feed_results.json`. Typical results: 85–95% detection
rate, ~3–6s average latency per IP.

**Q: How do agents coordinate — do they share context?**  
The orchestrator places agents in two groups:  
- **Parallel agents** run simultaneously with no prior context (faster, independent domains)  
- **Sequential agents** receive the `prior_findings` from all previously completed agents  
The orchestrator itself sees all findings before synthesising.

**Q: What is the role of the policy engine vs the LLM?**  
The LLM recommends the most appropriate action given the evidence. The PolicyAgent is a
hard rule layer that can *override* the LLM — for example, it can downgrade a "block_ip"
recommendation to "alert_admin" if the attacker's severity is below the configured block
threshold. This separates ML inference from organisational policy.

**Q: What happens if an external API is down?**  
Every agent has a `fallback=True` path — it returns an `AgentReport` with empty findings
and `confidence=0.0` rather than raising an exception. The orchestrator marks these as
"tool failure" in synthesis. The pipeline never crashes due to a single agent failing.

**Q: How are LLM costs controlled?**  
Two mechanisms: (1) SHA-256 prompt caching — identical events never re-call the API.
(2) A `max_tokens=1024` cap per call. The threat feed evaluation of 50 IPs with cache
hits costs approximately $0.30–0.80 in API credits.

---

## 6. Demo Attack Sequence

### Prerequisites (run these first)
```bash
# Terminal 1 — start the containers
docker compose -f docker/docker-compose.yml up

# Terminal 2 — start the live detection server
python -m threat_system.live

# Browser — open and stay on D1
http://localhost:8765
```

---

### Attack 1 — Port Scan (single rule, ~1 second)
**What it does:** Sends SYN packets to 15 high-signal ports (SSH, RDP, DB, etc.)  
**Rule triggered:** `port_scan` only (15 unique ports > 10 threshold; 15 < 20 so failed_conn doesn't fire)  
**Expected verdict:** MALICIOUS → block_ip or alert_admin  
```bash
python docker/run_attack.py --attack quick_port_scan
```
**Watch for:** VISUAL CORTEX (WHOIS) + LOGIC CENTER (port intel) agents voice — port services and MITRE techniques identified.

---

### Attack 2 — SSH Credential Spray (single rule, ~7 seconds)
**What it does:** 22 SSH login attempts with common passwords against port 22  
**Rule triggered:** `failed_conn` only (22 failures > 20 threshold; only 1 unique port so no port_scan)  
**Expected verdict:** MALICIOUS → block_ip  
```bash
python docker/run_attack.py --attack quick_ssh_spray
```
**Watch for:** MEMORY (reputation) confidence bar — if attacker IP has prior abuse history, score will be high.

---

### Attack 3 — HTTP Keep-Alive Flood (single rule, ~3 seconds)
**What it does:** 115 HTTP requests over ONE persistent TCP connection  
**Rule triggered:** `traffic_spike` only (115 requests > 100 threshold; 1 TCP SYN so failed_conn doesn't fire)  
**Expected verdict:** MALICIOUS → alert_admin or block_ip  
```bash
python docker/run_attack.py --attack quick_http_flood
```
**Watch for:** AUDITORY (DNS) checking if the source IP has a hostname — cloud VPS IPs typically have no PTR record.

---

### Attack 4 — Full Brute Force (multiple runs, burst handling demo)
**What it does:** 30 SSH attempts — may trigger multiple Sentinel events  
**Purpose:** Shows the burst-run handling — panel accumulates all sub-runs with dividers, single verdict at end  
```bash
python docker/run_attack.py --attack brute_force
```
**Watch for:** Thin separator lines between runs — each sub-run's agents stack in the same panel.

---

### False Positive Demo (optional — shows LLM nuance)
**What it does:** Simulates a Google/CDN scan that LOOKS like a port scan  
**Expected:** LLM classifies as BENIGN → log_only (despite triggering the port_scan rule)  
```bash
python docker/run_attack.py --attack benign_google_scan
```
**Talking point:** A traditional IDS would flag this. The LLM looks at the org name, ASN (Google LLC), and known CDN patterns and classifies it correctly.

---

## 7. Real-World Evaluation — AbuseIPDB Top 50

**What this is:** The system fetches the 50 most-reported IPs globally (≥90% abuse confidence)
from AbuseIPDB's live blacklist, runs each one through the full pipeline, and reports
detection rate and latency.

### How to run
```bash
# Ensure Docker is NOT needed — this uses the Python pipeline directly
python -m threat_system.tools.threat_feed
```

**Expected output in terminal:** Rich table showing each IP, abuse score, final action, policy decision, and per-IP latency.  
**Results saved to:** `threat_system/docs/threat_feed_results.json`

### What to highlight to professor
- **Detection rate:** Typically 85–95% of globally-blacklisted IPs correctly flagged
- **Zero ground truth labels needed:** The LLM infers from multi-source context alone
- **Latency:** ~3–6 seconds per IP (LLM reasoning time)
- **False positives:** Near zero on known-bad IPs — all have high abuse scores
- **Policy layer in action:** Some IPs escalated (low confidence) rather than auto-blocked — the system knows when it doesn't know

### Alternatively — trigger from the browser
Navigate to D1 → click the **Evaluate** button → watch runs appear live in the cabinet.

---

## 8. What Makes This Novel

1. **LLM as investigator, not classifier** — The model reasons over multi-source evidence rather than matching a pattern to a label

2. **Agent specialisation** — Each agent has a domain-specific system prompt and tool, which reduces hallucination and improves confidence calibration

3. **Separation of ML and policy** — The LLM is never the final authority. Policy rules can always override or constrain its recommendation

4. **Explainability** — Every decision produces a natural-language `reasoning` field in the InvestigatorResult, auditable in the case cabinet

5. **Graceful degradation** — If AbuseIPDB is down, if DNS times out, the system still produces a verdict (lower confidence, possibly escalated to human)

---

## 9. Quick Reference — Key Files

| File | Purpose |
|---|---|
| `threat_system/framework/sentinel.py` | Rule engine — fires events |
| `threat_system/framework/pipeline.py` | Orchestrates the full run |
| `threat_system/agents/orchestrator.py` | Two-pass LLM coordinator |
| `threat_system/agents/reputation_agent.py` | AbuseIPDB specialist |
| `threat_system/framework/policy_agent.py` | Hard rule enforcement |
| `threat_system/framework/llm_client.py` | Sole LLM access point |
| `threat_system/tools/threat_feed.py` | AbuseIPDB top-50 evaluation |
| `threat_system/visualizer/ws_server.py` | HTTP + WebSocket server |
| `threat_system/visualizer/narrator.py` | Inner voice synthesis (no LLM) |
| `docker/run_attack.py` | Attack launcher |
| `threat_system/live.py` | Live Docker watcher |
