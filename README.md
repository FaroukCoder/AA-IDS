# AA-IDS — LLM-Orchestrated Network Threat Detection

Multi-agent AI system that detects and classifies network threats in real time.

**Pipeline:** Sentinel (rule engine) → Orchestrator (LLM) → Specialist agents (WHOIS, DNS, Port Intel, Reputation) → Policy Agent → Executor

**Stack:** Python 3.11 · Anthropic SDK (claude-sonnet-4-6) · Scapy · Rich · pytest

---

## Quick Start — Scenario Mode (no Docker needed)

```bash
pip install -r requirements.txt

# Copy and fill in your API keys
cp threat_system/config/.env.example threat_system/config/.env

# Run a simulated attack scenario
py -m threat_system.main --scenario attack

# Or open the browser dashboard first, then trigger runs from the UI
py -m threat_system.server
# → open http://localhost:8765
```

---

## Live Mode — Docker Attack Simulation

Replaces the simulator with real network traffic: a Kali attacker container
attacks an Ubuntu victim container, Scapy captures packets, and the pipeline
responds in real time.

### Prerequisites

- Docker Desktop installed and running
- API keys configured in `threat_system/config/.env`

### Step 1: Start the Docker environment

```bash
docker-compose -f docker/docker-compose.yml up -d
```

### Step 2: Verify containers are running

```bash
docker ps
# Should show: threat-lab-attacker and threat-lab-victim
```

### Step 3: Start the live pipeline watcher

```bash
py -m threat_system.live
# Opens browser dashboard at http://localhost:8765
# Watches logs/live_traffic.jsonl for real packet data
```

### Step 4: Launch an attack (separate terminal)

```bash
# Individual attacks
python docker/run_attack.py --attack port_scan
python docker/run_attack.py --attack traffic_spike
python docker/run_attack.py --attack brute_force

# Run all three sequentially with 5 s pauses
python docker/run_attack.py --attack all
```

### Step 5: Watch the pipeline respond

Terminal running `live.py` shows rich output as each event is processed.
Browser at http://localhost:8765 shows the live decision tree.

Expected events:
- `port_scan` — fired by port_scan.py (>10 unique ports / 10 s)
- `traffic_spike` — fired by traffic_spike.py (>100 requests / 10 s)
- `failed_conn` — fired by brute_force.py (>20 failed SSH / 30 s)

### Teardown

```bash
docker-compose -f docker/docker-compose.yml down
```

---

## Network Layout

```
172.20.0.0/24  (threat-lab bridge network)
├── 172.20.0.10  victim   — nginx:80, sshd:22, capture.py (Scapy sniffer)
└── 172.20.0.20  attacker — port_scan.py, traffic_spike.py, brute_force.py
```

Shared volume: `./threat_system/logs/` ↔ `/logs/` in both containers.
`capture.py` writes to `/logs/live_traffic.jsonl`; `live.py` reads from there.

---

## Project Structure

```
threat_system/
├── agents/          LLM specialist agents (WHOIS, DNS, PortIntel, Reputation)
├── config/          Settings, policy files, .env
├── framework/       Sentinel, ThreatPipeline, BaseAgent, models
├── logs/            Runtime output (gitignored)
├── prompts/         .txt prompt templates
├── simulator/       Synthetic scenario generator (no Docker needed)
├── skills/          .md domain guidelines loaded at runtime
├── tests/           pytest test suite
├── tools/           Raw data fetchers (WHOIS, DNS, AbuseIPDB)
├── visualizer/      Browser dashboard (WebSocket + static HTML/JS)
├── live.py          Live mode entry point
├── main.py          Scenario mode entry point
└── server.py        Dashboard-only server

docker/
├── docker-compose.yml
├── run_attack.py    Convenience launcher
├── attacker/        Kali container + attack scripts
└── victim/          Ubuntu container + Scapy capture
```

---

## Running Tests

```bash
py -m pytest threat_system/tests/ -v
```

All tests use mocked tool calls — no API key required to run the test suite.
