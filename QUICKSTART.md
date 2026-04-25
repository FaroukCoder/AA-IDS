# AA-IDS Quick Start Guide

## Prerequisites

| Requirement | Version | Check |
|---|---|---|
| Python | 3.11+ | `python --version` |
| Docker Desktop | 24+ | `docker --version` |
| Anthropic API key | — | stored in `config/.env` |

---

## First-Time Setup

### 1. Configure API key

```
config/.env
```
```
ANTHROPIC_API_KEY=sk-ant-...
```

### 2. Install Python dependencies

```bash
cd C:\Users\youss\Desktop\AA-IDS
pip install -r requirements.txt
```

### 3. Build Docker containers (once)

```bash
cd docker
docker compose build
```

---

## Every-Session Startup (in order)

### Step 1 — Start Docker containers

```bash
cd C:\Users\youss\Desktop\AA-IDS\docker
docker compose up -d
```

Verify both containers are running:
```bash
docker ps
```
Expected output includes:
```
threat-lab-victim    Up ...
threat-lab-attacker  Up ...
```

### Step 2 — Start the live pipeline

Open a **dedicated terminal** and keep it open the entire session:

```bash
cd C:\Users\youss\Desktop\AA-IDS
python -m threat_system.live
```

Wait for this output before proceeding:
```
  Visualizer -> http://localhost:8765

  WebSocket   -> ws://localhost:8766
```

> **CRITICAL — Port conflict warning**
> If you see `WebSocket FAILED to bind port 8766` or the line never appears,
> another process holds the port. Kill it first:
> ```
> netstat -ano | findstr :8766
> taskkill /PID <pid> /F
> ```
> Then restart `live.py`. If `_ws_loop` never binds, **zero messages reach the browser**.

### Step 3 — Open the UI

Navigate to: `http://localhost:8765`

You should see the **D1 idle scene** (detective desk video loop).

---

## Running an Attack

Open a **second terminal** (leave `live.py` running in the first):

```bash
cd C:\Users\youss\Desktop\AA-IDS
python docker/run_attack.py --attack port_scan
```

Available attack types:
- `port_scan` — SYN sweep across common ports
- `brute_force` — SSH credential stuffing
- `traffic_spike` — HTTP flood

> `live.py` must be started **before** you run the attack. Sentinel watches from
> the tail of `live_traffic.jsonl` — traffic written before watch started is ignored.

---

## What to Expect in the UI

### During a run (D1 scene)

| Element | What happens |
|---|---|
| **Monologue panel** (bottom-left) | Slides in; narration lines stream in as each agent fires |
| **Agent portraits** (right side) | Icons appear when an agent is dispatched; glow gold when complete |

### After a run completes

- Monologue and portraits fade out ~4 seconds after `run_complete`
- Navigate to **D2** (right arrow) → new case card appears at top of the cabinet

### D2 cabinet card fields

| Field | Source |
|---|---|
| Event ID | `live_NNNN` |
| Target IP | Attacker container (`172.20.0.20`) |
| Classification | `ATTACK` / `BENIGN` / `ALLOW` |
| Confidence | 0–100% |

Click a card → D2→D3 transition → full case detail view.

---

## Scene Navigation

| Key | Action |
|---|---|
| Hover right edge | Forward arrow (D1→D2→D3) |
| Hover left edge | Back arrow (D3→D2→D1) |

Navigation is blocked while a transition video plays.

---

## Troubleshooting

### Nothing appears on D1 during a run

1. Check `live.py` terminal — look for `[pipeline]` log lines confirming a run started
2. Open browser DevTools → Console → look for `[WS]` messages
3. Verify WS connected: `[WS] connected` should appear on page load
4. If `[WS] disconnected` or no connect message — port 8766 conflict (see above)

### Cabinet is empty after a run

- Open browser DevTools → Network → filter `history` → confirm `/api/history` returns data
- If yes: hard-refresh the page (`Ctrl+Shift+R`) to clear JS cache
- If no: `live.py` didn't record the run — check its terminal for errors

### Attack finishes instantly with no pipeline output

- Sentinel seeks to the **end** of `live_traffic.jsonl` on start
- If Docker containers were already running when you started `live.py`, traffic from before that point is ignored — this is normal
- Run a fresh attack **after** `live.py` is fully started

### Ports already in use on Windows

```bash
# Find what holds 8765 or 8766
netstat -ano | findstr :8765
netstat -ano | findstr :8766

# Kill by PID
taskkill /PID <pid> /F
```

---

## Clean Shutdown

```bash
# Stop Docker containers
cd C:\Users\youss\Desktop\AA-IDS\docker
docker compose down

# live.py — Ctrl+C in its terminal
```
