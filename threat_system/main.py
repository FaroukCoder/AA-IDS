"""
main.py — LLM-Orchestrated Network Threat Detection System

Usage:
    python -m threat_system.main --scenario attack
    python -m threat_system.main --scenario spike
    python -m threat_system.main --scenario benign
    python -m threat_system.main --scenario attack --active
    python -m threat_system.main --evaluate
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import time

from rich.console import Console

console = Console()


def _make_ip_event(ip: str):
    """Build a synthetic port-scan Event for a custom IP entered in the browser."""
    from .framework.models import Event
    import uuid
    return Event(
        event_id=f"evt_web_{uuid.uuid4().hex[:8]}",
        src_ip=ip,
        event_type="port_scan",
        ports_targeted=[22, 80, 443, 445, 3389],
        frequency=15,
        time_window_s=5.0,
        severity="high",
    )


def _run_pipeline_for_web(payload: dict) -> None:
    """Run the pipeline from a browser-triggered request.

    payload shapes:
        {"scenario": "attack" | "spike" | "benign"}
        {"ip": "1.2.3.4"}
        {"evaluate": True}
    """
    try:
        if payload.get("evaluate"):
            run_evaluation()
        elif payload.get("ip"):
            _run_single_ip(payload["ip"])
        else:
            run_pipeline(payload.get("scenario", "attack"))
    except Exception as exc:
        console.print(f"[red]Web-triggered run failed: {exc}[/red]")


def _run_single_ip(ip: str) -> None:
    """Run a single synthetic event for a custom IP through the full pipeline."""
    from .config.settings import settings
    settings.validate()

    from .visualizer import ws_server
    from .visualizer.ws_server import broadcast
    from .visualizer import narrator as narr
    from .framework.pipeline import ThreatPipeline
    from .framework import display

    event = _make_ip_event(ip)
    on_stage = _make_stage_handler(display, narr, broadcast)

    ws_server.run_started(event.event_id)
    pipeline = ThreatPipeline(policy_file="default_policy.json", on_stage_complete=on_stage)
    action = pipeline.run_event(event)
    ws_server.run_complete({
        "event_id":       event.event_id,
        "target":         event.src_ip,
        "final_action":   action.final_action,
        "classification": action.policy_decision,
        "confidence":     ws_server._current_confidence,
    })


def run_pipeline(scenario: str, active: bool = False) -> None:
    from .config.settings import settings
    settings.validate()

    from .visualizer import ws_server
    from .visualizer.ws_server import start_server, broadcast
    from .visualizer import narrator as narr
    start_server()
    ws_server.register_run_handler(_run_pipeline_for_web)

    from .simulator.scenarios import attack_scenario, spike_scenario, benign_scenario
    from .simulator.writer import write_scenario
    from .framework.sentinel import Sentinel
    from .framework.pipeline import ThreatPipeline
    from .framework import display

    on_stage = _make_stage_handler(display, narr, broadcast)

    scenarios = {
        "attack": attack_scenario,
        "spike": spike_scenario,
        "benign": benign_scenario,
    }
    if scenario not in scenarios:
        console.print(f"[red]Unknown scenario '{scenario}'. Choose: attack, spike, benign[/red]")
        sys.exit(1)

    console.print(f"[cyan]Running scenario: {scenario}[/cyan]")
    count = write_scenario(scenarios[scenario])
    console.print(f"[green]Wrote {count} log entries to logs/raw_traffic.jsonl[/green]")

    sentinel = Sentinel()
    log_path = os.path.join(os.path.dirname(__file__), "logs", "raw_traffic.jsonl")
    events = sentinel.process(log_path)

    if not events:
        console.print("[yellow]No events detected by Sentinel.[/yellow]")
        return

    console.print(f"[magenta]Sentinel detected {len(events)} event(s)[/magenta]")

    pipeline = ThreatPipeline(
        policy_file="default_policy.json",
        active_mode=active,
        on_stage_complete=on_stage,
    )

    for event in events:
        console.rule(f"Processing {event.event_id}")
        ws_server.run_started(event.event_id)
        action = pipeline.run_event(event)
        ws_server.run_complete({
            "event_id":      event.event_id,
            "target":        event.src_ip,
            "final_action":  action.final_action,
            "classification": action.policy_decision,
            "confidence":    ws_server._current_confidence,
        })


def _to_dict(obj) -> dict:
    """Safely convert any pipeline data object to a JSON-serialisable dict."""
    try:
        import dataclasses
        if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
            return dataclasses.asdict(obj)
    except Exception:
        pass
    if hasattr(obj, '__dict__'):
        return dict(obj.__dict__)
    return {}


def _make_live_stage_handler(broadcast_fn, narrator_mod):
    """Live mode handler: clean Rich terminal banners + web broadcast.

    No JSON panels, no thought bubbles — those stay in the web UI.
    """
    from .visualizer import ws_server
    from .framework import terminal_display as td

    state: dict = {"agent_count": 0, "agent_total": 4}

    def _on_stage(stage: str, data) -> None:
        try:
            if stage == "event":
                state["agent_count"] = 0
                td.render_event(data)
            elif stage == "dispatch":
                total = len(data.parallel_agents) + len(data.sequential_agents)
                state["agent_total"] = max(total, 1)
                td.render_dispatch(data.parallel_agents + data.sequential_agents)
            elif stage == "agent_report":
                state["agent_count"] += 1
                td.render_agent_result(data, state["agent_count"], state["agent_total"])
            elif stage == "investigator_result":
                ws_server.set_confidence(data.confidence)
                td.render_investigation(data)
            elif stage == "policy_result":
                td.render_policy(data)
            elif stage == "action_record":
                td.render_final_action(data)
        except Exception:
            pass  # terminal output is cosmetic — never crash the pipeline

        # Web broadcast unchanged — narration still flows to browser
        try:
            narration = narrator_mod.narrate(stage, data)
            broadcast_fn(stage, {"narration": narration or {}, "raw": _to_dict(data)})
        except Exception:
            pass

    return _on_stage


def _make_stage_handler(display_mod, narrator_mod, broadcast_fn):
    """Return a combined on_stage_complete callback."""
    from .visualizer import ws_server

    def _on_stage(stage: str, data) -> None:
        # 1. Existing rich display (unchanged)
        display_mod.render_stage(stage, data)
        # 2. Capture confidence from investigator result before narration
        if stage == "investigator_result" and hasattr(data, "confidence"):
            ws_server.set_confidence(data.confidence)
        # 3. Narrate
        narration = narrator_mod.narrate(stage, data)
        # 4. Terminal thought bubble
        if narration:
            display_mod.render_thought_bubble(narration)
        # 5. WebSocket broadcast
        try:
            broadcast_fn(stage, {
                "narration": narration or {},
                "raw": _to_dict(data),
            })
        except Exception:
            pass
    return _on_stage



def _build_attack_log(n_ips: int, seed: int) -> str:
    """Generate a temp JSONL with traffic from n_ips distinct IPs.

    Each IP sends 15 ports in 5 s, reliably triggering port_scan_rule
    (>10 unique ports in 10 s window).  Ports are drawn from a curated
    high-value attack pool that always includes the credential-access
    combo (22+445+3389) so Port Intel returns attack_pattern=
    'credential_access' regardless of reputation data availability.
    """
    import random
    import tempfile
    from datetime import datetime, timezone, timedelta

    # Credential-access anchors guaranteed in every scan.
    _ANCHOR_PORTS = [22, 445, 3389]
    # Additional high-value ports that signal purposeful reconnaissance.
    _RECON_POOL = [21, 23, 25, 80, 135, 139, 443, 1433, 3306, 5432, 5985, 8080]

    rng = random.Random(seed)
    base = datetime(2025, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
    # Public, routable IP ranges — avoids RFC-1918, loopback, link-local,
    # multicast, and RFC-5737 documentation ranges.
    first_octets = [45, 46, 47, 80, 82, 83, 84, 85, 86, 89,
                    91, 92, 93, 94, 95, 185, 188, 193, 194, 195]
    records = []
    for i in range(n_ips):
        first = first_octets[i % len(first_octets)]
        ip = f"{first}.{rng.randint(0, 255)}.{rng.randint(1, 254)}.{rng.randint(1, 254)}"
        t0 = base + timedelta(minutes=i * 2)
        # Always include credential-access anchors; fill remainder from recon pool.
        extra = rng.sample(_RECON_POOL, 15 - len(_ANCHOR_PORTS))
        ports = _ANCHOR_PORTS + extra
        rng.shuffle(ports)
        for j, port in enumerate(ports):
            ts = t0 + timedelta(milliseconds=j * 333)   # 15 ports in ~5 s
            records.append({
                "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "src_ip": ip,
                "dst_port": port,
                "protocol": "TCP",
                "status": "SYN",
            })

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    )
    for r in records:
        tmp.write(json.dumps(r) + "\n")
    tmp.close()
    return tmp.name


# Known-clean public IPs (DNS resolvers / large trusted providers).
# AbuseIPDB scores for these are near 0; WHOIS shows legitimate orgs.
_BENIGN_IPS = [
    "8.8.8.8",        "8.8.4.4",          # Google Public DNS
    "1.1.1.1",        "1.0.0.1",          # Cloudflare DNS
    "208.67.222.222", "208.67.220.220",   # OpenDNS
    "9.9.9.9",        "149.112.112.112",  # Quad9
    "64.6.64.6",      "64.6.65.6",        # Verisign
    "185.228.168.9",  "185.228.169.9",    # CleanBrowsing
    "76.76.19.19",    "76.223.122.150",   # Alternate DNS
    "94.140.14.14",   "94.140.15.15",     # AdGuard
    "216.146.35.35",  "216.146.36.36",    # Dyn DNS
    "198.101.242.72", "23.253.163.53",    # Alternate DNS
]


def _build_benign_events(n: int, seed: int) -> list:
    """Synthetic benign Event objects from known-clean IPs.

    Severity is always 'low' so the severity-based baseline and the
    LLM alike should classify these as non-threatening.
    """
    import random
    from .framework.models import Event

    rng = random.Random(seed + 9999)
    ips = (_BENIGN_IPS * ((n // len(_BENIGN_IPS)) + 1))[:n]
    events = []
    for i, ip in enumerate(ips):
        ports = rng.sample([80, 443, 8080], rng.randint(1, 2))
        events.append(Event(
            event_id=f"evt_benign_{i + 1:04d}",
            src_ip=ip,
            event_type="port_scan",
            ports_targeted=ports,
            frequency=rng.randint(2, 5),
            time_window_s=rng.uniform(8.0, 10.0),
            severity="low",
        ))
    return events


def run_evaluation() -> None:
    from .config.settings import settings
    settings.validate()

    from .visualizer import ws_server
    from .visualizer.ws_server import start_server, broadcast
    from .visualizer import narrator as narr
    from .framework import display
    start_server()
    ws_server.register_run_handler(_run_pipeline_for_web)
    on_stage = _make_stage_handler(display, narr, broadcast)

    from .framework.sentinel import Sentinel
    from .framework.pipeline import ThreatPipeline

    console.print("[cyan]Starting 60-event evaluation (seed=42)...[/cyan]")

    import random
    rng = random.Random(42)

    # --- Build dataset ---
    # Attack: 40 distinct IPs, each reliably triggers port_scan_rule
    attack_log = _build_attack_log(n_ips=40, seed=42)
    sentinel = Sentinel()
    attack_events = sentinel.process(attack_log)
    os.unlink(attack_log)
    attack_events = attack_events[:40]

    # Benign: 20 synthetic events from known-clean public IPs
    benign_events = _build_benign_events(n=20, seed=42)

    console.print(
        f"[green]Dataset built: {len(attack_events)} attack events, "
        f"{len(benign_events)} benign events[/green]"
    )

    all_events = [(e, True) for e in attack_events] + [(e, False) for e in benign_events]
    rng.shuffle(all_events)

    pipeline = ThreatPipeline(policy_file="default_policy.json", on_stage_complete=on_stage)

    tp = fp = tn = fn = 0
    latencies: list[float] = []
    policy_overrides = 0
    baseline_tp = baseline_fp = baseline_tn = baseline_fn = 0

    for event, is_attack in all_events:
        ws_server.run_started(event.event_id)
        start = time.time()
        action = pipeline.run_event(event)
        latency = time.time() - start
        latencies.append(latency)
        ws_server.run_complete({
            "event_id":      event.event_id,
            "target":        event.src_ip,
            "final_action":  action.final_action,
            "classification": action.policy_decision,
            "confidence":    ws_server._current_confidence,
        })

        llm_blocked = action.final_action in {"block_ip", "alert_admin", "escalate_human"}
        if action.policy_decision in {"DOWNGRADE", "BLOCK"}:
            policy_overrides += 1

        if is_attack and llm_blocked:
            tp += 1
        elif not is_attack and llm_blocked:
            fp += 1
        elif not is_attack and not llm_blocked:
            tn += 1
        else:
            fn += 1

        # Baseline: severity-threshold rule — high/medium = attack, low = benign
        baseline_blocked = event.severity in {"high", "medium"}
        if is_attack and baseline_blocked:
            baseline_tp += 1
        elif not is_attack and baseline_blocked:
            baseline_fp += 1
        elif not is_attack and not baseline_blocked:
            baseline_tn += 1
        else:
            baseline_fn += 1

    total = len(all_events)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

    b_precision = baseline_tp / (baseline_tp + baseline_fp) if (baseline_tp + baseline_fp) > 0 else 0.0
    b_recall = baseline_tp / (baseline_tp + baseline_fn) if (baseline_tp + baseline_fn) > 0 else 0.0
    b_fpr = baseline_fp / (baseline_fp + baseline_tn) if (baseline_fp + baseline_tn) > 0 else 0.0

    report = {
        "total_events": total,
        "llm_pipeline": {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "false_positive_rate": round(fpr, 4),
            "avg_latency_s": round(avg_latency, 3),
            "policy_overrides": policy_overrides,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        },
        "rule_baseline": {
            "precision": round(b_precision, 4),
            "recall": round(b_recall, 4),
            "false_positive_rate": round(b_fpr, 4),
            "avg_latency_s": 0.0,
            "policy_overrides": 0,
            "tp": baseline_tp, "fp": baseline_fp, "tn": baseline_tn, "fn": baseline_fn,
        },
    }

    docs_dir = os.path.join(os.path.dirname(__file__), "docs")
    os.makedirs(docs_dir, exist_ok=True)
    report_path = os.path.join(docs_dir, "evaluation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    console.print(f"[green]Evaluation complete. Report saved to {report_path}[/green]")

    from .framework.display import render_evaluation_table
    render_evaluation_table(report_path)


def main() -> None:
    parser = argparse.ArgumentParser(description="LLM-Orchestrated Network Threat Detection System")
    parser.add_argument("--scenario", choices=["attack", "spike", "benign"], default="attack",
                        help="Traffic scenario to simulate")
    parser.add_argument("--active", action="store_true", help="Enable active mode (append to blocked_ips.txt)")
    parser.add_argument("--evaluate", action="store_true", help="Run 60-event evaluation")
    args = parser.parse_args()

    if args.evaluate:
        run_evaluation()
    else:
        run_pipeline(args.scenario, active=args.active)


if __name__ == "__main__":
    main()
