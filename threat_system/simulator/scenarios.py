from __future__ import annotations
import random
from datetime import datetime, timedelta, timezone

from ..framework.models import Event


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# Credential-access anchors always included so PortIntelAgent detects the pattern.
_ANCHOR_PORTS = [22, 445, 3389]
_RECON_POOL   = [21, 23, 25, 80, 135, 139, 443, 1433, 3306, 5432, 5985, 8080]


def attack_scenario(seed: int = 42) -> list[dict]:
    """Port scan from a confirmed Tor exit node (185.220.101.1).
    AbuseIPDB: 100% abuse score, 134 reports — produces a genuinely malicious verdict.

    15 ports at 333ms spacing → fires port_scan only (not traffic_spike or failed_conn).
    Always includes 22/445/3389 so PortIntelAgent detects the credential-access pattern.
    """
    rng    = random.Random(seed)
    base   = datetime(2025, 4, 1, 10, 0, 0, tzinfo=timezone.utc)
    src_ip = "185.220.101.1"

    extra = rng.sample(_RECON_POOL, 15 - len(_ANCHOR_PORTS))
    ports = _ANCHOR_PORTS + extra
    rng.shuffle(ports)

    records = []
    for j, port in enumerate(ports):
        ts = base + timedelta(milliseconds=j * 333)   # 15 ports in ~5s
        records.append({
            "timestamp": _iso(ts),
            "src_ip":    src_ip,
            "dst_port":  port,
            "protocol":  "TCP",
            "status":    "SYN",
        })

    return records


def spike_scenario(seed: int = 42) -> list[dict]:
    """Traffic spike from a known scanner IP (194.169.223.26).
    Triggers traffic_spike rule only — fixed dst_port prevents port_scan from firing."""
    rng    = random.Random(seed)
    base   = datetime(2025, 4, 1, 11, 0, 0, tzinfo=timezone.utc)
    src_ip = "194.169.223.26"
    records = []

    for i in range(500):
        offset_ms = i * rng.randint(5, 15)
        ts = base + timedelta(milliseconds=offset_ms)
        records.append({
            "timestamp": _iso(ts),
            "src_ip":    src_ip,
            "dst_port":  rng.choice([80, 443, 8080, 8443]),  # fixed set — no port_scan
            "protocol":  "TCP",
            "status":    "ESTABLISHED",  # no SYN — prevents failed_conn rule from firing
        })

    return records


def benign_scenario(_seed: int = 42) -> list[dict]:
    """Web-port sweep from 8.8.8.8 (Google LLC, AbuseIPDB 0%).
    Triggers Sentinel port_scan rule but LLM classifies as log_only:
    zero abuse history, web-only ports, no credential-access pattern."""
    base = datetime(2025, 4, 1, 12, 0, 0, tzinfo=timezone.utc)
    src_ip = "8.8.8.8"
    # 15 web/API ports — no SSH/SMB/RDP credential-access combo
    ports = [80, 443, 8080, 8443, 3000, 3001, 4000, 5000, 5173, 8000, 9000, 9200, 9300, 9090, 4200]
    records = []

    for i, port in enumerate(ports):
        ts = base + timedelta(milliseconds=i * 533)   # 15 ports spread over ~8 s
        records.append({
            "timestamp": _iso(ts),
            "src_ip": src_ip,
            "dst_port": port,
            "protocol": "TCP",
            "status": "SYN",
        })

    return records


def demo_scenario() -> Event:
    return Event(
        event_id="evt_demo_001",
        src_ip="192.168.99.1",
        event_type="port_scan",
        ports_targeted=[22, 80, 443],
        frequency=15,
        time_window_s=8.0,
        severity="medium",
    )
