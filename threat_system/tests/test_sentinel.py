"""Tests for Sentinel detection rules using synthetic log fixtures."""
from __future__ import annotations
import json
import os
import tempfile
import pytest

from ..framework.sentinel import Sentinel
from ..framework.models import Event


def _write_log(records: list[dict]) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8")
    for rec in records:
        tmp.write(json.dumps(rec) + "\n")
    tmp.close()
    return tmp.name


def _ts(base_s: float, offset_ms: int) -> str:
    from datetime import datetime, timezone, timedelta
    dt = datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=base_s, milliseconds=offset_ms)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- Rule 1: port scan ---

def test_port_scan_rule_triggers():
    records = [
        {"timestamp": _ts(0, i * 100), "src_ip": "10.0.0.1", "dst_port": 20 + i, "protocol": "TCP", "status": "SYN"}
        for i in range(15)  # 15 unique ports within 10s
    ]
    log = _write_log(records)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        port_scan_events = [e for e in events if e.event_type == "port_scan"]
        assert len(port_scan_events) >= 1
        assert port_scan_events[0].src_ip == "10.0.0.1"
    finally:
        os.unlink(log)


def test_port_scan_rule_does_not_trigger_below_threshold():
    records = [
        {"timestamp": _ts(0, i * 100), "src_ip": "10.0.0.2", "dst_port": 20 + i, "protocol": "TCP", "status": "SYN"}
        for i in range(5)  # Only 5 unique ports — below threshold of 10
    ]
    log = _write_log(records)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        port_scan_events = [e for e in events if e.event_type == "port_scan"]
        assert len(port_scan_events) == 0
    finally:
        os.unlink(log)


# --- Rule 2: traffic spike ---

def test_traffic_spike_rule_triggers():
    records = [
        {"timestamp": _ts(0, i * 50), "src_ip": "10.0.0.3", "dst_port": 80, "protocol": "TCP", "status": "SYN"}
        for i in range(150)  # 150 requests within ~7.5s
    ]
    log = _write_log(records)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        spike_events = [e for e in events if e.event_type == "traffic_spike"]
        assert len(spike_events) >= 1
        assert spike_events[0].frequency > 100
    finally:
        os.unlink(log)


def test_traffic_spike_rule_does_not_trigger_benign():
    records = [
        {"timestamp": _ts(0, i * 2000), "src_ip": "10.0.0.4", "dst_port": 443, "protocol": "TCP", "status": "ESTABLISHED"}
        for i in range(20)  # 20 requests spread over 40s
    ]
    log = _write_log(records)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        spike_events = [e for e in events if e.event_type == "traffic_spike"]
        assert len(spike_events) == 0
    finally:
        os.unlink(log)


# --- Rule 3: failed connections ---

def test_failed_conn_rule_triggers():
    records = [
        {"timestamp": _ts(0, i * 500), "src_ip": "10.0.0.5", "dst_port": 22 + (i % 10), "protocol": "TCP", "status": "SYN"}
        for i in range(25)  # 25 SYN connections within 12.5s (< 30s window)
    ]
    log = _write_log(records)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        failed_events = [e for e in events if e.event_type == "failed_connections"]
        assert len(failed_events) >= 1
    finally:
        os.unlink(log)


def test_benign_traffic_produces_no_events():
    ips = [f"192.168.1.{i}" for i in range(2, 12)]
    import random
    rng = random.Random(99)
    records = []
    for i in range(200):
        records.append({
            "timestamp": _ts(i * 30, 0),  # 1 request every 30s per IP
            "src_ip": rng.choice(ips),
            "dst_port": rng.choice([80, 443, 22]),
            "protocol": "TCP",
            "status": "ESTABLISHED",
        })
    log = _write_log(records)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        assert len(events) == 0
    finally:
        os.unlink(log)


# --- Boundary conditions ---

def test_port_scan_exactly_at_threshold_does_not_trigger():
    """Exactly 10 unique ports (== threshold) must NOT fire — rule is >10, not >=10."""
    records = [
        {"timestamp": _ts(0, i * 100), "src_ip": "10.1.0.1", "dst_port": 20 + i, "protocol": "TCP", "status": "SYN"}
        for i in range(10)  # exactly 10 unique ports
    ]
    log = _write_log(records)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        port_scan_events = [e for e in events if e.event_type == "port_scan"]
        assert len(port_scan_events) == 0
    finally:
        os.unlink(log)


def test_port_scan_one_above_threshold_triggers():
    """11 unique ports (threshold + 1) must fire port_scan."""
    records = [
        {"timestamp": _ts(0, i * 100), "src_ip": "10.1.0.2", "dst_port": 20 + i, "protocol": "TCP", "status": "SYN"}
        for i in range(11)  # 11 unique ports
    ]
    log = _write_log(records)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        port_scan_events = [e for e in events if e.event_type == "port_scan"]
        assert len(port_scan_events) >= 1
    finally:
        os.unlink(log)


def test_traffic_spike_boundary():
    """101 requests in 10s must fire; 100 must not."""
    # 100 requests — must NOT trigger
    records_100 = [
        {"timestamp": _ts(0, i * 50), "src_ip": "10.1.0.3", "dst_port": 80, "protocol": "TCP", "status": "SYN"}
        for i in range(100)
    ]
    log = _write_log(records_100)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        assert len([e for e in events if e.event_type == "traffic_spike"]) == 0
    finally:
        os.unlink(log)

    # 101 requests — must trigger
    records_101 = [
        {"timestamp": _ts(0, i * 50), "src_ip": "10.1.0.4", "dst_port": 80, "protocol": "TCP", "status": "SYN"}
        for i in range(101)
    ]
    log = _write_log(records_101)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        assert len([e for e in events if e.event_type == "traffic_spike"]) >= 1
    finally:
        os.unlink(log)


def test_invalid_ip_is_skipped():
    records = [
        {"timestamp": _ts(0, 0), "src_ip": "not_an_ip\x00", "dst_port": 80, "protocol": "TCP", "status": "SYN"},
        {"timestamp": _ts(0, 100), "src_ip": "10.0.0.6", "dst_port": 80, "protocol": "TCP", "status": "SYN"},
    ]
    log = _write_log(records)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        for event in events:
            assert event.src_ip != "not_an_ip\x00"
    finally:
        os.unlink(log)
