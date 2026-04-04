"""Fuzzing tests for Sentinel."""
from __future__ import annotations
import json
import os
import tempfile
import pytest

from ..framework.sentinel import Sentinel
from ..framework.models import Event

def _write_raw(lines: list[str]) -> str:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False, encoding="utf-8")
    for line in lines:
        tmp.write(line + "\n")
    tmp.close()
    return tmp.name

def _ts(base_s: float, offset_ms: int) -> str:
    from datetime import datetime, timezone, timedelta
    dt = datetime(2025, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=base_s, milliseconds=offset_ms)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def test_sentinel_process_malformed_json():
    # Should it crash or skip? Let's check watch vs process
    # If it crashes, we found a bug!
    lines = [
        '{"timestamp": "2025-01-01T00:00:00Z", "src_ip": "10.0.0.1", "dst_port": 80', # Missing closing brace
        '{"timestamp": "2025-01-01T00:00:01Z", "src_ip": "10.0.0.1", "dst_port": 80}',
    ]
    log = _write_raw(lines)
    try:
        sentinel = Sentinel()
        # This will likely crash with JSONDecodeError!
        events = sentinel.process(log)
        # If we fix it, it should just return 0 events (since 1 line is ignored, 1 line isn't enough for a rule)
        assert len(events) == 0
    finally:
        os.unlink(log)

def test_sentinel_process_missing_fields_and_wrong_types():
    lines = [
        json.dumps({"timestamp": _ts(0, i * 100), "src_ip": "10.0.0.2", "dst_port": "not-an-int", "status": ["wrong", "type"]})
        for i in range(15)
    ]
    log = _write_raw(lines)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        assert len(events) == 0
    finally:
        os.unlink(log)

def test_sentinel_process_ips_fuzzing():
    # Test with IPV6, loopback, broadcast, etc.
    ips = [
        "::1",  # IPv6 loopback
        "255.255.255.255", # Broadcast
        "0.0.0.0",
        "127.0.0.1",
        "fe80::1ff:fe23:4567:890a", # IPv6 link local
        "not_an_ip",
        "",
        " ",
    ]
    
    # We will trigger a port scan for each IP to see if it processes them or crashes
    lines = []
    base = 0
    for ip in ips:
        for i in range(15):
            lines.append(json.dumps({"timestamp": _ts(base, i * 100), "src_ip": ip, "dst_port": 20 + i, "protocol": "TCP", "status": "SYN"}))
        base += 10
        
    log = _write_raw(lines)
    try:
        sentinel = Sentinel()
        events = sentinel.process(log)
        # Should drop invalid IPs but process valid ones like IPv6, broadcast, etc.
        # "not_an_ip" and "" and " " should not be processed.
        events_by_ip = {e.src_ip for e in events}
        assert "not_an_ip" not in events_by_ip
        assert "" not in events_by_ip
        assert " " not in events_by_ip
        assert "::1" in events_by_ip or "127.0.0.1" in events_by_ip  # Should process valid forms
    finally:
        os.unlink(log)
