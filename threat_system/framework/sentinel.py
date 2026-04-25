from __future__ import annotations
import ipaddress
import json
import logging
import os
import re
from collections import defaultdict
from datetime import datetime

from .models import Event

logger = logging.getLogger(__name__)

EVENTS_LOG = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "events.jsonl")

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")

# Ports that carry strong attack signal — preserved preferentially in event.ports_targeted
# so downstream agents (PortIntelAgent) always see credential-access / C2 combos.
_HIGH_SIGNAL_PORTS = frozenset([
    21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445,
    1433, 1521, 3306, 3389, 4444, 5432, 5985, 8080, 8443,
])


def _prioritized_ports(ports: list[int], limit: int = 20) -> list[int]:
    """Return up to `limit` ports, high-signal ones first."""
    priority = [p for p in ports if p in _HIGH_SIGNAL_PORTS]
    rest     = [p for p in ports if p not in _HIGH_SIGNAL_PORTS]
    return (priority + rest)[:limit]


def _sanitize_ip(raw: str) -> str | None:
    clean = _CONTROL_CHARS.sub("", str(raw)).strip()
    try:
        ipaddress.ip_address(clean)
        return clean
    except ValueError:
        return None


def _safe_int(val, default=0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


class Sentinel:
    def process(self, log_path: str) -> list[Event]:
        lines = []
        with open(log_path, encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        lines.append(json.loads(line))
                    except json.JSONDecodeError as e:
                        logger.warning("Invalid JSON skipped: %s", e)

        events: list[Event] = []
        event_counter = 0

        def _next_id() -> str:
            nonlocal event_counter
            event_counter += 1
            return f"evt_{event_counter:04d}"

        by_ip: dict[str, list[dict]] = defaultdict(list)
        for entry in lines:
            ip = _sanitize_ip(entry.get("src_ip", ""))
            if ip is None:
                logger.warning("Invalid src_ip skipped: %r", entry.get("src_ip"))
                continue
            entry["src_ip"] = ip
            by_ip[ip].append(entry)

        for ip, records in by_ip.items():
            records_sorted = sorted(records, key=lambda r: r.get("timestamp", ""))

            # Evaluate rules in priority order; emit at most one event per source IP
            # to prevent the same attack generating multiple pipeline runs.
            for rule_fn in (
                self._port_scan_rule,
                self._traffic_spike_rule,
                self._failed_conn_rule,
            ):
                event = rule_fn(ip, records_sorted, _next_id)
                if event:
                    events.append(event)
                    break   # one event per IP per batch

        os.makedirs(os.path.dirname(EVENTS_LOG), exist_ok=True)
        with open(EVENTS_LOG, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev.__dict__) + "\n")

        return events

    def _port_scan_rule(
        self, ip: str, records: list[dict], next_id
    ) -> Event | None:
        window_s = 10.0
        threshold = 10
        best_ports: list[int] = []
        best_window = 0.0

        for i, rec in enumerate(records):
            t_start = self._ts(rec)
            if t_start is None:
                continue
            ports_in_window: set[int] = set()
            ports_in_window.add(_safe_int(rec.get("dst_port", 0)))
            last_t = t_start

            for j in range(i + 1, len(records)):
                t = self._ts(records[j])
                if t is None or t - t_start > window_s:
                    break
                ports_in_window.add(_safe_int(records[j].get("dst_port", 0)))
                last_t = t

            if len(ports_in_window) > threshold:
                if len(ports_in_window) > len(best_ports):
                    best_ports = sorted(ports_in_window)
                    best_window = last_t - t_start if last_t > t_start else 1.0

        if len(best_ports) > threshold:
            return Event(
                event_id=next_id(),
                src_ip=ip,
                event_type="port_scan",
                ports_targeted=_prioritized_ports(best_ports),
                frequency=len(best_ports),
                time_window_s=round(best_window, 1),
                severity="high",
            )
        return None

    def _traffic_spike_rule(
        self, ip: str, records: list[dict], next_id
    ) -> Event | None:
        window_s = 10.0
        threshold = 100

        for i, rec in enumerate(records):
            t_start = self._ts(rec)
            if t_start is None:
                continue
            count = 1

            for j in range(i + 1, len(records)):
                t = self._ts(records[j])
                if t is None or t - t_start > window_s:
                    break
                count += 1

            if count > threshold:
                return Event(
                    event_id=next_id(),
                    src_ip=ip,
                    event_type="traffic_spike",
                    ports_targeted=[],
                    frequency=count,
                    time_window_s=window_s,
                    severity="high",
                )
        return None

    def _failed_conn_rule(
        self, ip: str, records: list[dict], next_id
    ) -> Event | None:
        window_s = 30.0
        threshold = 20
        failed_statuses = {"SYN", "FAILED", "RESET", "RST", "FIN"}

        failed = [
            r for r in records if str(r.get("status", "")).upper() in failed_statuses
        ]

        for i, rec in enumerate(failed):
            t_start = self._ts(rec)
            if t_start is None:
                continue
            count = 1
            ports_seen: set[int] = {_safe_int(rec.get("dst_port", 0))}

            for j in range(i + 1, len(failed)):
                t = self._ts(failed[j])
                if t is None or t - t_start > window_s:
                    break
                count += 1
                ports_seen.add(_safe_int(failed[j].get("dst_port", 0)))

            if count > threshold:
                return Event(
                    event_id=next_id(),
                    src_ip=ip,
                    event_type="failed_connections",
                    ports_targeted=sorted(ports_seen)[:20],
                    frequency=count,
                    time_window_s=window_s,
                    severity="medium",
                )
        return None

    def watch(self, log_path: str, callback) -> None:
        """
        Tail log_path in real time and call callback(event) whenever a rule fires.

        Uses the same per-rule sliding windows as process():
          port_scan    — >10 unique ports from one IP within 10 s
          traffic_spike — >100 requests from one IP within 10 s
          failed_conn  — >20 SYN/RST connections from one IP within 30 s

        A 60 s per-(ip, rule) cooldown prevents re-firing on the same ongoing
        attack.  Blocks until KeyboardInterrupt.  Does NOT modify process().
        """
        import time
        from collections import deque
        from typing import Callable

        # Per-IP record buffers (ordered by arrival)
        ip_records: dict[str, deque] = defaultdict(deque)
        # Cooldown: (ip, rule_name) → earliest wall-clock time to fire again
        cooldown: dict[str, float] = {}   # ip → earliest wall-clock time any rule may fire again
        COOLDOWN_S = 60.0
        MAX_WINDOW = 30.0   # max of all rule windows

        event_counter = 0

        def _next_id() -> str:
            nonlocal event_counter
            event_counter += 1
            return f"live_{event_counter:04d}"

        # Wait for file to appear (capture.py may still be starting up)
        while not os.path.exists(log_path):
            logger.info("watch(): waiting for %s to appear", log_path)
            time.sleep(1.0)

        with open(log_path, encoding="utf-8") as fh:
            fh.seek(0, 2)   # seek to end — ignore historical data
            try:
                while True:
                    line = fh.readline()
                    if not line:
                        time.sleep(0.1)
                        continue

                    try:
                        record = json.loads(line.strip())
                    except json.JSONDecodeError:
                        continue

                    ip = _sanitize_ip(record.get("src_ip", ""))
                    if ip is None:
                        continue
                    record["src_ip"] = ip

                    # B4: skip records with missing/unparseable timestamps —
                    # they would default to epoch and never evict from the buffer.
                    if self._ts(record) is None:
                        logger.debug("watch(): skipping record with invalid timestamp")
                        continue

                    now = time.time()
                    ip_records[ip].append(record)

                    # Evict records outside the max window.
                    # For live traffic, packet timestamps ≈ wall clock.
                    cutoff = now - MAX_WINDOW
                    buf = ip_records[ip]
                    while buf and (self._ts(buf[0]) or 0.0) < cutoff:
                        buf.popleft()

                    records_list = list(buf)

                    # Per-IP cooldown: if any rule already fired for this IP, skip all rules.
                    if cooldown.get(ip, 0.0) > now:
                        continue

                    for rule_name, rule_fn in (
                        ("port_scan",     self._port_scan_rule),
                        ("traffic_spike", self._traffic_spike_rule),
                        ("failed_conn",   self._failed_conn_rule),
                    ):
                        event = rule_fn(ip, records_list, _next_id)
                        if event:
                            cooldown[ip] = now + COOLDOWN_S   # block ALL rules for this IP
                            # B2: catch callback exceptions so the watch loop
                            # survives a pipeline crash and keeps processing events.
                            try:
                                callback(event)
                            except Exception as exc:
                                logger.error(
                                    "watch(): event callback raised %s — loop continues",
                                    exc,
                                )
                            break   # one event per IP per packet arrival

            except KeyboardInterrupt:
                pass

    @staticmethod
    def _ts(record: dict) -> float | None:
        """Return Unix timestamp from record, or None if timestamp is missing/invalid."""
        ts_str = record.get("timestamp", "")
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, AttributeError):
            return None
