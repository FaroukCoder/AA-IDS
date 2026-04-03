#!/usr/bin/env python3
"""
capture.py — Sniff TCP traffic on the threat-lab network interface and write
each packet as a JSON line to /logs/live_traffic.jsonl.

Output format matches the Sentinel input schema exactly:
  {"timestamp": "...", "src_ip": "...", "dst_port": N, "protocol": "TCP", "status": "SYN"}

Status field logic:
  SYN only  (flags 0x02)       → "SYN"
  SYN+ACK   (flags 0x12)       → "SYN-ACK"
  RST       (flags & 0x04)     → "RST"
  Anything else                → "OTHER"

Run:
  python3 capture.py [--interface eth0]
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone

from scapy.all import IP, TCP, sniff  # type: ignore[import]

OUTPUT_PATH = "/logs/live_traffic.jsonl"


def _packet_to_record(pkt) -> dict | None:
    if not (pkt.haslayer(IP) and pkt.haslayer(TCP)):
        return None

    flags: int = pkt[TCP].flags
    if flags & 0x02 and not (flags & 0x10):
        status = "SYN"
    elif flags & 0x02 and flags & 0x10:
        status = "SYN-ACK"
    elif flags & 0x04:
        status = "RST"
    else:
        status = "OTHER"

    return {
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "src_ip":    pkt[IP].src,
        "dst_port":  pkt[TCP].dport,
        "protocol":  "TCP",
        "status":    status,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="TCP packet capture → JSONL")
    parser.add_argument("--interface", default="eth0", help="Network interface to sniff")
    args = parser.parse_args()

    print(f"[capture] Sniffing {args.interface} → {OUTPUT_PATH}", flush=True)

    with open(OUTPUT_PATH, "a", encoding="utf-8") as out_f:
        def handle(pkt) -> None:
            record = _packet_to_record(pkt)
            if record is not None:
                out_f.write(json.dumps(record) + "\n")
                out_f.flush()

        try:
            sniff(iface=args.interface, filter="tcp", prn=handle, store=False)
        except KeyboardInterrupt:
            print("[capture] Stopped.", flush=True)


if __name__ == "__main__":
    main()
