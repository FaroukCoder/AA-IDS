from __future__ import annotations
import json
import os
from typing import Any

_DB_PATH = os.path.join(os.path.dirname(__file__), "port_db.json")

with open(_DB_PATH, encoding="utf-8") as _f:
    _PORT_DB: dict[str, dict] = json.load(_f)


class PortDBTool:
    def fetch(self, ports: list[int]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for port in ports:
            entry = _PORT_DB.get(str(port))
            if entry:
                result[str(port)] = entry
        return result


class MockPortDBTool:
    def fetch(self, ports: list[int]) -> dict[str, Any]:
        return {
            "22": {"service": "SSH", "protocol": "TCP", "mitre_technique": "T1021.004"},
            "80": {"service": "HTTP", "protocol": "TCP", "mitre_technique": "T1071.001"},
            "443": {"service": "HTTPS", "protocol": "TCP", "mitre_technique": "T1071.001"},
        }
