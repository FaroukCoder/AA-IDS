from __future__ import annotations
import ipaddress
import json
import os
from typing import Any

import requests

CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "api_cache.json"
)


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {ip}") from e


def _load_cache() -> dict[str, Any]:
    if os.path.isfile(CACHE_PATH):
        with open(CACHE_PATH, encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def _save_cache(cache: dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    with open(CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2)


class AbuseIPDBTool:
    def __init__(self) -> None:
        from ..config.settings import settings
        self._api_key = settings.abuseipdb_key

    def fetch(self, ip: str) -> dict[str, Any]:
        _validate_ip(ip)

        cache = _load_cache()
        if ip in cache:
            return cache[ip]

        try:
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": self._api_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=10,
            )
            response.raise_for_status()
            raw = response.json().get("data", {})
            # Keep only aggregate fields — drop the per-report list to save tokens
            data = {k: v for k, v in raw.items() if k != "reports"}
            cache[ip] = data
            _save_cache(cache)
            return data
        except Exception as e:
            return {"error": str(e), "fallback": True}


class MockAbuseIPDBTool:
    def fetch(self, ip: str) -> dict[str, Any]:
        return {
            "ipAddress": ip,
            "abuseConfidenceScore": 87,
            "totalReports": 23,
            "numDistinctUsers": 11,
            "lastReportedAt": "2025-03-28T14:30:00+00:00",
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting/Transit",
            "isp": "Vultr Holdings LLC",
            "domain": "vultr.com",
            "isWhitelisted": False,
            "reports": [
                {"categories": [14, 15], "comment": "Port scan detected"},
                {"categories": [18], "comment": "Brute force SSH"},
            ],
        }
