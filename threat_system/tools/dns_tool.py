from __future__ import annotations
import ipaddress
import socket
from typing import Any


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {ip}") from e


class DNSTool:
    def fetch(self, ip: str) -> dict[str, Any]:
        _validate_ip(ip)
        try:
            # B5: gethostbyaddr() blocks indefinitely without a timeout.
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(5.0)
            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
            finally:
                socket.setdefaulttimeout(old_timeout)
            return {"hostname": hostname, "ip": ip}
        except Exception as e:
            return {"error": str(e), "fallback": True, "ip": ip, "hostname": None}


class MockDNSTool:
    def fetch(self, ip: str) -> dict[str, Any]:
        return {
            "hostname": "203.0.113.45.vultr.com",
            "ip": ip,
        }
