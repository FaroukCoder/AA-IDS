from __future__ import annotations
import ipaddress
from typing import Any


def _validate_ip(ip: str) -> None:
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {ip}") from e


def _trim_rdap(raw: dict) -> dict:
    """Extract only the fields the LLM needs — drops verbose contact/remarks blobs."""
    network = raw.get("network") or {}
    entities = raw.get("objects") or {}
    # Collect org names from entity contacts
    orgs = []
    for obj in entities.values():
        contact = obj.get("contact") or {}
        name = contact.get("name") or obj.get("handle")
        if name:
            orgs.append(name)
    return {
        "asn": raw.get("asn"),
        "asn_description": raw.get("asn_description"),
        "asn_country_code": raw.get("asn_country_code"),
        "asn_cidr": raw.get("asn_cidr"),
        "network_name": network.get("name"),
        "network_country": network.get("country"),
        "org_names": orgs[:3],  # first 3 only
    }


class WHOISTool:
    def fetch(self, ip: str) -> dict[str, Any]:
        _validate_ip(ip)
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip)
            raw = obj.lookup_rdap(depth=1)
            return _trim_rdap(raw)
        except Exception as e:
            return {"error": str(e), "fallback": True}


class MockWHOISTool:
    def fetch(self, ip: str) -> dict[str, Any]:
        return {
            "asn": "AS20473",
            "asn_description": "CHOOPA, US",
            "asn_cidr": "203.0.113.0/24",
            "asn_country_code": "US",
            "asn_registry": "arin",
            "network": {
                "name": "VULTR-CLOUD",
                "country": "US",
                "start_address": "203.0.113.0",
                "end_address": "203.0.113.255",
            },
            "objects": {
                "VULTR-1": {
                    "contact": {
                        "name": "Vultr Holdings LLC",
                    }
                }
            },
        }
