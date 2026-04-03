from __future__ import annotations

# Registry populated after agent modules are imported
# to avoid circular imports. Agents register themselves on import.
REGISTRY: dict[str, type] = {}


def register(name: str, cls: type) -> None:
    REGISTRY[name] = cls


def _populate() -> None:
    from ..agents.whois_agent import WHOISAgent
    from ..agents.dns_agent import DNSAgent
    from ..agents.reputation_agent import ReputationAgent
    from ..agents.port_intel_agent import PortIntelAgent

    REGISTRY["whois"] = WHOISAgent
    REGISTRY["dns"] = DNSAgent
    REGISTRY["reputation"] = ReputationAgent
    REGISTRY["port_intel"] = PortIntelAgent


def get_registry() -> dict[str, type]:
    if not REGISTRY:
        _populate()
    return REGISTRY
