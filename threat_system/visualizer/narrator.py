"""
narrator.py — Synthesize thought-bubble narrations from agent output + personality profiles.

No extra LLM calls. All synthesis is local, deterministic (given a fixed random seed),
and based on key fields in the agent's findings dict.

Public API
----------
narrate(stage, data) -> dict | None
    Unified entry point for all pipeline stages.

Return shape (all narrate_* functions):
    {
        "agent":      str,   agent key (e.g. "reputation")
        "catchphrase": str,  personality phrase matching context
        "inner_voice": str,  1-2 sentence inner monologue from data
        "confidence":  float,
        "verdict":     str,  "clean" | "suspicious" | "malicious" | "escalated" | "pending" | "unknown"
        "color":       str,  Rich / CSS color token
        "archetype":   str,  e.g. "The Bounty Hunter"
    }
"""
from __future__ import annotations

import random
from typing import Any

from .personalities import PERSONALITIES

# Module-level RNG — seeded once so catchphrases are varied but stable across tests
_rng = random.Random()

# Current event stored for stages that need context (policy)
_current_event: Any = None


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pick(profile: dict, context: str) -> str:
    phrases = profile.get(context) or profile.get("high_confidence") or ["..."]
    return _rng.choice(phrases)


def _verdict_from_risk(risk_level: str, fallback: bool = False) -> str:
    if fallback:
        return "unknown"
    return {
        "critical": "malicious",
        "high":     "malicious",
        "medium":   "suspicious",
        "low":      "clean",
    }.get(str(risk_level).lower(), "unknown")


def _profile(agent_name: str) -> dict:
    return PERSONALITIES.get(agent_name, PERSONALITIES["orchestrator"])


# ---------------------------------------------------------------------------
# Per-agent inner-voice synthesizers
# ---------------------------------------------------------------------------

def _voice_whois(findings: dict, fallback: bool) -> str:
    if fallback or not findings:
        return "RDAP lookup failed. No ownership data available."
    org = findings.get("org", "Unknown organisation")
    hosting = findings.get("hosting_provider", "")
    country = findings.get("country", "")
    is_vps = findings.get("is_vps_hosting", False)
    risk_note = findings.get("risk_note", "")
    vps_str = " VPS/cloud infrastructure — common attacker base." if is_vps else ""
    host_str = f" ({hosting})" if hosting else ""
    loc_str = f", {country}" if country else ""
    return f"IP registered to {org}{host_str}{loc_str}.{vps_str} {risk_note}".strip()


def _voice_dns(findings: dict, fallback: bool) -> str:
    if fallback or not findings:
        return "No PTR record. The absence of a hostname is itself a signal."
    hostname = findings.get("hostname")
    has_ptr = findings.get("has_ptr_record", False)
    pattern = findings.get("hostname_pattern", "")
    risk_note = findings.get("risk_note", "")
    if hostname:
        ptr_str = "PTR confirmed." if has_ptr else "PTR absent despite having a hostname."
        pat_str = f" Pattern: {pattern}." if pattern else ""
        return f"Resolved -> {hostname}.{pat_str} {ptr_str} {risk_note}".strip()
    return f"No hostname resolved. {risk_note}".strip()


def _voice_reputation(findings: dict, fallback: bool) -> str:
    if fallback or not findings:
        return "AbuseIPDB unreachable. Operating without reputation data."
    score = findings.get("abuse_score", 0)
    total = findings.get("total_reports", 0)
    days = findings.get("last_reported_days_ago")
    cats = findings.get("categories", [])
    if score:
        cat_str = ", ".join(str(c) for c in cats[:2]) if cats else "unspecified"
        days_str = f", last reported {days}d ago" if days is not None else ""
        return f"Abuse score {score}/100. {total} reports ({cat_str}){days_str}."
    return "No prior abuse reports on record."


def _voice_port_intel(findings: dict, fallback: bool) -> str:
    if fallback or not findings:
        return "Port database lookup failed. Proceeding without service mapping."
    services = findings.get("services_targeted", [])
    techniques = findings.get("mitre_techniques", [])
    pattern = findings.get("attack_pattern", "")
    ports = findings.get("ports_analyzed", [])
    svc_str = ", ".join(str(s) for s in services[:3]) if services else "unrecognised"
    tec_str = ", ".join(str(t) for t in techniques[:2]) if techniques else "none mapped"
    pat_str = f" Pattern: {pattern}." if pattern else ""
    return f"Ports {list(ports)[:5]} -> {svc_str}. Techniques: {tec_str}.{pat_str}"


def _voice_generic(agent_name: str, findings: dict, fallback: bool) -> str:
    if fallback or not findings:
        return "Tool returned no data."
    risk_note = findings.get("risk_note", "")
    risk_level = findings.get("risk_level", "unknown")
    return risk_note or f"Risk assessed as {risk_level}."


_VOICE_MAP = {
    "whois":      _voice_whois,
    "dns":        _voice_dns,
    "reputation": _voice_reputation,
    "port_intel": _voice_port_intel,
}


# ---------------------------------------------------------------------------
# Public narration functions
# ---------------------------------------------------------------------------

def narrate_agent(report: Any) -> dict | None:
    """Synthesize thought bubble from an AgentReport."""
    agent_name = getattr(report, "agent_name", None)
    if not agent_name:
        return None
    profile = _profile(agent_name)
    findings: dict = getattr(report, "findings", {}) or {}
    confidence: float = getattr(report, "confidence", 0.0)
    fallback: bool = getattr(report, "fallback", False)

    # Choose context bucket
    if fallback:
        context = "fallback"
    elif confidence >= 0.8:
        risk = findings.get("risk_level", "")
        context = "suspicious" if risk in ("high", "critical") else "high_confidence"
    elif confidence < 0.5:
        context = "low_confidence"
    else:
        risk = findings.get("risk_level", "")
        if risk in ("high", "critical"):
            context = "suspicious"
        elif risk == "low":
            context = "benign"
        else:
            context = "high_confidence"

    voice_fn = _VOICE_MAP.get(agent_name, lambda f, fb: _voice_generic(agent_name, f, fb))

    return {
        "agent":       agent_name,
        "catchphrase": _pick(profile, context),
        "inner_voice": voice_fn(findings, fallback),
        "confidence":  confidence,
        "verdict":     _verdict_from_risk(findings.get("risk_level", ""), fallback),
        "color":       profile["color"],
        "archetype":   profile["archetype"],
    }


def narrate_sentinel(event: Any) -> dict | None:
    """Synthesize Sentinel inner voice from an Event."""
    global _current_event
    _current_event = event

    profile = _profile("sentinel")
    event_type = getattr(event, "event_type", "unknown")
    severity = getattr(event, "severity", "low")
    freq = getattr(event, "frequency", 0)
    window = getattr(event, "time_window_s", 0.0)
    src_ip = getattr(event, "src_ip", "?")

    context = {
        "high": "suspicious", "medium": "suspicious",
        "low":  "benign",
    }.get(severity, "high_confidence")

    type_detail = {
        "port_scan":          f"Port scan — {freq} unique ports in {window:.1f}s.",
        "traffic_spike":      f"Traffic spike — {freq} requests in {window:.1f}s.",
        "failed_connections": f"Failed connections — {freq} in {window:.1f}s.",
    }.get(event_type, f"Event '{event_type}', freq={freq}.")

    inner = f"Source: {src_ip}. {type_detail} Severity: {severity.upper()}."

    return {
        "agent":       "sentinel",
        "catchphrase": _pick(profile, context),
        "inner_voice": inner,
        "confidence":  1.0,
        "verdict":     {"high": "malicious", "medium": "suspicious", "low": "clean"}.get(severity, "unknown"),
        "color":       profile["color"],
        "archetype":   profile["archetype"],
    }


def narrate_dispatch(dispatch_data: Any) -> dict | None:
    """Synthesize orchestrator dispatch thought bubble."""
    profile = _profile("orchestrator")
    parallel = getattr(dispatch_data, "parallel_agents", [])
    sequential = getattr(dispatch_data, "sequential_agents", [])

    par_str = ", ".join(parallel) if parallel else "none"
    seq_str = ", ".join(sequential) if sequential else "none"
    inner = f"Parallel units: {par_str}. Sequential follow-up: {seq_str}. Moving out."

    return {
        "agent":       "orchestrator",
        "catchphrase": "All units, move out.",
        "inner_voice": inner,
        "confidence":  1.0,
        "verdict":     "pending",
        "color":       profile["color"],
        "archetype":   profile["archetype"],
    }


def narrate_orchestrator(result: Any) -> dict | None:
    """Synthesize war-room commander inner voice from InvestigatorResult."""
    profile = _profile("orchestrator")
    confidence: float = getattr(result, "confidence", 0.0)
    cls: str = getattr(result, "classification", "unknown")
    action: str = getattr(result, "recommended_action", "log_only")
    agents: list = getattr(result, "agents_invoked", [])
    reasoning: str = getattr(result, "reasoning", "")
    auto_esc: bool = getattr(result, "auto_escalated", False)

    if auto_esc:
        context = "low_confidence"
    elif confidence >= 0.8 and cls == "malicious":
        context = "suspicious"
    elif cls in ("suspicious", "malicious"):
        context = "suspicious"
    else:
        context = "benign"

    agents_str = ", ".join(agents) if agents else "unknown"
    esc_str = " — auto-escalating (confidence below threshold)." if auto_esc else ""
    short_reason = reasoning[:120] + ("…" if len(reasoning) > 120 else "")
    inner = (
        f"Consulted: {agents_str}. Classification: {cls.upper()} "
        f"({confidence:.0%} confidence). Action: {action}.{esc_str} "
        f"{short_reason}"
    ).strip()

    verdict_map = {"malicious": "malicious", "suspicious": "suspicious", "benign": "clean"}
    verdict = "escalated" if auto_esc else verdict_map.get(cls, "unknown")

    return {
        "agent":       "orchestrator",
        "catchphrase": _pick(profile, context),
        "inner_voice": inner,
        "confidence":  confidence,
        "verdict":     verdict,
        "color":       profile["color"],
        "archetype":   profile["archetype"],
    }


def narrate_policy(policy: Any) -> dict | None:
    """Synthesize judge inner voice from PolicyResult."""
    profile = _profile("policy")
    decision: str = getattr(policy, "decision", "ALLOW")
    original: str = getattr(policy, "original_action", "")
    final: str = getattr(policy, "final_action", "")
    reason: str = getattr(policy, "reason", "")

    context = {
        "ALLOW":     "benign" if final == "log_only" else "high_confidence",
        "BLOCK":     "suspicious",
        "DOWNGRADE": "suspicious",
        "ESCALATE":  "low_confidence",
    }.get(decision, "high_confidence")

    inner = (
        f"LLM recommended: {original}. "
        f"Policy decision: {decision} -> final action: {final}. "
        f"{reason}"
    ).strip()

    verdict_map = {
        "ALLOW":     "clean" if final == "log_only" else "malicious",
        "BLOCK":     "clean",      # action suppressed — protective
        "DOWNGRADE": "suspicious",
        "ESCALATE":  "escalated",
    }

    return {
        "agent":       "policy",
        "catchphrase": _pick(profile, context),
        "inner_voice": inner,
        "confidence":  1.0,
        "verdict":     verdict_map.get(decision, "unknown"),
        "color":       profile["color"],
        "archetype":   profile["archetype"],
    }


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def narrate(stage: str, data: Any) -> dict | None:
    """
    Dispatch to the correct narration function based on pipeline stage name.

    Stages:
        "event"               -> narrate_sentinel
        "dispatch"            -> narrate_dispatch
        "agent_report"        -> narrate_agent
        "investigator_result" -> narrate_orchestrator
        "policy_result"       -> narrate_policy
        (all others)          -> None
    """
    try:
        if stage == "event":
            return narrate_sentinel(data)
        if stage == "dispatch":
            return narrate_dispatch(data)
        if stage == "agent_report":
            return narrate_agent(data)
        if stage == "investigator_result":
            return narrate_orchestrator(data)
        if stage == "policy_result":
            return narrate_policy(data)
    except Exception:
        # Narration is purely cosmetic — never crash the pipeline
        pass
    return None
