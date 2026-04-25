"""
demo.py — One-command demonstration of the LLM-Orchestrated Threat Detection System.

Run:
    python -m threat_system.demo

Expected output (<90s):
  1. Demo event displayed (medium severity port scan)
  2. LLM-chosen agent dispatch order shown
  3. Each AgentReport printed sequentially
  4. InvestigatorResult: LLM recommends block_ip
  5. PolicyResult: DOWNGRADE → alert_admin (severity=medium below min_severity_to_block=high)
  6. ActionRecord: final_action=alert_admin, mode=advisory
  7. Evaluation metrics table

Browser: http://localhost:8765 shows the live decision tree while the demo runs.
"""
from __future__ import annotations
import os
import sys

# Allow running as: python -m threat_system.demo  (repo root must be on path)
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from threat_system.config.settings import settings

try:
    settings.validate()
except Exception as e:
    print(f"\n[ERROR] {e}\n")
    sys.exit(1)

from threat_system.simulator.scenarios import demo_scenario
from threat_system.framework.pipeline import ThreatPipeline
from threat_system.framework import display
from threat_system.visualizer import ws_server, narrator as narr
from threat_system.visualizer.ws_server import broadcast
from threat_system.main import _make_stage_handler

print("\n" + "=" * 70)
print("  LLM-Orchestrated Network Threat Detection System — DEMO")
print("=" * 70 + "\n")

# Start the visualizer so the browser can follow along.
ws_server.start_server()
ws_server.register_run_handler(lambda _payload: None)  # no browser-triggered runs in demo

on_stage = _make_stage_handler(display, narr, broadcast)

# Use strict_policy so DOWNGRADE is clearly visible
pipeline = ThreatPipeline(
    policy_file="strict_policy.json",
    on_stage_complete=on_stage,
)

event = demo_scenario()
display.render_stage("event", event)

print("\n[Running full pipeline...]\n")
ws_server.run_started(event.event_id)
action = pipeline.run_event(event)
ws_server.run_complete({
    "event_id":       event.event_id,
    "target":         event.src_ip,
    "final_action":   action.final_action,
    "classification": action.policy_decision,
    "confidence":     ws_server._current_confidence,
})

print("\n" + "=" * 70)
print("  Evaluation Results")
print("=" * 70)

report_path = os.path.join(os.path.dirname(__file__), "threat_system", "docs", "evaluation_report.json")
display.render_evaluation_table(report_path)

print("\nDemo complete.\n")
