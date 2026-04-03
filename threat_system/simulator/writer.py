from __future__ import annotations
import json
import os
from typing import Callable

RAW_LOG = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "raw_traffic.jsonl"
)


def write_scenario(scenario_fn: Callable[[], list[dict]], output_path: str = RAW_LOG) -> int:
    records = scenario_fn()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")
    return len(records)
