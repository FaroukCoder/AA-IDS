from __future__ import annotations
import os

SKILLS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "skills")


def load(name: str) -> str:
    path = os.path.join(SKILLS_DIR, f"{name}.md")
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Skill not found: {path}")
    with open(path, encoding="utf-8") as f:
        return f.read()
