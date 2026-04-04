from __future__ import annotations
import hashlib
import json
import os
import threading
import time
from typing import Any

import anthropic

from ..config.settings import settings

_cache_lock = threading.Lock()

# Limit concurrent LLM calls to avoid token-per-minute rate limits.
# With 4 parallel agents each sending ~2–3 k tokens, a concurrency of 2
# keeps peak usage well inside the 30 k TPM org limit.
_api_semaphore = threading.Semaphore(2)

CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "logs", "llm_cache.json"
)


class LLMOutputError(Exception):
    pass


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


def _cache_key(system: str, user: str) -> str:
    return hashlib.sha256((system + user).encode()).hexdigest()


def _parse_json(text: str) -> dict[str, Any]:
    text = text.strip()

    def _check_dict(obj: Any, source: str) -> dict[str, Any]:
        if not isinstance(obj, dict):
            raise LLMOutputError(
                f"LLM output must be a JSON object, got {type(obj).__name__} "
                f"(source={source}): {text[:100]}"
            )
        return obj

    try:
        return _check_dict(json.loads(text), "direct")
    except json.JSONDecodeError:
        pass
    # strip markdown fences
    if text.startswith("```"):
        lines = text.split("\n")
        inner = "\n".join(
            line for line in lines if not line.startswith("```")
        )
        try:
            return _check_dict(json.loads(inner.strip()), "fenced")
        except json.JSONDecodeError:
            pass
    raise LLMOutputError(f"Failed to parse LLM output as JSON: {text[:200]}")


def call(system: str, user: str) -> dict[str, Any]:
    key = _cache_key(system, user)

    # Check cache before hitting the API — lock protects concurrent readers.
    with _cache_lock:
        cache = _load_cache()
        if key in cache:
            return cache[key]

    client = anthropic.Anthropic(api_key=settings.anthropic_api_key)
    max_retries = 6
    last_error: Exception | None = None

    for attempt in range(max_retries):
        with _api_semaphore:
            try:
                response = client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=1024,
                    temperature=0,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                )
                content = response.content[0].text
                result = _parse_json(content)

                # Write back to cache under lock to prevent concurrent corruption.
                with _cache_lock:
                    cache = _load_cache()
                    cache[key] = result
                    _save_cache(cache)

                return result

            except LLMOutputError as e:
                last_error = e
                if attempt < max_retries - 1:
                    time.sleep(2 * (attempt + 1))

            except anthropic.RateLimitError as e:
                last_error = e
                # Exponential backoff: 20s, 40s, 60s, 80s, 100s
                wait = 20 * (attempt + 1)
                if attempt < max_retries - 1:
                    time.sleep(wait)

            except anthropic.APIStatusError as e:
                if e.status_code >= 500:
                    last_error = e
                    if attempt < max_retries - 1:
                        time.sleep(5 * (attempt + 1))
                else:
                    raise

    raise last_error or LLMOutputError("Max retries exceeded")
