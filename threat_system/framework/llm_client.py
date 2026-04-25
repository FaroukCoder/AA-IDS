from __future__ import annotations
import hashlib
import json
import os
import re
import threading
import time
from typing import Any

import openai

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


_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)


def _collect_stream(stream) -> str:
    """Collect answer content from a streaming response, skipping reasoning chunks.

    NVIDIA thinking models (DeepSeek V4 Pro, R1, etc.) emit internal reasoning
    in delta.reasoning / delta.reasoning_content before the final answer.
    We discard those chunks and only collect delta.content.

    Works identically for standard models — they never set delta.reasoning.
    """
    parts: list[str] = []
    for chunk in stream:
        if not chunk.choices:
            continue
        delta = chunk.choices[0].delta
        if getattr(delta, "reasoning", None) or getattr(delta, "reasoning_content", None):
            continue          # skip internal thinking — not part of the answer
        if delta.content:
            parts.append(delta.content)
    return "".join(parts)


def _clean_content(text: str) -> str:
    """Strip <think>…</think> blocks that some models embed in the content stream.

    Some thinking models include reasoning inside <think> tags in delta.content
    rather than in a separate reasoning field. Strip them before JSON parsing.
    """
    return _THINK_RE.sub("", text).strip()


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

    # ── NVIDIA universal formula ───────────────────────────────────────────
    # timeout prevents indefinite hangs on slow or unresponsive models.
    client = openai.OpenAI(
        base_url=settings.llm_base_url,
        api_key=settings.nvidia_api_key,
        timeout=settings.llm_timeout,
    )

    # Thinking models need temperature=1, more token budget, and a thinking flag.
    # Standard models use temperature=0 for deterministic, reproducible JSON.
    call_kwargs: dict = {
        "model":       settings.llm_model,
        "max_tokens":  4096 if settings.llm_thinking else 1024,
        "temperature": 1    if settings.llm_thinking else 0,
        "stream":      True,   # always stream — required for thinking models,
                               # fine for standard models
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
    }
    if settings.llm_thinking:
        call_kwargs["extra_body"] = {
            "chat_template_kwargs": {"thinking": True}
        }
    # ── end formula ────────────────────────────────────────────────────────

    max_retries = 6
    last_error: Exception | None = None

    for attempt in range(max_retries):
        with _api_semaphore:
            try:
                stream   = client.chat.completions.create(**call_kwargs)
                raw      = _collect_stream(stream)
                content  = _clean_content(raw)
                result   = _parse_json(content)

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

            except openai.RateLimitError as e:
                last_error = e
                # Exponential backoff: 20s, 40s, 60s, 80s, 100s
                wait = 20 * (attempt + 1)
                if attempt < max_retries - 1:
                    time.sleep(wait)

            except openai.APIStatusError as e:
                if e.status_code >= 500:
                    last_error = e
                    if attempt < max_retries - 1:
                        time.sleep(5 * (attempt + 1))
                else:
                    raise

    raise last_error or LLMOutputError("Max retries exceeded")
