# Prompt Injection Prevention

## Risk

User-controlled data (IP addresses, hostnames, tool output) is injected
into LLM prompts via `str.format()`. A malicious IP or hostname could
contain tokens designed to manipulate the LLM.

## Sanitization Pattern

Apply to ALL event field values BEFORE `str.format()`:

```python
import re

_INJECTION_TOKENS = re.compile(
    r"ignore|disregard|system\s*:|</s>|<\|im_start\|>|<\|im_end\|>",
    re.IGNORECASE,
)
_BRACES = re.compile(r"[{}]")

def _sanitize(value: str) -> str:
    clean = _INJECTION_TOKENS.sub("", str(value))
    clean = _BRACES.sub("", clean)
    return clean.strip()
```

## What to Strip

| Token | Reason |
|-------|--------|
| `{`, `}` | Would break `str.format()` or inject new placeholders |
| `ignore`, `disregard` | Common instruction-override prefixes |
| `system:` | Could inject a system prompt boundary |
| `</s>` | Common EOS token used to break context |
| `<\|im_start\|>`, `<\|im_end\|>` | ChatML tokens |

## Forbidden Pattern

```python
# NEVER construct prompts with f-strings from untrusted data
prompt = f"The IP {event.src_ip} shows: {event.event_type}"  # WRONG

# ALWAYS use sanitized str.format() with .txt template files
prompt = template.format(src_ip=_sanitize(event.src_ip), ...)  # CORRECT
```

## Tool Output

Tool output (JSON dicts) is serialized with `json.dumps()` — this
auto-escapes special characters. Do not sanitize JSON tool output further.
