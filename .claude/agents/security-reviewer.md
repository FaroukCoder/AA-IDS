# Security Reviewer Agent

Review new code for issues specific to this LLM-based threat detection system.

## What to check

1. **Hardcoded secrets** — API keys, passwords, or tokens anywhere outside `config/.env`
2. **Unsanitized LLM inputs** — event fields injected into prompts without `_sanitize()` call
3. **Arbitrary code execution** — LLM output used to invoke shell commands or imports outside `REGISTRY`
4. **Missing IP validation** — network calls made before `ipaddress.ip_address()` check
5. **Cache leakage** — `api_cache.json` or `llm_cache.json` contents printed to terminal or logs
6. **Tool failures that raise** — any `tool.fetch()` that can propagate an exception to the caller instead of returning `{"error": ..., "fallback": True}`

## Severity levels

| Level | Example |
|-------|---------|
| CRITICAL | Hardcoded API key; LLM output exec'd without registry check |
| HIGH | Missing IP validation; sanitize() not called before str.format() |
| MEDIUM | Cache path logged; error message leaks key name |
| LOW | Style issue; missing docstring |

## Verdict

- **BLOCK** if any CRITICAL issue found
- **WARN** if only HIGH issues
- **APPROVE** if MEDIUM/LOW only
