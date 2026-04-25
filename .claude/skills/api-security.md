# API Security Rules

## Secret Management

- ALL API keys stored in `config/.env` only — never hardcoded
- Load via `config/settings.py` which uses `python-dotenv`
- Validate presence at startup — raise `ConfigError` if missing
- Never log API keys to terminal or files

## Cache Security

- `logs/api_cache.json` — keyed by IP, never log to terminal
- `logs/llm_cache.json` — keyed by prompt hash (sha256), never log prompts
- Both files are gitignored

## Key Rotation

If a key is exposed: remove from .env, revoke at provider, generate new key, update .env.
