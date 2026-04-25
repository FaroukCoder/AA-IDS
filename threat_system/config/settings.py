from __future__ import annotations
import os
from pathlib import Path

from dotenv import load_dotenv

ENV_PATH = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=ENV_PATH)


class ConfigError(Exception):
    pass


class _Settings:
    def __init__(self) -> None:
        self.nvidia_api_key  = os.environ.get("NVIDIA_API_KEY", "")
        self.llm_base_url    = os.environ.get("LLM_BASE_URL", "https://integrate.api.nvidia.com/v1")
        self.llm_model       = os.environ.get("LLM_MODEL", "meta/llama-3.3-70b-instruct")
        self.abuseipdb_key   = os.environ.get("ABUSEIPDB_KEY", "")
        self.llm_thinking    = os.environ.get("LLM_THINKING", "false").lower() == "true"
        self.llm_timeout     = float(os.environ.get("LLM_TIMEOUT", "60"))
        self.min_confidence_to_act: float = 0.60

    def validate(self) -> None:
        missing = []
        if not self.nvidia_api_key:
            missing.append("NVIDIA_API_KEY")
        if not self.abuseipdb_key:
            missing.append("ABUSEIPDB_KEY")
        if missing:
            raise ConfigError(
                f"Missing required environment variables: {', '.join(missing)}. "
                "Copy config/.env.example to config/.env and fill in your keys."
            )


settings = _Settings()
