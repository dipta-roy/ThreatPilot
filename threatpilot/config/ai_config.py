"""AI configuration module for ThreatPilot.

Contains the ``AIConfig`` model representing AI provider settings.
"""

from __future__ import annotations

import os
from pathlib import Path
from pydantic import BaseModel, ConfigDict
import dotenv

from threatpilot.utils.crypto_utils import encrypt_api_key, decrypt_api_key
from threatpilot.utils.logger import add_secret_to_redaction

_ENV_FILE = Path(__file__).resolve().parent.parent.parent / "config.env"


class AIConfig(BaseModel):
    """Configuration for the AI provider used by the application.

    Attributes:
        provider_type: The AI backend type ('ollama' or 'gemini').
        endpoint_url: The URL of the AI endpoint (ignored for native Gemini).
        model_name: The model identifier to use.
        temperature: Sampling temperature (0.0 - 2.0).
        max_tokens: Maximum number of tokens in the response.
        timeout: Request timeout in seconds.
        gemini_api_key: API key for Gemini.
    """

    provider_type: str = "ollama"
    endpoint_url: str = "http://localhost:11434"
    model_name: str = "qwen2.5vl:3b"
    temperature: float = 0.7
    max_tokens: int = 8192
    timeout: int = 120
    gemini_api_key: str = ""

    model_config = ConfigDict(extra="ignore")

    @property
    def api_key(self) -> str:
        """Helper to get the appropriate API key based on provider type."""
        if self.provider_type == "gemini":
            return self.gemini_api_key
        return ""

    @api_key.setter
    def api_key(self, value: str) -> None:
        """Helper to set the API key for the current provider."""
        if self.provider_type == "gemini":
            self.gemini_api_key = value

    @classmethod
    def load(cls) -> AIConfig:
        """Load configuration from config.env, decrypting API keys."""
        if not _ENV_FILE.exists():
            instance = cls()
            instance.save()
            return instance
            
        dotenv.load_dotenv(_ENV_FILE, override=True)
        
        def get_opt(key: str, default: str) -> str:
            val = os.getenv(key, default)
            if not val:
                return default
            # Strip both double and single quotes which can be added by dotenv.set_key
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            return val.strip().replace("\n", "").replace("\r", "")

        def scrub_key(key: str) -> str:
            if not key: return ""
            clean = key.replace("\n", "").replace("\r", "").strip()
            # If the user accidentally pasted a traceback as a key, treat it as empty
            if clean.lower().startswith("traceback"):
                 return ""
            return clean

        config = cls(
            provider_type=get_opt("AI_PROVIDER_TYPE", "ollama"),
            endpoint_url=get_opt("AI_ENDPOINT_URL", "http://localhost:11434"),
            model_name=get_opt("AI_MODEL_NAME", "qwen2.5vl:3b"),
            temperature=float(get_opt("AI_TEMPERATURE", "0.7")),
            max_tokens=int(get_opt("AI_MAX_TOKENS", "8192")),
            timeout=int(get_opt("AI_TIMEOUT", "120")),
            gemini_api_key=scrub_key(decrypt_api_key(get_opt("GEMINI_API_KEY", ""))),
        )
        
        # Register keys for log redaction
        add_secret_to_redaction(config.gemini_api_key)
        
        return config



    def save(self) -> None:
        """Save configuration to config.env, encrypting API keys."""
        _ENV_FILE.touch(exist_ok=True)
        dotenv.set_key(_ENV_FILE, "AI_PROVIDER_TYPE", self.provider_type)
        dotenv.set_key(_ENV_FILE, "AI_ENDPOINT_URL", self.endpoint_url)
        dotenv.set_key(_ENV_FILE, "AI_MODEL_NAME", self.model_name)
        dotenv.set_key(_ENV_FILE, "AI_TEMPERATURE", str(self.temperature))
        dotenv.set_key(_ENV_FILE, "AI_MAX_TOKENS", str(self.max_tokens))
        dotenv.set_key(_ENV_FILE, "AI_TIMEOUT", str(self.timeout))
        
        # Only write non-empty keys
        if self.gemini_api_key:
            dotenv.set_key(_ENV_FILE, "GEMINI_API_KEY", encrypt_api_key(self.gemini_api_key))
        elif os.getenv("GEMINI_API_KEY"):
            dotenv.unset_key(_ENV_FILE, "GEMINI_API_KEY")

