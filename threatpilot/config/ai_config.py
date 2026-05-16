"""AI configuration module for ThreatPilot.

Contains the ``AIConfig`` model representing AI provider settings.
"""

from __future__ import annotations
import os
from pathlib import Path
from pydantic import BaseModel, ConfigDict, SecretStr
import dotenv
from threatpilot.utils.crypto_utils import encrypt_api_key, decrypt_api_key
from threatpilot.utils.logger import add_secret_to_redaction
from threatpilot.utils.paths import CONFIG_FILE, THREATPILOT_HOME
from threatpilot.core.constants import (
    DEFAULT_AI_PROVIDER, DEFAULT_OLLAMA_ENDPOINT, DEFAULT_TEMPERATURE,
    DEFAULT_MAX_TOKENS, DEFAULT_TIMEOUT, DEFAULT_AUTOSAVE_INTERVAL
)

class AIConfig(BaseModel):
    """Encapsulates global AI provider settings and persistence logic."""
    provider_type: str = DEFAULT_AI_PROVIDER
    endpoint_url: str = DEFAULT_OLLAMA_ENDPOINT
    model_name: str = ""
    temperature: float = DEFAULT_TEMPERATURE
    max_tokens: int = DEFAULT_MAX_TOKENS
    timeout: int = DEFAULT_TIMEOUT
    gemini_api_key: SecretStr = SecretStr("")
    autosave_interval: int = DEFAULT_AUTOSAVE_INTERVAL
    analysis_mode: str = "STRIDE"
    application_mode: str = "Production"

    model_config = ConfigDict(extra="ignore", protected_namespaces=())

    @property
    def api_key(self) -> str:
        """Retrieves the active API key for the configured provider."""
        return self.gemini_api_key.get_secret_value() if self.provider_type == "gemini" else ""

    @api_key.setter
    def api_key(self, value: str) -> None:
        """Sets the API key for the Gemini provider."""
        if self.provider_type == "gemini": self.gemini_api_key = SecretStr(value)

    @classmethod
    def load(cls) -> AIConfig:
        """Deserializes configuration from environment variables or file with decryption."""
        file_values = dotenv.dotenv_values(str(CONFIG_FILE)) if CONFIG_FILE.exists() else {}
        
        def get_val(k: str, d: str) -> str:
            # Environment variables take precedence over file values
            v = os.environ.get(k) or file_values.get(k, d) or d
            return str(v).strip().strip("'\"").replace("\n", "").replace("\r", "")

        def scrub(k: str) -> str:
            # Prevent corrupted/traceback strings from being loaded as keys
            return "" if not k or k.lower().startswith("traceback") else k

        config = cls(
            provider_type=get_val("AI_PROVIDER_TYPE", DEFAULT_AI_PROVIDER),
            endpoint_url=get_val("AI_ENDPOINT_URL", DEFAULT_OLLAMA_ENDPOINT),
            model_name=get_val("AI_MODEL_NAME", ""),
            temperature=float(get_val("AI_TEMPERATURE", str(DEFAULT_TEMPERATURE))),
            max_tokens=int(get_val("AI_MAX_TOKENS", str(DEFAULT_MAX_TOKENS))),
            timeout=int(get_val("AI_TIMEOUT", str(DEFAULT_TIMEOUT))),
            autosave_interval=int(get_val("AUTOSAVE_INTERVAL", str(DEFAULT_AUTOSAVE_INTERVAL))),
            analysis_mode=get_val("AI_ANALYSIS_MODE", "STRIDE"),
            application_mode=get_val("AI_APPLICATION_MODE", "Production"),
            gemini_api_key=SecretStr(scrub(decrypt_api_key(get_val("GEMINI_API_KEY", "")))),
        )
        add_secret_to_redaction(config.gemini_api_key)
        return config

    def save(self) -> None:
        """Serializes the current configuration to the environment file with encryption."""
        THREATPILOT_HOME.mkdir(parents=True, exist_ok=True)
        path = str(CONFIG_FILE)
        fields = {
            "AI_PROVIDER_TYPE": self.provider_type,
            "AI_ENDPOINT_URL": self.endpoint_url,
            "AI_MODEL_NAME": self.model_name,
            "AI_TEMPERATURE": str(self.temperature),
            "AI_MAX_TOKENS": str(self.max_tokens),
            "AI_TIMEOUT": str(self.timeout),
            "AUTOSAVE_INTERVAL": str(self.autosave_interval),
            "AI_ANALYSIS_MODE": self.analysis_mode,
            "AI_APPLICATION_MODE": self.application_mode
        }
        try:
            for k, v in fields.items(): dotenv.set_key(path, k, v)
            if (key := self.gemini_api_key.get_secret_value()):
                if (enc := encrypt_api_key(key)): dotenv.set_key(path, "GEMINI_API_KEY", enc)
            else: dotenv.unset_key(path, "GEMINI_API_KEY")
        except Exception:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    for k, v in fields.items(): f.write(f"{k}={v}\n")
                    if (key := self.gemini_api_key.get_secret_value()):
                        f.write(f"GEMINI_API_KEY={encrypt_api_key(key)}\n")
            except Exception: pass

