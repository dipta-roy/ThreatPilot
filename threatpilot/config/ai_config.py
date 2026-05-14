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

import sys
from pathlib import Path

def _get_config_path() -> Path:
    """Determine the most reliable path for the config.env file."""
    # Use a dedicated hidden directory in the user's home for all persistent state
    # This ensures writability even in restricted frozen environments.
    base_dir = Path.home() / ".threatpilot"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir / "config.env"

_ENV_FILE = _get_config_path()


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
    model_name: str = ""
    temperature: float = 0.7
    max_tokens: int = 8192
    timeout: int = 3600
    gemini_api_key: SecretStr = SecretStr("")
    autosave_interval: int = 5
    analysis_mode: str = "STRIDE"

    model_config = ConfigDict(
        extra="ignore",
        protected_namespaces=(),
    )

    @property
    def api_key(self) -> str:
        """Helper to get the appropriate API key based on provider type."""
        if self.provider_type == "gemini":
            return self.gemini_api_key.get_secret_value()
        return ""

    @api_key.setter
    def api_key(self, value: str) -> None:
        """Helper to set the API key for the current provider."""
        if self.provider_type == "gemini":
            self.gemini_api_key = SecretStr(value)

    @classmethod
    def load(cls) -> AIConfig:
        """Load configuration from config.env, decrypting API keys."""
        path_str = str(_ENV_FILE.absolute())
        
        if not _ENV_FILE.exists():
            # Ensure the directory exists even if the file doesn't
            _ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
            instance = cls()
            instance.save()
            return instance
            
        # Read values directly from the file to avoid process environment pollution
        values = dotenv.dotenv_values(path_str)
        
        def get_opt(key: str, default: str) -> str:
            val = values.get(key, default)
            if val is None:
                return default
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                val = val[1:-1]
            return val.strip().replace("\n", "").replace("\r", "")

        def scrub_key(key: str) -> str:
            if not key: return ""
            clean = key.replace("\n", "").replace("\r", "").strip()
            if clean.lower().startswith("traceback"):
                 return ""
            return clean

        config = cls(
            provider_type=get_opt("AI_PROVIDER_TYPE", "ollama"),
            endpoint_url=get_opt("AI_ENDPOINT_URL", "http://localhost:11434"),
            model_name=get_opt("AI_MODEL_NAME", ""),
            temperature=float(get_opt("AI_TEMPERATURE", "0.7")),
            max_tokens=int(get_opt("AI_MAX_TOKENS", "8192")),
            timeout=int(get_opt("AI_TIMEOUT", "3600")),
            autosave_interval=int(get_opt("AUTOSAVE_INTERVAL", "5")),
            analysis_mode=get_opt("AI_ANALYSIS_MODE", "STRIDE"),
            gemini_api_key=SecretStr(scrub_key(decrypt_api_key(get_opt("GEMINI_API_KEY", "")))),
        )
        
        add_secret_to_redaction(config.gemini_api_key)
        return config

    def save(self) -> None:
        """Save configuration to config.env, encrypting API keys."""
        path_str = str(_ENV_FILE.absolute())
        try:
            # Ensure parent directory exists
            _ENV_FILE.parent.mkdir(parents=True, exist_ok=True)
            _ENV_FILE.touch(exist_ok=True)
            
            dotenv.set_key(path_str, "AI_PROVIDER_TYPE", self.provider_type)
            dotenv.set_key(path_str, "AI_ENDPOINT_URL", self.endpoint_url)
            dotenv.set_key(path_str, "AI_MODEL_NAME", self.model_name)
            dotenv.set_key(path_str, "AI_TEMPERATURE", str(self.temperature))
            dotenv.set_key(path_str, "AI_MAX_TOKENS", str(self.max_tokens))
            dotenv.set_key(path_str, "AI_TIMEOUT", str(self.timeout))
            dotenv.set_key(path_str, "AUTOSAVE_INTERVAL", str(self.autosave_interval))
            dotenv.set_key(path_str, "AI_ANALYSIS_MODE", self.analysis_mode)
            
            api_key_str = self.gemini_api_key.get_secret_value()
            if api_key_str:
                encrypted = encrypt_api_key(api_key_str)
                if encrypted:
                    dotenv.set_key(path_str, "GEMINI_API_KEY", encrypted)
            else:
                # If no key, explicitly remove it from the file
                dotenv.unset_key(path_str, "GEMINI_API_KEY")
                
        except Exception:
            # Fallback to direct file write if dotenv fails or permissions are tricky
            try:
                with open(path_str, "w", encoding="utf-8") as f:
                    f.write(f"AI_PROVIDER_TYPE={self.provider_type}\n")
                    f.write(f"AI_ENDPOINT_URL={self.endpoint_url}\n")
                    f.write(f"AI_MODEL_NAME={self.model_name}\n")
                    f.write(f"AI_TEMPERATURE={self.temperature}\n")
                    f.write(f"AI_MAX_TOKENS={self.max_tokens}\n")
                    f.write(f"AI_TIMEOUT={self.timeout}\n")
                    f.write(f"AUTOSAVE_INTERVAL={self.autosave_interval}\n")
                    f.write(f"AI_ANALYSIS_MODE={self.analysis_mode}\n")
                    api_key_str = self.gemini_api_key.get_secret_value()
                    if api_key_str:
                        f.write(f"GEMINI_API_KEY={encrypt_api_key(api_key_str)}\n")
            except Exception:
                pass

