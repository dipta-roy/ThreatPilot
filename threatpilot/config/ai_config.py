"""AI configuration module for ThreatPilot.

Contains the ``AIConfig`` model representing AI provider settings.
"""

from __future__ import annotations

from pydantic import BaseModel


class AIConfig(BaseModel):
    """Configuration for the AI provider used by a project.

    Attributes:
        provider_type: The AI backend type ('ollama', 'external', 'gemini', or 'claude').
        endpoint_url: The URL of the AI endpoint (ignored for native Gemini/Claude).
        model_name: The model identifier to use.
        temperature: Sampling temperature (0.0 - 2.0).
        max_tokens: Maximum number of tokens in the response.
        timeout: Request timeout in seconds.
        api_key: Optional API key for external providers.
    """

    provider_type: str = "ollama"
    endpoint_url: str = "http://localhost:11434"
    model_name: str = "llama3"
    temperature: float = 0.7
    max_tokens: int = 4096
    timeout: int = 120
    api_key: str = ""

