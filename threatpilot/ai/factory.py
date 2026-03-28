"""AI Provider Factory for ThreatPilot.

Central point for instantiating different AI backends based on project
configuration.
"""

from __future__ import annotations

from threatpilot.config.ai_config import AIConfig
from threatpilot.ai.ai_provider_interface import AIProviderInterface
from threatpilot.ai.ollama_provider import OllamaProvider
from threatpilot.ai.gemini_provider import GeminiProvider


def create_ai_provider(config: AIConfig) -> AIProviderInterface:
    """Instantiate the correct AI provider based on the type string.

    Args:
        config: The Project's AI settings.

    Returns:
        A concrete instance of an AIProviderInterface.

    Raises:
        ValueError: If provider type is unknown.
    """
    p_type = config.provider_type.lower()
    
    if p_type == "ollama":
        return OllamaProvider(config)
    elif p_type == "gemini":
        return GeminiProvider(config)
    else:
        raise ValueError(f"Unknown AI provider type: {config.provider_type}")
