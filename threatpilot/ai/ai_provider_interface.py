"""Abstract AI provider interface for ThreatPilot.

Defines the base class and protocol for all AI background providers (e.g. 
local Ollama or external REST APIs).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from threatpilot.config.ai_config import AIConfig


class AIProviderInterface(ABC):
    """Abstract base class for all AI backends.

    Defining a standard interface allows the application to switch between
    local (Ollama) and hosted/external models seamlessly.
    """

    def __init__(self, config: AIConfig) -> None:
        self.config = config

    @abstractmethod
    async def chat_complete(
        self,
        prompt: str,
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a request to the AI model and return the text response.

        Args:
            prompt: The user-supplied prompt text.
            system_instructions: Optional system instructions/context.
            **kwargs: Extra model-specific parameters.

        Returns:
            A tuple of (raw text content, metadata dict).
            Metadata dict contains 'prompt_tokens', 'completion_tokens', 'total_tokens'.

        Raises:
            IOError: If connection to the provider fails.
            RuntimeError: If the provider returns an error response.
        """
        pass

    @abstractmethod
    async def vision_complete(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a request to a multimodal AI model including an image.

        Args:
            prompt: User-specified prompt text.
            image_bytes: Raw binary data of the image.
            mime_type: MIME type of the image (e.g. 'image/png').
            system_instructions: Optional system context.
            **kwargs: Generation parameters.
            
        Returns:
            A tuple of (raw text content, metadata dict).
            Metadata dict contains 'usage' information.
        """
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the AI backend is reachable and correctly configured.

        Returns:
            True if the provider responds to a health/version ping.
        """
        pass
