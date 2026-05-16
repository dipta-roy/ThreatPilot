"""Abstract AI provider interface for ThreatPilot.

Defines the base class and protocol for all AI background providers (e.g. 
local Ollama or external REST APIs).
"""

from abc import ABC, abstractmethod
from typing import Any, List, Optional
from pydantic import BaseModel
from threatpilot.config.ai_config import AIConfig

class TokenUsage(BaseModel):
    """Standardized token usage metadata across AI providers."""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

class AIProviderInterface(ABC):
    """Defines the standard protocol for all AI backend implementations."""

    def __init__(self, config: AIConfig) -> None:
        self.config = config

    @abstractmethod
    async def chat_complete(
        self,
        prompt: str,
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, TokenUsage]:
        """Sends a text completion request and returns text with standardized usage."""
        pass

    @abstractmethod
    async def vision_complete(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, TokenUsage]:
        """Sends a multimodal completion request and returns text with standardized usage."""
        pass

    @abstractmethod
    async def get_available_models(self) -> List[str]:
        """Retrieves a list of supported models from the backend."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Verifies the availability and health of the AI backend."""
        pass
