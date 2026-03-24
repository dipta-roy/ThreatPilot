"""Ollama provider for ThreatPilot.

Implements the AIProviderInterface by communicating with a local Ollama
instance via its REST API (defaulting to port 11434).
"""

from __future__ import annotations

import httpx
import json
from typing import Any, Dict, List, Optional

from threatpilot.ai.ai_provider_interface import AIProviderInterface


class OllamaProvider(AIProviderInterface):
    """Local Ollama instance provider.

    Expects the Ollama server to be running (e.g. ``ollama serve``).
    """

    async def chat_complete(
        self,
        prompt: str,
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a chat completion request to the local Ollama instance.

        Args:
            prompt: The text containing DFD elements and instructions.
            system_instructions: The structured prompt metadata context.
            **kwargs: Extra parameters like temperature, top_p etc.

        Returns:
            The raw text content of the assistant message.

        Raises:
            IOError: If Ollama is not reachable.
            RuntimeError: If the model request fails.
        """
        messages: List[Dict[str, str]] = []
        if system_instructions:
            messages.append({"role": "system", "content": system_instructions})
        messages.append({"role": "user", "content": prompt})

        # Configuration from AIConfig
        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
                **kwargs
            }
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.config.endpoint_url}/api/chat",
                    json=payload
                )
                response.raise_for_status()
                data = response.json()
                text = str(data.get("message", {}).get("content", ""))
                return text, {"usage": data} # Ollama usage is in the root response object

        except httpx.HTTPError as exc:
            raise IOError(f"Could not reach Ollama at {self.config.endpoint_url}: {exc}")
        except Exception as exc:
            raise RuntimeError(f"Ollama request failed: {exc}")

    async def vision_complete(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Vision is not currently supported by local Ollama plugin."""
        raise NotImplementedError("Vision analysis is not supported via local Ollama.")

    def is_available(self) -> bool:
        """Check if the local Ollama instance is alive."""
        try:
            # We use synchronous check for local availability
            import requests # fallback to requests for simple sync healthcheck
            resp = requests.get(f"{self.config.endpoint_url}/api/tags", timeout=2)
            return resp.status_code == 200
        except:
            return False
