"""Google Gemini AI provider for ThreatPilot.

Implements the AIProviderInterface for the Google Generative Language API
using the 'gemini' model family.
"""

from __future__ import annotations

import httpx
import json
import socket
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from threatpilot.ai.ai_provider_interface import AIProviderInterface
from threatpilot.config.ai_config import AIConfig


class GeminiProvider(AIProviderInterface):
    """Integrates with Google's Gemini models via REST API.

    API: https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={API_KEY}
    """

    def __init__(self, config: AIConfig) -> None:
        super().__init__(config)
        self._base_url = "https://generativelanguage.googleapis.com/v1beta"

    async def chat_complete(
        self,
        prompt: str,
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a request to Gemini and return the choice text.

        Args:
            prompt: User-specified prompt text.
            system_instructions: Optional system context/instructions.
            **kwargs: Generation parameters (temperature, max_tokens, etc).

        Returns:
            Raw generated string response content.

        Raises:
            IOError: If Gemini is unreachable.
            RuntimeError: If the API returns an error or empty response.
        """
        model = self.config.model_name or "gemini-3-flash-preview"
        api_key = self.config.api_key
        if not api_key:
             raise RuntimeError("Gemini API key is required but missing.")

        url = f"{self._base_url}/models/{model}:generateContent?key={api_key}"

        # Combine contents
        contents = [{"role": "user", "parts": [{"text": prompt}]}]

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens,
                "topP": 0.8,
                "topK": 10
            }
        }

        if system_instructions:
            payload["system_instruction"] = {
                "parts": [{"text": system_instructions}]
            }

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            try:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                
                usage = data.get("usageMetadata", {})
                
                # Extract text from: { "candidates": [ { "content": { "parts": [ { "text": "..." } ] } } ] }
                if "candidates" in data and len(data["candidates"]) > 0:
                    parts = data["candidates"][0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", ""), {"usage": usage}
                
                return "", {"usage": usage}

            except httpx.HTTPError as exc:
                raise IOError(f"HTTP request to Gemini failed: {exc}")
            except (KeyError, IndexError, ValueError) as exc:
                raise RuntimeError(f"Failed to parse Gemini API response: {exc}")

    async def vision_complete(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a request to Gemini including an image."""
        import base64
        model = self.config.model_name or "gemini-3-flash-preview"
        api_key = self.config.api_key
        url = f"{self._base_url}/models/{model}:generateContent?key={api_key}"

        image_b64 = base64.b64encode(image_bytes).decode("utf-8")

        contents = [
            {
                "role": "user",
                "parts": [
                    {"text": prompt},
                    {"inline_data": {"mime_type": mime_type, "data": image_b64}}
                ]
            }
        ]

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens,
            }
        }

        if system_instructions:
            payload["system_instruction"] = {"parts": [{"text": system_instructions}]}

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            data = response.json()
            usage = data.get("usageMetadata", {})
            if "candidates" in data and len(data["candidates"]) > 0:
                text = data["candidates"][0]["content"]["parts"][0]["text"]
                return text, {"usage": usage}
            return "", {"usage": usage}

    def is_available(self) -> bool:
        """Check if the Gemini API endpoint is reachable.

        Note: This only verifies the host is up, not that the API key is 
        valid for specific models.
        """
        try:
            domain = "generativelanguage.googleapis.com"
            socket.create_connection((domain, 443), timeout=3)
            return True
        except (socket.error, socket.timeout):
            return False
