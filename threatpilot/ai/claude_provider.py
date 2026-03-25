"""Anthropic Claude AI provider for ThreatPilot.

Implements the AIProviderInterface for the Anthropic Messages API
supporting Claude 3+ models.
"""

from __future__ import annotations

import httpx
import json
import socket
from typing import Any, Dict, Optional

from threatpilot.ai.ai_provider_interface import AIProviderInterface
from threatpilot.config.ai_config import AIConfig


class ClaudeProvider(AIProviderInterface):
    """Integrates with Anthropic's Claude models via REST API.

    API: https://api.anthropic.com/v1/messages
    """

    def __init__(self, config: AIConfig) -> None:
        super().__init__(config)
        self._url = "https://api.anthropic.com/v1/messages"
        self._version = "2023-06-01"

    async def chat_complete(
        self,
        prompt: str,
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a request to Claude and return the text response.

        Args:
            prompt: User-specified prompt text.
            system_instructions: Optional system context/instructions.
            **kwargs: Generation parameters (temperature, max_tokens, etc).

        Returns:
            Raw generated string response content.

        Raises:
            IOError: If Anthropic API is unreachable.
            RuntimeError: If the API returns an error or empty response.
        """
        model = self.config.model_name or "claude-3-haiku-20240307"
        api_key = self.config.api_key
        if not api_key:
             raise RuntimeError("Anthropic API key is required but missing.")

        headers = {
            "x-api-key": api_key,
            "anthropic-version": self._version,
            "content-type": "application/json"
        }

        # Structure payload for Anthropic Messages API
        messages = [
            {"role": "user", "content": prompt}
        ]

        payload = {
            "model": model,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
            "messages": messages
        }

        if system_instructions:
            payload["system"] = system_instructions

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            try:
                response = await client.post(self._url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                
                usage = data.get("usage", {})
                
                # Extract text from: { "content": [ { "type": "text", "text": "..." } ] }
                if "content" in data and len(data["content"]) > 0:
                    for part in data["content"]:
                        if part.get("type") == "text":
                            return part.get("text", ""), {"usage": usage}
                
                return "", {"usage": usage}

            except httpx.HTTPError as exc:
                # Provide useful error detail if available in response body
                error_detail = ""
                try:
                    error_data = response.json()
                    error_detail = f" - {error_data.get('error', {}).get('message', '')}"
                except (json.JSONDecodeError, UnboundLocalError):
                    pass
                except Exception:
                    pass
                raise IOError(f"HTTP request to Claude failed: {exc}{error_detail}")
            except (KeyError, IndexError, ValueError) as exc:
                raise RuntimeError(f"Failed to parse Claude API response: {exc}")

    async def vision_complete(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a request to Claude including a base64-encoded image."""
        import base64
        model = (self.config.model_name or "claude-3-haiku-20240307").strip()
        headers = {
            "x-api-key": self.config.api_key.strip(),
            "anthropic-version": self._version,
            "content-type": "application/json"
        }

        image_b64 = base64.b64encode(image_bytes).decode("utf-8")

        payload = {
            "model": model,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": mime_type,
                                "data": image_b64
                            }
                        },
                        {"type": "text", "text": prompt}
                    ]
                }
            ]
        }
        if system_instructions:
            payload["system"] = system_instructions

        async with httpx.AsyncClient(timeout=self.config.timeout) as client:
            response = await client.post(self._url, headers=headers, json=payload)
            data = response.json()
            usage = data.get("usage", {})
            text = data["content"][0]["text"] if data.get("content") else ""
            return text, {"usage": usage}

    def is_available(self) -> bool:
        """Check if the Anthropic API endpoint is reachable."""
        try:
            domain = "api.anthropic.com"
            socket.create_connection((domain, 443), timeout=3)
            return True
        except (socket.error, socket.timeout):
            return False
