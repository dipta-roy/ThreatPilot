"""External provider for ThreatPilot.

Implements the AIProviderInterface by communicating with a hosted/external 
REST API (OpenAI-compatible) for chat completions.
"""

from __future__ import annotations

import httpx
from typing import Any, Dict, List, Optional

from threatpilot.ai.ai_provider_interface import AIProviderInterface


class ExternalProvider(AIProviderInterface):
    """External/Hosted API provider (e.g. OpenAI, Anthropic, or custom proxy).

    Assumes an OpenAI-compatible /chat/completions endpoint structure.
    """

    async def chat_complete(
        self,
        prompt: str,
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a completions request to an external provider.

        Args:
            prompt: Text describing components and flows.
            system_instructions: The project context/metadata.
            **kwargs: Extra model-specific parameters.

        Returns:
            The raw text content of the response.

        Raises:
            IOError: If communication with the remote host fails.
            RuntimeError: If the remote returns an error.
        """
        messages: List[Dict[str, str]] = []
        if system_instructions:
            messages.append({"role": "system", "content": system_instructions})
        messages.append({"role": "user", "content": prompt})

        # Base configuration from AIConfig
        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            **kwargs
        }

        # Auth headers
        headers = {}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    self.config.endpoint_url,
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
                data = response.json()
                
                # Assume standard OpenAI output structure: choices[0].message.content
                choices = data.get("choices", [])
                usage = data.get("usage", {})
                if choices:
                    text = str(choices[0].get("message", {}).get("content", ""))
                    return text, {"usage": usage}
                return "", {"usage": usage}

        except httpx.HTTPStatusError as exc:
             raise RuntimeError(f"External API error ({exc.response.status_code}): {exc.response.text}")
        except httpx.HTTPError as exc:
            raise IOError(f"Could not reach external provider at {self.config.endpoint_url}: {exc}")
        except Exception as exc:
            raise RuntimeError(f"External request process failed: {exc}")

    async def vision_complete(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Vision analysis is not yet implemented for generic external/OpenAI proxies."""
        raise NotImplementedError("Vision analysis is not supported via this specific provider.")

    def is_available(self) -> bool:
        """Check if the external API endpoint appears to be reachable."""
        try:
            # External healthchecks vary greatly. We attempt to check if the
            # endpoint domain responds in a reasonable time.
            import socket
            from urllib.parse import urlparse
            parsed = urlparse(self.config.endpoint_url)
            if not parsed.hostname:
                return False
            
            socket.create_connection((parsed.hostname, parsed.port or 80), timeout=2)
            return True
        except:
            return False
