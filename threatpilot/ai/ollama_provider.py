"""Ollama provider for ThreatPilot.

Implements the AIProviderInterface by communicating with a local Ollama
instance via its REST API (defaulting to port 11434).
"""

from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

import httpx
from threatpilot.ai.ai_provider_interface import AIProviderInterface
from threatpilot.utils.logger import get_logger

logger = get_logger(__name__)


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
                
                if response.status_code == 404:
                    # Capture specific message if Ollama tells us the model is missing
                    try:
                        error_text = response.json().get("error", response.text)
                    except Exception:
                        error_text = response.text
                    raise RuntimeError(f"Ollama Model Not Found (404): The model '{self.config.model_name}' is not downloaded. Run 'ollama pull {self.config.model_name}' in your terminal. Details: {error_text}")
                
                response.raise_for_status()
                data = response.json()
                text = str(data.get("message", {}).get("content", ""))
                return text, {"usage": data}

        except httpx.ConnectError:
            raise IOError(f"Connection Failed: Could not reach Ollama at {self.config.endpoint_url}. Ensure 'ollama serve' is running.")
        except httpx.TimeoutException:
            raise IOError(f"Request Timeout: Ollama took too long to respond. You may need to increase the timeout in AI Settings.")
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Ollama API Error: {exc}")
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
        """Send a multimodal vision request to a local Ollama vision model.
        
        Ollama supports vision models (e.g. llava, qwen2.5vl) by passing
        base64-encoded images in the ``images`` field of the user message.

        Args:
            prompt: The text prompt describing what to extract from the image.
            image_bytes: Raw binary data of the image.
            mime_type: MIME type of the image (unused by Ollama).
            system_instructions: Optional system context.
            **kwargs: Extra generation parameters.

        Returns:
            A tuple of (raw text content, metadata dict).
        """
        b64_image = base64.b64encode(image_bytes).decode("utf-8")

        messages: List[Dict[str, Any]] = []
        if system_instructions:
            messages.append({"role": "system", "content": system_instructions})
        messages.append({
            "role": "user",
            "content": prompt,
            "images": [b64_image],
        })

        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
                **kwargs,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.config.endpoint_url}/api/chat",
                    json=payload,
                )
                
                if response.status_code == 404:
                    # Model not found specifically
                    try:
                        error_text = response.json().get("error", response.text)
                    except Exception:
                        error_text = response.text
                    raise RuntimeError(f"Ollama Vision Model Not Found (404): The vision model '{self.config.model_name}' is not downloaded. Run 'ollama pull {self.config.model_name}' in your terminal. Details: {error_text}")
                
                response.raise_for_status()
                data = response.json()
                text = str(data.get("message", {}).get("content", ""))
                return text, {"usage": data}

        except httpx.ConnectError:
            raise IOError(f"Connection Failed: Could not reach Ollama at {self.config.endpoint_url}. Ensure 'ollama serve' is running.")
        except httpx.TimeoutException:
            raise IOError(f"Request Timeout: Ollama took too long to respond. You may need to increase the timeout in AI Settings.")
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Ollama Vision API Error: {exc}")
        except Exception as exc:
            raise RuntimeError(f"Ollama vision request failed: {exc}")

    def is_available(self) -> bool:
        """Test if Ollama is running and accessible."""
        try:
            # Use httpx (consistent with the rest of your AI providers)
            with httpx.Client(timeout=5.0) as client:
                response = client.get("http://localhost:11434/api/tags")
                response.raise_for_status()
                return True
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
            return False
        except Exception as e:
            # Log the real error but don't expose technical details to user
            logger.error(f"Ollama connection test failed: {e}")
            return False
