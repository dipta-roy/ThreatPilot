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

        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": self.config.max_tokens,
                "num_ctx": 16384,
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
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 500:
                hint = (
                    "\n\nHINT: A 500 Internal Server Error in Ollama usually means:\n"
                    "1. Out of Memory (OOM): Try closing other apps.\n"
                    "2. Context Window: The request might be too large for the model's current configuration.\n"
                    "3. Model Crash: Try restarting the Ollama service."
                )
                raise RuntimeError(f"Ollama API Error (500): {exc}{hint}")
            raise RuntimeError(f"Ollama API Error: {exc}")
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

        full_content = prompt
        if system_instructions:
            full_content = f"INSTRUCTIONS:\n{system_instructions}\n\nUSER REQUEST:\n{prompt}"
            
        messages = [{
            "role": "user",
            "content": full_content,
            "images": [b64_image],
        }]

        payload = {
            "model": self.config.model_name,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": self.config.temperature,
                "num_predict": max(self.config.max_tokens, 16384),
                "num_ctx": 16384,
                **kwargs,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                response = await client.post(
                    f"{self.config.endpoint_url}/api/chat",
                    json=payload,
                )
                
                if response.status_code >= 500:
                    try:
                        error_data = response.json()
                        error_msg = error_data.get("error", "")
                        if "out of memory" in error_msg.lower():
                            raise RuntimeError(f"Ollama Out Of Memory: The model '{self.config.model_name}' exceeded available VRAM. Try a smaller model (llava:7b) or close other GPU-intensive apps.")
                        if error_msg:
                            raise RuntimeError(f"Ollama Server Failure: {error_msg}")
                    except (ValueError, TypeError, json.JSONDecodeError):
                        pass

                if response.status_code == 404:
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
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 500:
                hint = (
                    "\n\nDIAGNOSTIC HINTS:\n"
                    "1. Model Type: Ensure you are using a VISION model (llava, qwen2-vl). "
                    "Sending images to models like 'qwen2.5:72b' (non-vision) will crash Ollama with a 500 error.\n"
                    "2. VRAM: Images require significant EXTRA memory. Try closing browsers or secondary monitors.\n"
                    "3. Model Swap: Try 'ollama pull moondream:latest' (very lightweight) to verify if vision logic is working."
                )
                raise RuntimeError(f"Ollama Vision API Error (500): {exc}{hint}")
            raise RuntimeError(f"Ollama Vision API Error: {exc}")
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Ollama Vision API Error: {exc}")
        except Exception as exc:
            raise RuntimeError(f"Ollama vision request failed: {exc}")

    def is_available(self) -> bool:
        """Test if Ollama is running and accessible."""
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get("http://localhost:11434/api/tags")
                response.raise_for_status()
                return True
        except (httpx.ConnectError, httpx.TimeoutException, httpx.RequestError):
            return False
        except Exception as e:
            logger.error(f"Ollama connection test failed: {e}")
            return False
