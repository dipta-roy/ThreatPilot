"""Google Gemini AI provider for ThreatPilot.

Implements the AIProviderInterface for the Google Generative Language API
using the 'gemini' model family with automated API version fallback.
"""

from __future__ import annotations
import asyncio
import base64
import httpx
import json
import logging
import socket
from typing import Any, Dict, Optional
from threatpilot.ai.ai_provider_interface import AIProviderInterface
from threatpilot.config.ai_config import AIConfig
from threatpilot.utils.logger import get_logger

logger = get_logger(__name__)

class GeminiProvider(AIProviderInterface):
    """Integrates with Google's Gemini models via REST API.

    Features automated fallback between v1 (Stable) and v1beta (Preview)
    to handle various model availability states.
    """

    def __init__(self, config: AIConfig) -> None:
        super().__init__(config)
        self._api_host = "https://generativelanguage.googleapis.com"

    async def chat_complete(
        self,
        prompt: str,
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a request to Gemini and return the choice text."""
        contents = [{"role": "user", "parts": [{"text": prompt}]}]
        
        max_out = max(self.config.max_tokens, 16384)
        
        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": max_out,
                "topP": 0.95,
                "topK": 40,
                "responseMimeType": "application/json"
            }
        }

        model_name = (self.config.model_name or "").lower()
        if "2.0" in model_name or "2-0" in model_name:
            payload["generationConfig"]["thinkingConfig"] = {
                "thinkingBudget": 2048
            }
        
        elif "2.5" in model_name or "2-5" in model_name:
            payload["generationConfig"]["thinkingConfig"] = {
                "thinkingBudget": 2048
            }

        if system_instructions:
            payload["system_instruction"] = {"parts": [{"text": system_instructions}]}

        return await self._execute_with_fallback(payload)

    async def vision_complete(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, dict]:
        """Send a request to Gemini including an image."""
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

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": self.config.max_tokens or 4096,
                "topP": 0.95,
                "topK": 40,
                "responseMimeType": "application/json"
            }
        }

        if system_instructions:
            payload["system_instruction"] = {"parts": [{"text": system_instructions}]}

        return await self._execute_with_fallback(payload)

    async def _execute_with_fallback(self, payload: Dict[str, Any]) -> tuple[str, dict]:
        """Execute request with automated URL version fallback (v1 -> v1beta)."""
        model = (self.config.model_name or "gemini-3.1-flash-lite-preview").strip().replace("\n", "").replace("\r", "")
        if model.lower().startswith("models/"):
            model = model[7:]
            
        api_key = self.config.api_key.strip().replace("\n", "").replace("\r", "")
        if not api_key:
            raise RuntimeError("Gemini API key is missing.")

        last_error = None
        
        custom_endpoint = self.config.endpoint_url.strip()
        urls_to_try = []
        
        if custom_endpoint and custom_endpoint != "http://localhost:11434":
            if ":generateContent" in custom_endpoint:
                urls_to_try = [custom_endpoint]
            else:
                host = custom_endpoint.rstrip("/")
                urls_to_try = [
                    f"{host}/v1beta/models/{model}:generateContent",
                    f"{host}/v1/models/{model}:generateContent"
                ]
        else:
            urls_to_try = [
                f"{self._api_host}/v1beta/models/{model}:generateContent",
                f"{self._api_host}/v1/models/{model}:generateContent"
            ]
            
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": api_key
        }
            
        for url in urls_to_try:
            response = None
            try:
                async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                    retries = 3
                    for attempt in range(retries):
                        logger.debug(f"Sending request to Gemini: {url}")
                        response = await client.post(url, json=payload, headers=headers)
                        
                        if response.status_code in [500, 502, 503, 504] and attempt < retries - 1:
                            logger.warning(f"Gemini server error {response.status_code}. Retrying...")
                            await asyncio.sleep(2 ** attempt)
                            continue
                            
                        if response.status_code in [400, 404]:
                            last_error = f"HTTP {response.status_code} on {url}"
                            break
                            
                        response.raise_for_status()
                        
                        data = response.json()
                        usage = data.get("usageMetadata", {})
                        if "candidates" in data and len(data["candidates"]) > 0:
                            candidate = data["candidates"][0]
                            finish_reason = candidate.get("finishReason", "COMPLETED")
                            parts = candidate.get("content", {}).get("parts", [])
                            text = "".join(part.get("text", "") for part in parts if "text" in part)
                            return text, {"usage": usage, "finish_reason": finish_reason}
                        return "", {"usage": usage}

                if response is not None and response.status_code in [400, 404]:
                    continue

            except httpx.HTTPError as exc:
                if response is not None:
                    try:
                        error_msg = response.json().get("error", {}).get("message", response.text)
                    except Exception:
                        error_msg = response.text
                    
                    if response.status_code == 404:
                        last_error = f"Model Not Found (404): The model '{model}' was not recognized. {error_msg}"
                    elif response.status_code == 401:
                        last_error = f"Invalid API Key (401): The provided key was rejected by Google. {error_msg}"
                    elif response.status_code == 429:
                        last_error = f"Rate Limit Exceeded (429): Too many requests to Gemini. {error_msg}"
                    else:
                        last_error = f"HTTP {response.status_code}: {error_msg}"
                else:
                    last_error = f"Connection Failed: {type(exc).__name__} - {exc}"
                
                if response is not None and response.status_code not in [400, 404, 500, 502, 503, 504]:
                    break

        error_context = url if 'url' in locals() else 'unknown URL'
        error_msg = f"Gemini API request failed. Last attempted URL: {error_context}. Error: {last_error}"
        logger.error(error_msg)
        raise IOError(error_msg)

    def is_available(self) -> bool:
        """Check if the Gemini API host is reachable."""
        try:
            socket.create_connection(("generativelanguage.googleapis.com", 443), timeout=3)
            return True
        except (socket.error, socket.timeout):
            return False
