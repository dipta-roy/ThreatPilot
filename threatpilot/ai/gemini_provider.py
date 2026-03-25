"""Google Gemini AI provider for ThreatPilot.

Implements the AIProviderInterface for the Google Generative Language API
using the 'gemini' model family with automated API version fallback.
"""

from __future__ import annotations

import base64
import httpx
import json
import socket
from typing import Any, Dict, Optional

from threatpilot.ai.ai_provider_interface import AIProviderInterface
from threatpilot.config.ai_config import AIConfig


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
        
        # For threat analysis, we need generous output budgets.
        # gemini-2.5-flash uses "thinking" tokens that count AGAINST maxOutputTokens,
        # so we must set a very high ceiling and constrain thinking separately.
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

        # For Gemini 2.5+ models, cap thinking tokens so the bulk of the budget
        # goes to actual JSON output rather than internal reasoning.
        model_name = (self.config.model_name or "").lower()
        if "2.5" in model_name or "2-5" in model_name:
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
        model = (self.config.model_name or "gemini-2.5-flash").strip().replace("\n", "").replace("\r", "")
        # Strip internal 'models/' prefix if user accidentally included it
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
                sep = "&" if "?" in custom_endpoint else "?"
                urls_to_try = [f"{custom_endpoint}{sep}key={api_key}"]
            else:
                host = custom_endpoint.rstrip("/")
                urls_to_try = [
                    f"{host}/v1/models/{model}:generateContent?key={api_key}",
                    f"{host}/v1beta/models/{model}:generateContent?key={api_key}"
                ]
        else:
            urls_to_try = [
                f"{self._api_host}/v1/models/{model}:generateContent?key={api_key}",
                f"{self._api_host}/v1beta/models/{model}:generateContent?key={api_key}"
            ]
            
        for url in urls_to_try:
            response = None
            try:
                async with httpx.AsyncClient(timeout=self.config.timeout) as client:
                    # Implement robust retry loop for 5xx Server Errors (like 503 Service Unavailable)
                    retries = 3
                    import asyncio
                    for attempt in range(retries):
                        response = await client.post(url, json=payload)
                        
                        # If the server is temporarily unavailable or overloaded, back off and retry
                        if response.status_code in [500, 502, 503, 504] and attempt < retries - 1:
                            await asyncio.sleep(2 ** attempt) # 1s, 2s, 4s...
                            continue
                            
                        # If 404 or 400, the model might only be in the other version channel (Common for new models)
                        if response.status_code in [400, 404]:
                            try:
                                error_details = response.json().get("error", {}).get("message", "")
                                last_error = f"API error ({response.status_code}): {error_details}"
                            except Exception:
                                last_error = f"API returned {response.status_code}"
                            break # Break the retry loop to immediately fall back to v1beta
                            
                        response.raise_for_status()
                        break # Break retry loop on success (or non-retryable 4xx handled below)

                    if response is not None and response.status_code in [400, 404]:
                        continue # Fall back to next version in urls_to_try
                        
                    data = response.json()
                    
                    usage = data.get("usageMetadata", {})
                    if "candidates" in data and len(data["candidates"]) > 0:
                        candidate = data["candidates"][0]
                        finish_reason = candidate.get("finishReason", "COMPLETED")
                        parts = candidate.get("content", {}).get("parts", [])
                        text = "".join(part.get("text", "") for part in parts if "text" in part)
                        return text, {"usage": usage, "finish_reason": finish_reason}
                    
                    return "", {"usage": usage}

            except httpx.HTTPError as exc:
                last_error = str(exc)
                if response is not None and getattr(response, "text", None):
                    # Capture response body if available for better debugging
                    try:
                        error_msg = str(response.text)
                        if error_msg.strip().startswith("{"):
                            try:
                                error_msg = response.json().get("error", {}).get("message", error_msg)
                            except Exception:
                                pass
                        last_error = f"HTTP {response.status_code}: {error_msg}"
                    except Exception:
                        pass
                
                # If we have a response and it's not a generic retryable error, stop falling back
                if response is not None and response.status_code not in [400, 404, 500, 502, 503, 504]:
                    # Non-retryable errors (like 401 Unauthorized, 403 Forbidden, 429 Rate Limit)
                    break
                # If there's no response (network error like timeout), we'll try the next version anyway 
                # or fail at the end of loop.

        error_context = url if 'url' in locals() else 'unknown URL'
        raise IOError(f"Gemini API request failed. Last attempted URL: {error_context}. Error: {last_error}")

    def is_available(self) -> bool:
        """Check if the Gemini API host is reachable."""
        try:
            socket.create_connection(("generativelanguage.googleapis.com", 443), timeout=3)
            return True
        except (socket.error, socket.timeout):
            return False
