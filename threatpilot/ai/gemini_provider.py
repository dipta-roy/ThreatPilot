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
from threatpilot.ai.ai_provider_interface import AIProviderInterface, TokenUsage
from threatpilot.config.ai_config import AIConfig
from threatpilot.utils.logger import get_logger

logger = get_logger(__name__)

class GeminiProvider(AIProviderInterface):
    """Integrates with Google's Gemini family of models via REST API, supporting v1/v1beta fallback."""

    def __init__(self, config: AIConfig) -> None:
        super().__init__(config)
        self._api_host = "https://generativelanguage.googleapis.com"

    async def chat_complete(
        self,
        prompt: str,
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, TokenUsage]:
        """Sends a text-based chat completion request to the Gemini API."""
        contents = [{"role": "user", "parts": [{"text": prompt}]}]
        max_out = max(self.config.max_tokens, 16384)
        mime_type = kwargs.get("response_mime_type", "application/json")
        
        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": max_out,
                "topP": 0.95,
                "topK": 40,
                "responseMimeType": mime_type
            }
        }

        model = (self.config.model_name or "").lower()
        if any(x in model for x in ["2.0", "2-0", "2.5", "2-5"]):
            payload["generationConfig"]["thinkingConfig"] = {"thinkingBudget": 2048}

        is_debug = getattr(self.config, "application_mode", "Production") == "Debug"
        if is_debug:
            logger.info(f"GEMINI PROMPT:\n{prompt}")
        else:
            logger.info(f"GEMINI PROMPT: {prompt[:200]}...")

        if system_instructions:
            payload["system_instruction"] = {"parts": [{"text": system_instructions}]}
            if is_debug:
                logger.info(f"GEMINI SYSTEM INSTRUCTIONS:\n{system_instructions}")
            else:
                logger.info(f"GEMINI SYSTEM INSTRUCTIONS: {system_instructions[:200]}...")

        raw_text, usage = await self._execute_with_fallback(payload)
        if is_debug:
            logger.info(f"GEMINI RESPONSE ({len(raw_text)} chars):\n{raw_text}")
        else:
            logger.info(f"GEMINI RESPONSE RECEIVED ({len(raw_text)} chars): {raw_text[:200]}...")
        return raw_text, usage

    async def vision_complete(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, TokenUsage]:
        """Sends a multimodal request containing image data to the Gemini API."""
        contents = [{
            "role": "user",
            "parts": [
                {"text": prompt},
                {"inline_data": {"mime_type": mime_type, "data": base64.b64encode(image_bytes).decode("utf-8")}}
            ]
        }]
        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": self.config.temperature,
                "maxOutputTokens": max(self.config.max_tokens, 16384),
                "topP": 0.95, "topK": 40, "responseMimeType": "application/json"
            }
        }
        if system_instructions: payload["system_instruction"] = {"parts": [{"text": system_instructions}]}
        return await self._execute_with_fallback(payload)

    async def _execute_with_fallback(self, payload: Dict[str, Any]) -> tuple[str, TokenUsage]:
        """Executes the API request with automated URL version fallback and retry logic."""
        model = (self.config.model_name or "gemini-3.1-flash-lite-preview").strip().replace("\n", "").replace("\r", "")
        if model.lower().startswith("models/"): model = model[7:]
        api_key = self.config.api_key.strip().replace("\n", "").replace("\r", "")
        if not api_key: raise RuntimeError("Gemini API key is missing.")

        custom_endpoint = self.config.endpoint_url.strip()
        if custom_endpoint and custom_endpoint != "http://localhost:11434":
            urls = [custom_endpoint] if ":generateContent" in custom_endpoint else [f"{custom_endpoint.rstrip('/')}/v1beta/models/{model}:generateContent", f"{custom_endpoint.rstrip('/')}/v1/models/{model}:generateContent"]
        else: urls = [f"{self._api_host}/v1beta/models/{model}:generateContent", f"{self._api_host}/v1/models/{model}:generateContent"]
            
        headers = {"Content-Type": "application/json", "x-goog-api-key": api_key}
        last_error = None
        for url in urls:
            try:
                async with httpx.AsyncClient(timeout=float(self.config.timeout)) as client:
                    for attempt in range(3):
                        resp = await client.post(url, json=payload, headers=headers)
                        if resp.status_code != 200:
                            error_body = resp.text
                            logger.error(f"Gemini API Error ({resp.status_code}) on {url}: {error_body}")
                            if resp.status_code in [500, 502, 503, 504] and attempt < 2:
                                await asyncio.sleep(2 ** attempt); continue
                            resp.raise_for_status()
                        data = resp.json(); meta = data.get("usageMetadata", {})
                        usage = TokenUsage(
                            prompt_tokens=meta.get("promptTokenCount", 0),
                            completion_tokens=meta.get("candidatesTokenCount", 0),
                            total_tokens=meta.get("totalTokenCount", 0)
                        )
                        text = ""
                        if "candidates" in data and data["candidates"]:
                            candidate = data["candidates"][0]
                            content = candidate.get("content")
                            if content and "parts" in content:
                                text = "".join(p.get("text", "") for p in content["parts"] if "text" in p)
                            elif candidate.get("finishReason") == "SAFETY":
                                text = "AI response was blocked by safety filters. Please try a different prompt or adjust sensitivity."
                        return text, usage
            except Exception as exc: last_error = str(exc)

        raise IOError(f"Gemini API request failed: {last_error}")

    async def get_available_models(self) -> List[str]:
        """Retrieves common Gemini models or lists them if the API key is set."""
        defaults = ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-2.0-flash-exp"]
        if not self.config.api_key: return defaults
        try:
            url = f"{self._api_host}/v1beta/models?key={self.config.api_key}"
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return [m["name"].replace("models/", "") for m in resp.json().get("models", []) if "generateContent" in m.get("supportedGenerationMethods", [])]
        except Exception: pass
        return defaults

    def is_available(self) -> bool:
        """Checks if the Google Generative Language API is reachable."""
        try:
            socket.create_connection(("generativelanguage.googleapis.com", 443), timeout=3)
            return True
        except Exception: return False
