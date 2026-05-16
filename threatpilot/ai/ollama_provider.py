"""Ollama provider for ThreatPilot.

Implements the AIProviderInterface by communicating with a local Ollama
instance via its REST API (defaulting to port 11434).
"""

from __future__ import annotations
import base64
import json
from typing import Any, Dict, List, Optional
import httpx
from threatpilot.ai.ai_provider_interface import AIProviderInterface, TokenUsage
from threatpilot.utils.logger import get_logger

logger = get_logger(__name__)

class OllamaProvider(AIProviderInterface):
    """Integrates with a local Ollama instance via its REST API."""

    def __init__(self, config: AIConfig) -> None:
        super().__init__(config)
        self._base_url = (self.config.endpoint_url or "http://localhost:11434").rstrip("/")

    async def chat_complete(
        self,
        prompt: str,
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, TokenUsage]:
        """Sends a text-based chat completion request to the local Ollama service."""
        lang_directive = "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. DO NOT use Chinese or any other language for any field.\n\n"
        
        messages = []
        if system_instructions:
            sys_content = lang_directive + system_instructions
            messages.append({"role": "system", "content": sys_content})
        else:
            messages.append({"role": "system", "content": lang_directive + "You are an expert security analyst."})

        usr_content = f"{lang_directive}{prompt}\n\nREMEMBER: RESPOND IN ENGLISH ONLY."
        messages.append({"role": "user", "content": usr_content})

        valid_options = {
            "num_ctx", "temperature", "num_predict", "top_k", "top_p", 
            "repeat_penalty", "seed", "stop", "tfs_z", "typical_p", 
            "presence_penalty", "frequency_penalty", "mirostat", 
            "mirostat_tau", "mirostat_eta", "penalize_newline", 
            "num_keep", "num_thread"
        }
        
        options = {
            "temperature": self.config.temperature,
            "num_predict": self.config.max_tokens,
            "num_ctx": 8192,
        }
        for k, v in kwargs.items():
            if k in valid_options:
                options[k] = v

        payload = {
            "model": self.config.model_name or "llama3",
            "messages": messages,
            "stream": False,
            "options": options
        }
        
        mime_type = kwargs.get("response_mime_type", "application/json")
        if mime_type == "application/json":
            payload["format"] = "json"

        logger.info(f"Ollama Request: model={payload['model']}, tokens={self.config.max_tokens}, format={payload.get('format', 'text')}")
        try:
            async with httpx.AsyncClient(timeout=float(self.config.timeout)) as client:
                resp = await client.post(f"{self._base_url}/api/chat", json=payload)
                actual_model = payload.get("model", "unknown")
                if resp.status_code == 404: 
                    logger.error(f"Ollama Model Not Found: {actual_model}")
                    raise RuntimeError(f"Ollama Model Not Found: '{actual_model}'. Please ensure the model is pulled (run 'ollama pull {actual_model}') or select a valid model in AI Settings.")
                
                if resp.status_code != 200:
                    try:
                        err_data = resp.json()
                        err_msg = err_data.get("error", resp.text)
                    except Exception:
                        err_msg = resp.text
                    logger.error(f"Ollama API Error ({resp.status_code}): {err_msg}")
                    raise RuntimeError(f"Ollama request failed with status {resp.status_code}: {err_msg}")

                data = resp.json()
                text = str(data.get("message", {}).get("content", ""))
                
                is_debug = getattr(self.config, "application_mode", "Production") == "Debug"
                if is_debug:
                    logger.info(f"OLLAMA PROMPT:\n{prompt}")
                    if system_instructions:
                        logger.info(f"OLLAMA SYSTEM INSTRUCTIONS:\n{system_instructions}")
                    logger.info(f"OLLAMA RESPONSE ({len(text)} chars):\n{text}")
                else:
                    logger.info(f"OLLAMA PROMPT: {prompt[:200]}...")
                    logger.info(f"OLLAMA RESPONSE RECEIVED ({len(text)} chars): {text[:200]}...")
                
                usage = TokenUsage(
                    prompt_tokens=data.get("prompt_eval_count", 0),
                    completion_tokens=data.get("eval_count", 0),
                    total_tokens=data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
                )
                return text, usage
        except Exception as exc: raise RuntimeError(f"Ollama request failed: {exc}")

    async def vision_complete(
        self,
        prompt: str,
        image_bytes: bytes,
        mime_type: str = "image/png",
        system_instructions: Optional[str] = None,
        **kwargs: Any
    ) -> tuple[str, TokenUsage]:
        """Sends a multimodal request containing image data to the local Ollama service."""
        lang_directive = "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. DO NOT use Chinese or any other language.\n\n"
        
        content = f"{lang_directive}INSTRUCTIONS:\n{system_instructions}\n\nUSER REQUEST:\n{prompt}\n\nREMEMBER: RESPOND IN ENGLISH ONLY." if system_instructions else f"{lang_directive}{prompt}\n\nREMEMBER: RESPOND IN ENGLISH ONLY."
        messages = [{"role": "user", "content": content, "images": [base64.b64encode(image_bytes).decode("utf-8")]}]
        
        valid_options = {
            "num_ctx", "temperature", "num_predict", "top_k", "top_p", 
            "repeat_penalty", "seed", "stop", "tfs_z", "typical_p", 
            "presence_penalty", "frequency_penalty", "mirostat", 
            "mirostat_tau", "mirostat_eta", "penalize_newline", 
            "num_keep", "num_thread"
        }
        
        options = {
            "temperature": self.config.temperature,
            "num_predict": min(max(self.config.max_tokens, 4096), 8192),
            "num_ctx": 4096,
        }
        for k, v in kwargs.items():
            if k in valid_options:
                options[k] = v

        payload = {
            "model": self.config.model_name or "llava",
            "messages": messages,
            "stream": False,
            "options": options
        }

        mime_type = kwargs.get("response_mime_type", "application/json")
        if mime_type == "application/json":
            payload["format"] = "json"

        logger.info(f"Ollama Vision Request: model={payload['model']}, image_size={len(image_bytes)} bytes")
        try:
            timeout_val = float(self.config.timeout)
            limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout_val, read=timeout_val), limits=limits) as client:
                resp = await client.post(f"{self._base_url}/api/chat", json=payload)
                actual_model = payload.get("model", "unknown")
                if resp.status_code == 404:
                    logger.error(f"Ollama Vision Model Not Found: {actual_model}")
                    raise RuntimeError(f"Ollama Vision Model Not Found: '{actual_model}'. Please ensure the model is pulled (run 'ollama pull {actual_model}') or select a vision-capable model in AI Settings.")
                
                if resp.status_code != 200:
                    try:
                        err_data = resp.json()
                        err_msg = err_data.get("error", resp.text)
                    except Exception:
                        err_msg = resp.text
                    logger.error(f"Ollama Vision API Error ({resp.status_code}): {err_msg}")
                    raise RuntimeError(f"Ollama vision request failed with status {resp.status_code}: {err_msg}")
                    
                data = resp.json()
                text = str(data.get("message", {}).get("content", ""))
                logger.debug(f"Ollama Vision Response received: {len(text)} chars")
                usage = TokenUsage(
                    prompt_tokens=data.get("prompt_eval_count", 0),
                    completion_tokens=data.get("eval_count", 0),
                    total_tokens=data.get("prompt_eval_count", 0) + data.get("eval_count", 0)
                )
                return text, usage
        except httpx.ReadError as exc:
            logger.error(f"Ollama connection closed during vision task: {exc}")
            raise RuntimeError(f"Ollama connection reset. The vision model might be struggling with the image size or out of memory. Try a smaller image or a different model.")
        except Exception as exc: 
            logger.exception(f"Ollama vision request failed: {exc}")
            raise RuntimeError(f"Ollama vision request failed: {exc}")

    async def get_available_models(self) -> List[str]:
        """Retrieves the list of locally pulled models from Ollama."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self._base_url}/api/tags")
                resp.raise_for_status()
                return [m["name"] for m in resp.json().get("models", [])]
        except Exception: return []

    def is_available(self) -> bool:
        """Verifies if the local Ollama service is running and reachable."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{self._base_url}/api/tags")
                resp.raise_for_status(); return True
        except Exception: return False
