"""Base HTTP AI provider for ThreatPilot."""

from __future__ import annotations
import asyncio
import json
import httpx
from typing import Any, Dict, List, Optional
from threatpilot.ai.ai_provider_interface import AIProviderInterface, TokenUsage
from threatpilot.config.ai_config import AIConfig
from threatpilot.utils.logger import get_logger

logger = get_logger(__name__)

class BaseHTTPProvider(AIProviderInterface):
    """Abstract base provider that handles httpx async sessions and rate limit retries."""

    def __init__(self, config: AIConfig) -> None:
        super().__init__(config)

    async def execute_http_post(self, urls: List[str], payload: Dict[str, Any], headers: Optional[Dict[str, str]] = None) -> httpx.Response:
        """Executes an HTTP POST with built-in retry and fallback logic across URLs."""
        last_error = None
        for url in urls:
            try:
                async with httpx.AsyncClient(timeout=float(self.config.timeout)) as client:
                    for attempt in range(3):
                        resp = await client.post(url, json=payload, headers=headers)
                        
                        if resp.status_code == 429:
                            # Handle rate limits
                            sleep_sec = 5.0
                            try:
                                err_data = json.loads(resp.text)
                                details = err_data.get("error", {}).get("details", [])
                                for detail in details:
                                    if "RetryInfo" in detail.get("@type", ""):
                                        delay_str = detail.get("retryDelay", "5s")
                                        sleep_sec = float(delay_str[:-1]) if delay_str.endswith("s") else float(delay_str)
                                        break
                            except Exception:
                                pass
                            
                            logger.warning(f"API rate limit hit (429). Sleeping for {sleep_sec:.2f}s...")
                            await asyncio.sleep(sleep_sec)
                            
                            retry_resp = await client.post(url, json=payload, headers=headers)
                            if retry_resp.status_code == 200:
                                return retry_resp
                            else:
                                retry_resp.raise_for_status()

                        if resp.status_code != 200:
                            if resp.status_code in [500, 502, 503, 504] and attempt < 2:
                                await asyncio.sleep(2 ** attempt)
                                continue
                            
                            # Log and let caller handle specific status codes
                            logger.error(f"HTTP Error ({resp.status_code}) on {url}: {resp.text}")
                            return resp
                            
                        return resp
            except Exception as exc:
                last_error = str(exc)

        raise IOError(f"API request failed across all fallbacks: {last_error}")
