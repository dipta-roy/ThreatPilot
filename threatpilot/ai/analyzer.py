"""Threat analysis orchestration module for ThreatPilot.

Orchestrates the end-to-end AI analysis workflow:
1. Constructing the prompts using PromptBuilder.
2. Executing the completion via an AIProviderInterface.
3. Parsing the result into a structured ThreatRegister using ResponseParser.
"""

from __future__ import annotations

import asyncio
from typing import List, Optional, Callable

from threatpilot.ai.ai_provider_interface import AIProviderInterface
from threatpilot.ai.prompt_builder import PromptBuilder
from threatpilot.ai.response_parser import parse_threat_list
from threatpilot.core.dfd_converter import DFDModel
from threatpilot.core.threat_model import Threat, ThreatRegister, STRIDECategory
from threatpilot.config.prompt_config import PromptConfig


# Max number of components to process in a single AI prompt
# Architecture larger than this will be automatically segmented to avoid token limits
# Max number of components to process in a single AI prompt
# Architecture larger than this will be automatically segmented to avoid token limits
# (Reduced to 6 to better handle segmented analysis feedback on smaller diagrams)
BATCH_THRESHOLD = 6

# Minimum output tokens required for a useful STRIDE analysis.
# Each node/edge generates ~200-400 tokens of threat JSON, so a 6-node batch
# needs at least ~2400 tokens. We use a generous minimum to avoid truncation.
MIN_ANALYSIS_TOKENS = 16384


class ThreatAnalyzer:
    """Analyzer that maps DFD elements to specific security threats via AI.

    Args:
        provider: The concrete AI backend implementation.
        prompt_config: Current user preferences for prompt generation.
    """

    def __init__(
        self,
        provider: AIProviderInterface,
        prompt_config: PromptConfig
    ) -> None:
        self.provider = provider
        self.prompt_config = prompt_config
        self.builder = PromptBuilder(prompt_config)

    async def analyze(
        self, 
        dfd: DFDModel, 
        system_name: str,
        progress_callback: Optional[Callable] = None
    ) -> tuple[ThreatRegister, str, dict]:
        """Execute a full STRIDE analysis on the provided DFD.

        Automatically switches to segmented analysis if the diagram is too large.
        If progress_callback is provided, it will be called after each segment
        with (current_segment, total_segments). If it returns False, analysis stops.
        """
        num_nodes = len(dfd.nodes)
        total_segments = (num_nodes + BATCH_THRESHOLD - 1) // BATCH_THRESHOLD

        if num_nodes <= BATCH_THRESHOLD:
            return await self._analyze_segment(dfd, system_name)
        
        # Segmented Analysis - Initial Prompt
        if progress_callback:
            should_start = await progress_callback(0, total_segments) # 0 indicates initial segment check
            if not should_start:
                return ThreatRegister(), "Analysis cancelled by user prior to segmentation.", {}

        all_threats = ThreatRegister()
        full_raw_text = []
        total_input = 0
        total_output = 0
        last_finish_reason = "UNKNOWN"

        # Divide nodes into batches
        for i in range(0, num_nodes, BATCH_THRESHOLD):
            current_segment = i // BATCH_THRESHOLD + 1
            
            # If we already did segment 1 and are about to do segment 2+, prompt again
            if progress_callback and current_segment > 1:
                should_continue = await progress_callback(current_segment - 1, total_segments) 
                if not should_continue:
                    break

            batch_nodes = dfd.nodes[i : i + BATCH_THRESHOLD]
            node_ids = {n.id for n in batch_nodes}
            
            # Sub-DFD should include the nodes and all edges connected to them
            # also include 'neighbor' nodes connected by those edges for context
            sub_edges = [e for e in dfd.edges if e.source_id in node_ids or e.target_id in node_ids]
            neighbor_ids = {e.source_id for e in sub_edges} | {e.target_id for e in sub_edges}
            
            # Ensure batch nodes are always included
            sub_node_ids = node_ids | neighbor_ids
            sub_nodes = [n for n in dfd.nodes if n.id in sub_node_ids]
            sub_dfd = DFDModel(nodes=sub_nodes, edges=sub_edges)
            
            # Analysis focus note for the prompt
            segment_name = f"{system_name} (Segment {current_segment} of {total_segments})"
            reg, raw, usage = await self._analyze_segment(sub_dfd, segment_name)
            
            # Merge
            for t in reg.threats:
                is_duplicate = any(
                    et.title == t.title and 
                    et.affected_components == t.affected_components and
                    et.description == t.description
                    for et in all_threats.threats
                )
                if not is_duplicate:
                    all_threats.add_threat(t)
            
            full_raw_text.append(f"--- Segment {current_segment} Analysis ---\n{raw}")
            
            # Aggregate usage
            seg_usage = usage.get("usage", usage)
            total_input += seg_usage.get("promptTokenCount", seg_usage.get("input_tokens", 0))
            total_output += seg_usage.get("candidatesTokenCount", seg_usage.get("output_tokens", 0))
            last_finish_reason = usage.get("finish_reason", last_finish_reason)

        # Return in the same format as _analyze_segment for consistent handling
        aggregated_usage = {
            "usage": {
                "promptTokenCount": total_input,
                "candidatesTokenCount": total_output,
                "totalTokenCount": total_input + total_output
            },
            "finish_reason": last_finish_reason
        }
        return all_threats, "\n\n".join(full_raw_text), aggregated_usage

    async def _analyze_segment(self, dfd: DFDModel, system_name: str) -> tuple[ThreatRegister, str, dict]:
        """Internal helper for a single AI pass with retry logic (M.2)."""
        system_prompt = self.builder.build_system_prompt()
        user_prompt = self.builder.build_user_prompt(dfd, system_name)

        # Enforce minimum token budget
        original_max = self.provider.config.max_tokens
        if original_max < MIN_ANALYSIS_TOKENS:
            self.provider.config.max_tokens = MIN_ANALYSIS_TOKENS

        last_error = None
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                # Execute AI Request
                raw_response, usage = await self.provider.chat_complete(
                    prompt=user_prompt,
                    system_instructions=system_prompt
                )
                
                if not raw_response:
                    raise RuntimeError("AI provider returned an empty response.")

                # Parse AI results into structured dictionaries (uses Pydantic internally)
                threat_dicts = parse_threat_list(raw_response)
                
                # If we got NO threats for a multi-node DFD, something might have failed in formatting
                if not threat_dicts and len(dfd.nodes) > 0 and attempt < max_retries - 1:
                    import logging
                    logging.getLogger(__name__).warning(f"AI returned 0 threats for {len(dfd.nodes)} nodes. Retrying ({attempt+1}/{max_retries})...")
                    continue

                register = ThreatRegister()
                for t_data in threat_dicts:
                    try:
                        # Map and validate (The ResponseParser already uses Threat.model_validate)
                        # but we re-map enum here for extra safety
                        cat_str = str(t_data.get("category", "")).strip()
                        category = self._map_category(cat_str)
                        
                        t_data["category"] = category
                        threat = Threat.model_validate(t_data)
                        register.add_threat(threat)
                    except Exception:
                        continue

                # Success
                self.provider.config.max_tokens = original_max
                return register, raw_response, usage

            except Exception as exc:
                last_error = exc
                import logging
                logging.getLogger(__name__).error(f"Analysis attempt {attempt+1} failed: {exc}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(1) # Brief backoff
                    continue
        
        # Restore and fail
        self.provider.config.max_tokens = original_max
        raise last_error or RuntimeError("Analysis failed after maximum retries.")

    def _map_category(self, cat_str: str) -> STRIDECategory:
        """Fuzzy map text categories from AI to the standard STRIDE enum."""
        s = str(cat_str).lower().strip()
        if "spoofing" in s: return STRIDECategory.SPOOFING
        if "tampering" in s: return STRIDECategory.TAMPERING
        if "repudiation" in s: return STRIDECategory.REPUDIATION
        if "disclosure" in s or "privacy" in s: return STRIDECategory.INFORMATION_DISCLOSURE
        if "denial" in s or "dos" in s: return STRIDECategory.DENIAL_OF_SERVICE
        if "privilege" in s or "elevation" in s: return STRIDECategory.ELEVATION_OF_PRIVILEGE
        
        return STRIDECategory.INFORMATION_DISCLOSURE
