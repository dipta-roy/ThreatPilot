"""Threat analysis orchestration module for ThreatPilot.

Orchestrates the end-to-end AI analysis workflow:
1. Constructing the prompts using PromptBuilder.
2. Executing the completion via an AIProviderInterface.
3. Parsing the result into a structured ThreatRegister using ResponseParser.
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

from threatpilot.ai.ai_provider_interface import AIProviderInterface
from threatpilot.ai.prompt_builder import PromptBuilder
from threatpilot.ai.response_parser import parse_threat_list
from threatpilot.core.dfd_converter import DFDModel
from threatpilot.core.threat_model import Threat, ThreatRegister, STRIDECategory
from threatpilot.config.prompt_config import PromptConfig


# Max number of components to process in a single AI prompt
# Architecture larger than this will be automatically segmented to avoid token limits
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

    async def analyze(self, dfd: DFDModel, system_name: str) -> tuple[ThreatRegister, str, dict]:
        """Execute a full STRIDE analysis on the provided DFD.

        Automatically switches to segmented analysis if the diagram is too large.
        """
        if len(dfd.nodes) <= BATCH_THRESHOLD:
            return await self._analyze_segment(dfd, system_name)
        
        # Segmented Analysis
        from threatpilot.core.dfd_converter import DFDNode, DFDEdge
        all_threats = ThreatRegister()
        full_raw_text = []
        total_input = 0
        total_output = 0
        last_finish_reason = "UNKNOWN"

        # Divide nodes into overlapping batches
        for i in range(0, len(dfd.nodes), BATCH_THRESHOLD):
            batch_nodes = dfd.nodes[i : i + BATCH_THRESHOLD]
            node_ids = {n.id for n in batch_nodes}
            
            # Sub-DFD should include the nodes and all edges connected to them
            # also include 'neighbor' nodes connected by those edges for context
            sub_edges = [e for e in dfd.edges if e.source_id in node_ids or e.target_id in node_ids]
            neighbor_ids = {e.source_id for e in sub_edges} | {e.target_id for e in sub_edges}
            
            # Ensure batch nodes are always included (even if no edges reference them)
            sub_node_ids = node_ids | neighbor_ids
            sub_nodes = [n for n in dfd.nodes if n.id in sub_node_ids]
            sub_dfd = DFDModel(nodes=sub_nodes, edges=sub_edges)
            
            # Analysis focus note for the prompt
            segment_name = f"{system_name} (Segment {i//BATCH_THRESHOLD + 1})"
            reg, raw, usage = await self._analyze_segment(sub_dfd, segment_name)
            
            # Merge
            for t in reg.threats:
                # Deduplicate based on title and affected component (crude)
                if not any(et.title == t.title and et.affected_components == t.affected_components for et in all_threats.threats):
                    all_threats.add_threat(t)
            
            full_raw_text.append(f"--- Segment {i//BATCH_THRESHOLD + 1} Analysis ---\n{raw}")
            
            # Aggregate usage from the nested structure returned by provider
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
        """Internal helper for a single AI pass."""
        system_prompt = self.builder.build_system_prompt()
        user_prompt = self.builder.build_user_prompt(dfd, system_name)

        # Enforce minimum token budget for threat analysis.
        # The user's config.max_tokens may be set low (e.g. 4096) for general use,
        # but STRIDE analysis of multiple components requires much more headroom.
        original_max = self.provider.config.max_tokens
        if original_max < MIN_ANALYSIS_TOKENS:
            self.provider.config.max_tokens = MIN_ANALYSIS_TOKENS

        try:
            # Execute AI Request
            raw_response, usage = await self.provider.chat_complete(
                prompt=user_prompt,
                system_instructions=system_prompt
            )
        finally:
            # Restore original config value
            self.provider.config.max_tokens = original_max

        if not raw_response:
             raise RuntimeError("AI provider returned an empty response.")

        # Parse AI results into structured dictionaries
        threat_dicts = parse_threat_list(raw_response)
        
        register = ThreatRegister()
        
        for t_data in threat_dicts:
            try:
                # Map case-insensitive STRIDE category strings to our enum
                cat_str = str(t_data.get("category", "")).strip()
                category = self._map_category(cat_str)

                # Safer numeric conversion
                def _to_int(val, default=3):
                    try: return int(float(str(val)))
                    except: return default
                
                def _to_float(val, default=0.0):
                    try: return float(str(val))
                    except: return default

                threat = Threat(
                    category=category,
                    title=t_data.get("title", "New Threat"),
                    description=t_data.get("description", ""),
                    impact=t_data.get("impact", ""),
                    likelihood=_to_int(t_data.get("likelihood", 3)),
                    mitigation=t_data.get("recommended_mitigation", "") or t_data.get("mitigation", ""),
                    vulnerabilities=str(t_data.get("vulnerabilities", "")),
                    affected_components=str(t_data.get("affected_components", "")),
                    cvss_score=_to_float(t_data.get("cvss_score", 0.0)),
                    cvss_vector=str(t_data.get("cvss_vector", "")),
                    source_dfd_node=t_data.get("threat_id") 
                )
                register.add_threat(threat)
            except Exception:
                continue

        return register, raw_response, usage

    def _map_category(self, cat_str: str) -> STRIDECategory:
        """Map text categories from AI to the standard STRIDE enum."""
        cmap = {
            "spoofing": STRIDECategory.SPOOFING,
            "tampering": STRIDECategory.TAMPERING,
            "repudiation": STRIDECategory.REPUDIATION,
            "information disclosure": STRIDECategory.INFORMATION_DISCLOSURE,
            "denial of service": STRIDECategory.DENIAL_OF_SERVICE,
            "elevation of privilege": STRIDECategory.ELEVATION_OF_PRIVILEGE
        }
        return cmap.get(cat_str.lower(), STRIDECategory.TAMPERING)
