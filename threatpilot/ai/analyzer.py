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
from threatpilot.core.threat_model import Threat, ThreatRegister, STRIDECategory, Vulnerability
from threatpilot.config.prompt_config import PromptConfig

BATCH_THRESHOLD = 6

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
        self.builder = PromptBuilder(prompt_config, analysis_mode=provider.config.analysis_mode)

    async def analyze(
        self, 
        dfd: DFDModel, 
        system_name: str,
        progress_callback: Optional[Callable] = None,
        result_callback: Optional[Callable[[ThreatRegister], None]] = None
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
        
        if progress_callback:
            should_start = await progress_callback(0, total_segments)
            if not should_start:
                return ThreatRegister(), "Analysis cancelled by user prior to segmentation.", {}

        all_threats = ThreatRegister()
        full_raw_text = []
        total_input = 0
        total_output = 0
        last_finish_reason = "UNKNOWN"

        for i in range(0, num_nodes, BATCH_THRESHOLD):
            current_segment = i // BATCH_THRESHOLD + 1
            
            if progress_callback and current_segment > 1:
                should_continue = await progress_callback(current_segment - 1, total_segments) 
                if not should_continue:
                    break

            batch_nodes = dfd.nodes[i : i + BATCH_THRESHOLD]
            node_ids = {n.id for n in batch_nodes}
            
            sub_edges = [e for e in dfd.edges if e.source_id in node_ids or e.target_id in node_ids]
            neighbor_ids = {e.source_id for e in sub_edges} | {e.target_id for e in sub_edges}
            
            sub_node_ids = node_ids | neighbor_ids
            sub_nodes = [n for n in dfd.nodes if n.id in sub_node_ids]
            sub_dfd = DFDModel(nodes=sub_nodes, edges=sub_edges, assets=dfd.assets)
            
            segment_name = f"{system_name} (Segment {current_segment} of {total_segments})"
            reg, raw, usage = await self._analyze_segment(sub_dfd, segment_name)
            
            for t in reg.threats:
                all_threats.add_threat(t)
            
            if hasattr(reg, "new_vulnerabilities"):
                all_threats.new_vulnerabilities.extend(reg.new_vulnerabilities)

            if result_callback:
                result_callback(reg)
            
            full_raw_text.append(f"--- Segment {current_segment} Analysis ---\n{raw}")
            
            seg_usage = usage.get("usage", usage)
            
            seg_in = seg_usage.get("promptTokenCount") or \
                     seg_usage.get("prompt_tokens") or \
                     seg_usage.get("prompt_eval_count") or 0
            total_input += seg_in
            
            seg_out = seg_usage.get("candidatesTokenCount") or \
                      seg_usage.get("completion_tokens") or \
                      seg_usage.get("eval_count") or 0
            total_output += seg_out
            
            last_finish_reason = usage.get("finish_reason", last_finish_reason)

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

        original_max = self.provider.config.max_tokens
        if original_max < MIN_ANALYSIS_TOKENS:
            self.provider.config.max_tokens = MIN_ANALYSIS_TOKENS

        last_error = None
        max_retries = 3
        
        for attempt in range(max_retries):
            try:
                raw_response, usage = await self.provider.chat_complete(
                    prompt=user_prompt,
                    system_instructions=system_prompt
                )
                
                if not raw_response:
                    raise RuntimeError("AI provider returned an empty response.")

                threat_dicts = parse_threat_list(raw_response)
                
                if not threat_dicts and len(dfd.nodes) > 0 and attempt < max_retries - 1:
                    import logging
                    logging.getLogger(__name__).warning(f"AI returned 0 threats for {len(dfd.nodes)} nodes. Retrying ({attempt+1}/{max_retries})...")
                    continue

                register = ThreatRegister()
                # Temporary storage for new vulnerabilities found in this segment
                new_vulns = []
                
                for t_data in threat_dicts:
                    try:
                        # Extract nested vulnerabilities before validation
                        raw_v = t_data.get("vulnerabilities", [])
                        
                        threat = Threat.model_validate(t_data)
                        
                        # ── Resolve element/asset names from flow source/target ──
                        if threat.affected_components:
                            # Build a search haystack from all narrative fields
                            haystack = (
                                f"{threat.affected_components} {threat.title} {threat.description}"
                            ).lower()
                            
                            node_by_id = {n.id: n for n in dfd.nodes}
                            
                            # 1. Try exact edge name match
                            edge_match = next(
                                (e for e in dfd.edges if e.name == threat.affected_components),
                                None
                            )
                            
                            # 2. Fuzzy edge match: source & target node names both in haystack
                            if not edge_match:
                                for e in dfd.edges:
                                    sn = node_by_id.get(e.source_id)
                                    tn = node_by_id.get(e.target_id)
                                    if sn and tn and sn.name.lower() in haystack and tn.name.lower() in haystack:
                                        edge_match = e
                                        break
                                        
                            if edge_match:
                                src_node = node_by_id.get(edge_match.source_id)
                                dst_node = node_by_id.get(edge_match.target_id)
                                if src_node:
                                    threat.affected_element_type = src_node.name
                                if dst_node:
                                    threat.affected_asset_type = dst_node.name
                            else:
                                # 3. Direct node match (threat is on a component, not a flow)
                                node_match = next(
                                    (n for n in dfd.nodes if n.name == threat.affected_components
                                     or n.name.lower() in haystack),
                                    None
                                )
                                if node_match:
                                    threat.affected_element_type = node_match.name
                                    threat.affected_asset_type   = node_match.name

                        # Process vulnerabilities
                        for v_item in raw_v:
                            if isinstance(v_item, dict):
                                try:
                                    v_obj = Vulnerability.model_validate(v_item)
                                    new_vulns.append(v_obj)
                                    if v_obj.vulnerability_id not in threat.vulnerability_ids:
                                        threat.vulnerability_ids.append(v_obj.vulnerability_id)
                                except Exception:
                                    pass
                                    
                        register.add_threat(threat)
                    except Exception as exc:
                        import logging
                        logging.getLogger(__name__).warning(f"Validation failed for parsed threat: {exc}")
                        continue
                
                # Attach new vulnerabilities to the register for MainWindow to merge
                register.new_vulnerabilities = new_vulns

                self.provider.config.max_tokens = original_max
                return register, raw_response, usage

            except Exception as exc:
                last_error = exc
                import logging
                logging.getLogger(__name__).error(f"Analysis attempt {attempt+1} failed: {exc}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                    continue
        
        self.provider.config.max_tokens = original_max
        raise last_error or RuntimeError("Analysis failed after maximum retries.")

    async def analyze_reasoning(self, threat: Threat) -> str:
        """Execute a separate AI call to generate deep technical reasoning for a specific threat."""
        prompt = self.builder.build_reasoning_prompt(threat)
        system_prompt = (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. "
            "Do NOT use any other language — including Chinese, Japanese, French, or any other — "
            "in ANY part of your response. This rule is absolute and overrides all model defaults.\n\n"
            "You are 'ThreatPilot XAI', a specialized security reasoning engine. "
            "Your task is to provide a deep technical 'Why' for identified security or privacy threats. "
            "Explain the architectural logic, attack path, and risk rationalization. "
            "Do NOT identify new threats. Be precise, professional, and use markdown."
        )
        
        try:
            raw_response, _ = await self.provider.chat_complete(
                prompt=prompt,
                system_instructions=system_prompt,
                response_mime_type="text/plain"
            )
            return str(raw_response or "AI Reasoning engine returned an empty response.")
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(f"XAI Reasoning failed: {exc}")
            return f"Failed to generate reasoning: {str(exc)}"

    async def analyze_vulnerability_reasoning(self, vuln: Vulnerability) -> str:
        """Execute a separate AI call to generate deep technical reasoning for a specific vulnerability."""
        prompt = self.builder.build_vulnerability_reasoning_prompt(vuln)
        system_prompt = (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. "
            "Do NOT use any other language in ANY part of your response.\n\n"
            "You are 'ThreatPilot XAI', a specialized security research engine. "
            "Provide a detailed technical explanation of the vulnerability, "
            "including attack vectors, root causes, and deep-dive mitigation strategy. "
            "Use markdown and be technical."
        )
        try:
            raw_response, _ = await self.provider.chat_complete(
                prompt=prompt,
                system_instructions=system_prompt,
                response_mime_type="text/plain"
            )
            return str(raw_response or "AI Reasoning engine returned an empty response.")
        except Exception as exc:
            import logging
            logging.getLogger(__name__).error(f"Vulnerability XAI failed: {exc}")
            return f"Failed to generate reasoning: {str(exc)}"
