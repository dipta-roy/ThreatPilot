"""Threat analysis orchestration module for ThreatPilot.

Orchestrates the end-to-end AI analysis workflow:
1. Constructing the prompts using PromptBuilder.
2. Executing the completion via an AIProviderInterface.
3. Parsing the result into a structured ThreatRegister using ResponseParser.
"""

from __future__ import annotations
import asyncio
from typing import List, Optional, Callable
from threatpilot.ai.ai_provider_interface import AIProviderInterface, TokenUsage
from threatpilot.ai.prompt_builder import PromptBuilder
from threatpilot.ai.response_parser import parse_threat_list
from threatpilot.core.dfd_converter import DFDModel
from threatpilot.core.threat_model import Threat, ThreatRegister, STRIDECategory, Vulnerability
from threatpilot.config.prompt_config import PromptConfig

from threatpilot.core.constants import ANALYSIS_BATCH_THRESHOLD, MIN_ANALYSIS_TOKENS

class ThreatAnalyzer:
    """Orchestrates the AI-driven threat analysis workflow for system architectures."""

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
        result_callback: Optional[Callable[[ThreatRegister], None]] = None,
        prompt_callback: Optional[Callable[[str, str], None]] = None,
        response_callback: Optional[Callable[[str], None]] = None
    ) -> tuple[ThreatRegister, str, TokenUsage]:
        """Performs a full architectural analysis, segmenting the workload if necessary."""
        num_nodes = len(dfd.nodes)
        total_segments = (num_nodes + ANALYSIS_BATCH_THRESHOLD - 1) // ANALYSIS_BATCH_THRESHOLD

        if num_nodes <= ANALYSIS_BATCH_THRESHOLD:
            reg, raw, usage = await self._analyze_segment(dfd, system_name, prompt_callback=prompt_callback)
            if response_callback:
                response_callback(raw)
            return reg, raw, usage
        
        if progress_callback:
            if not await progress_callback(0, total_segments):
                return ThreatRegister(), "Analysis cancelled by user.", {}

        all_threats = ThreatRegister()
        full_raw_text = []
        total_input = total_output = 0
        last_finish_reason = "UNKNOWN"

        for i in range(0, num_nodes, ANALYSIS_BATCH_THRESHOLD):
            current_segment = i // ANALYSIS_BATCH_THRESHOLD + 1
            if progress_callback and current_segment > 1:
                if not await progress_callback(current_segment - 1, total_segments): break

            batch_nodes = dfd.nodes[i : i + ANALYSIS_BATCH_THRESHOLD]
            node_ids = {n.id for n in batch_nodes}
            sub_edges = [e for e in dfd.edges if e.source_id in node_ids or e.target_id in node_ids]
            sub_nodes = [n for n in dfd.nodes if n.id in (node_ids | {e.source_id for e in sub_edges} | {e.target_id for e in sub_edges})]
            
            segment_name = f"{system_name} (Segment {current_segment} of {total_segments})"
            reg, raw, usage = await self._analyze_segment(
                DFDModel(nodes=sub_nodes, edges=sub_edges, assets=dfd.assets, boundaries=dfd.boundaries),
                segment_name,
                prompt_callback=prompt_callback
            )
            if response_callback:
                response_callback(raw)
            
            for t in reg.threats: all_threats.add_threat(t)
            if hasattr(reg, "new_vulnerabilities"): all_threats.new_vulnerabilities.extend(reg.new_vulnerabilities)
            if result_callback: result_callback(reg)
            
            full_raw_text.append(f"--- Segment {current_segment} ---\n{raw}")
            total_input += usage.prompt_tokens
            total_output += usage.completion_tokens
            last_finish_reason = "COMPLETED"

        aggregated_usage = TokenUsage(
            prompt_tokens=total_input,
            completion_tokens=total_output,
            total_tokens=total_input + total_output
        )
        return all_threats, "\n\n".join(full_raw_text), aggregated_usage

    async def _analyze_segment(
        self,
        dfd: DFDModel,
        system_name: str,
        prompt_callback: Optional[Callable[[str, str], None]] = None
    ) -> tuple[ThreatRegister, str, TokenUsage]:
        """Executes a single AI analysis pass for a specific architecture segment."""
        sys_p = self.builder.build_system_prompt()
        usr_p = self.builder.build_user_prompt(dfd, system_name)
        if prompt_callback:
            prompt_callback(sys_p, usr_p)
        orig_max = self.provider.config.max_tokens
        if orig_max < MIN_ANALYSIS_TOKENS: self.provider.config.max_tokens = MIN_ANALYSIS_TOKENS

        last_err = None
        for attempt in range(3):
            try:
                raw, usage = await self.provider.chat_complete(prompt=usr_p, system_instructions=sys_p)
                if not raw: raise RuntimeError("Empty AI response.")
                
                threats = parse_threat_list(raw, components=dfd.nodes, flows=dfd.edges, mode=self.provider.config.analysis_mode)
                if not threats and dfd.nodes and attempt < 2: continue

                reg = ThreatRegister(threats=threats)
                reg.new_vulnerabilities = [v for t in threats for v in t.vulnerabilities]
                self.provider.config.max_tokens = orig_max
                return reg, raw, usage
            except Exception as exc:
                last_err = exc
                if attempt < 2: await asyncio.sleep(1)
        
        self.provider.config.max_tokens = orig_max
        raise last_err or RuntimeError("Analysis failed.")

    async def analyze_reasoning(self, threat: Threat) -> str:
        """Generates technical architectural reasoning for a specific threat."""
        prompt = self.builder.build_reasoning_prompt(threat)
        is_stride = self.builder.analysis_mode == "STRIDE"
        role = "security" if is_stride else "privacy"
        
        # Methodology-specific field names to help the AI
        field_1 = "attack_path" if is_stride else "privacy_impact_path"
        field_2 = "architectural_root_cause"
        field_3 = "risk_rationalization"
        field_4 = "framework_alignment"

        system_prompt = (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. "
            f"You are 'ThreatPilot XAI', a specialized {role} reasoning engine. "
            f"Explain the architectural logic, {field_1.replace('_', ' ')}, and risk rationalization. "
            "Do NOT identify new threats. Be precise, professional, and use markdown.\n\n"
            "OUTPUT FORMAT: Return a JSON object with the following fields:\n"
            f"- attack_vector (string)\n"
            f"- architectural_root_cause (string)\n"
            f"- risk_rationalization (string)\n"
            f"- framework_alignment (string)"
        )
        try:
            # We use application/json to trigger Ollama's format="json" mode
            raw_response, _ = await self.provider.chat_complete(prompt=prompt, system_instructions=system_prompt, response_mime_type="application/json")
            if not raw_response or not str(raw_response).strip():
                return "The AI returned an empty response. This often happens if safety filters are triggered or if the model is overloaded."
            return str(raw_response)
        except Exception as exc: return f"Reasoning failed: {exc}"

    async def analyze_vulnerability_reasoning(self, vuln: Vulnerability) -> str:
        """Generates deep-dive technical reasoning for a specific vulnerability."""
        prompt = self.builder.build_vulnerability_reasoning_prompt(vuln)
        system_prompt = (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. "
            "You are 'ThreatPilot XAI', a specialized security research engine. "
            "Provide a detailed technical explanation of the vulnerability, root causes, and mitigation strategy. "
            "Use markdown."
        )
        try:
            raw_response, _ = await self.provider.chat_complete(prompt=prompt, system_instructions=system_prompt, response_mime_type="text/plain")
            return str(raw_response or "AI returned empty response.")
        except Exception as exc: return f"Vulnerability XAI failed: {exc}"
