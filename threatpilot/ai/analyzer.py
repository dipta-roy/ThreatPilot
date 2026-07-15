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
from threatpilot.core.candidate_generator import generate_candidates

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
        
        # RAG KnowledgeBase has been removed

    async def analyze(
        self, 
        dfd: DFDModel, 
        system_name: str,
        progress_callback: Optional[Callable] = None,
        result_callback: Optional[Callable[[ThreatRegister], None]] = None,
        prompt_callback: Optional[Callable[[str, str], None]] = None,
        response_callback: Optional[Callable[[str], None]] = None,
        compliance_standards: list[str] = None
    ) -> tuple[ThreatRegister, str, TokenUsage]:
        """Performs a tree-traversal architectural analysis, focusing on data flows and trust boundaries."""
        num_nodes = len(dfd.nodes)
        
        from threatpilot.engine.graph import ArchitectureGraph, Node, Edge, AssetMetadata
        graph = ArchitectureGraph()
        
        # Translate UI models to Engine Tri-Graph
        for c in dfd.nodes:
            tz = c.trust_boundary if c.trust_boundary else "External"
            node_id = c.component_id if c.component_id else c.id
            graph.add_node(Node(id=node_id, name=c.name, type=c.type, trust_zone=tz))
            
        for f in dfd.edges:
            edge_id = f.flow_id if f.flow_id else f.id
            graph.add_edge(Edge(
                id=edge_id, source_id=f.source_id, target_id=f.target_id, protocol=f.protocol
            ), bidirectional=f.is_bidirectional)
            
        from threatpilot.core.dfd_converter import generate_deterministic_narrative
        global_narrative = generate_deterministic_narrative(dfd)

        # Deterministic Object-Centric Traversal: Components then Flows
        analysis_segments = []
        
        for c in dfd.nodes:
            sub_dfd = DFDModel(nodes=[c], edges=[], assets=dfd.assets, boundaries=dfd.boundaries)
            analysis_segments.append((sub_dfd, f"Component: {c.name}"))
            
        for f in dfd.edges:
            source = next((n for n in dfd.nodes if n.id == f.source_id or n.component_id == f.source_id), None)
            target = next((n for n in dfd.nodes if n.id == f.target_id or n.component_id == f.target_id), None)
            
            sub_nodes = []
            if source: sub_nodes.append(source)
            if target: sub_nodes.append(target)
            
            if f.is_bidirectional:
                sub_dfd_req = DFDModel(nodes=sub_nodes, edges=[f], assets=dfd.assets, boundaries=dfd.boundaries)
                analysis_segments.append((sub_dfd_req, f"Flow: {source.name if source else 'Unknown'} -> {target.name if target else 'Unknown'} (Request Path)"))
                f_rev = f.copy(deep=True)
                f_rev.id = f.id + "_reverse"
                f_rev.source_id, f_rev.target_id = f.target_id, f.source_id
                sub_dfd_resp = DFDModel(nodes=sub_nodes, edges=[f_rev], assets=dfd.assets, boundaries=dfd.boundaries)
                analysis_segments.append((sub_dfd_resp, f"Flow: {target.name if target else 'Unknown'} -> {source.name if source else 'Unknown'} (Response Path)"))
            else:
                sub_dfd = DFDModel(nodes=sub_nodes, edges=[f], assets=dfd.assets, boundaries=dfd.boundaries)
                analysis_segments.append((sub_dfd, f"Flow: {source.name if source else 'Unknown'} -> {target.name if target else 'Unknown'}"))
                
        total_segments = len(analysis_segments)
        if progress_callback and not await progress_callback(0, total_segments):
            return ThreatRegister(), "Analysis cancelled by user.", {}

        all_threats = ThreatRegister()
        full_raw_text = []
        total_input = total_output = 0

        # Concurrently run AI analysis on each object with a concurrency limit
        semaphore = asyncio.Semaphore(3)  # Max concurrent requests
        completed_tasks = 0

        async def analyze_task(idx, sub_dfd_seg, seg_title):
            async with semaphore:
                seg_name = f"Object Context: {seg_title} ({idx+1}/{total_segments})"
                res_reg, res_raw, res_usage = await self._analyze_segment(
                    sub_dfd_seg, seg_name, prompt_callback=prompt_callback, compliance_standards=compliance_standards, global_narrative=global_narrative
                )
                return idx, sub_dfd_seg, seg_name, res_reg, res_raw, res_usage

        tasks = [
            asyncio.create_task(analyze_task(idx, sub_dfd_seg, seg_title)) 
            for idx, (sub_dfd_seg, seg_title) in enumerate(analysis_segments)
        ]

        for completed in asyncio.as_completed(tasks):
            idx, sub_dfd_seg, seg_name, res_reg, res_raw, res_usage = await completed
            completed_tasks += 1
            
            if progress_callback:
                import inspect
                sig = inspect.signature(progress_callback)
                if 'active_node_ids' in sig.parameters:
                    node_ids = [n.id for n in sub_dfd_seg.nodes]
                    edge_ids = [e.id for e in sub_dfd_seg.edges]
                    if not await progress_callback(completed_tasks, total_segments, active_node_ids=node_ids, active_edge_ids=edge_ids):
                        break
                else:
                    if not await progress_callback(completed_tasks, total_segments):
                        break
            
            if response_callback: response_callback(res_raw)
            
            for t in res_reg.threats: all_threats.add_threat(t)
            if hasattr(res_reg, "new_vulnerabilities"): all_threats.new_vulnerabilities.extend(res_reg.new_vulnerabilities)
            if result_callback: result_callback(res_reg)
            
            full_raw_text.append(f"--- {seg_name} ---\n{res_raw}")
            total_input += res_usage.prompt_tokens
            total_output += res_usage.completion_tokens

        aggregated_usage = TokenUsage(
            prompt_tokens=total_input, completion_tokens=total_output, total_tokens=total_input + total_output
        )
        return all_threats, "\n\n".join(full_raw_text), aggregated_usage

    async def _analyze_segment(
        self,
        dfd: DFDModel,
        system_name: str,
        prompt_callback: Optional[Callable[[str, str], None]] = None,
        compliance_standards: list[str] = None,
        global_narrative: str = ""
    ) -> tuple[ThreatRegister, str, TokenUsage]:
        """Executes a single AI analysis pass for a specific architecture segment."""
        # Build a dynamic query based on the current DFD segment
        node_types = set([n.type.lower() for n in dfd.nodes if n.type])
        node_names = set([n.name.lower() for n in dfd.nodes if n.name])
        query_parts = list(node_types) + list(node_names)
        query = " ".join(query_parts)
        
        rag_context = ""
        
        narrative = global_narrative
        
        sys_p = self.builder.build_system_prompt()
        candidates = generate_candidates(dfd, self.builder.analysis_mode)
        usr_p = self.builder.build_user_prompt(dfd, system_name, rag_context, candidates=candidates, narrative=narrative)
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

    async def analyze_mitigation_reasoning(self, req: any) -> str:
        """Generates deep-dive technical reasoning for a specific mitigation requirement."""
        prompt = self.builder.build_mitigation_reasoning_prompt(req)
        system_prompt = (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. "
            "You are 'ThreatPilot XAI', a specialized security research engine. "
            "Provide a detailed technical explanation of the security control, implementation guide, and testing strategy. "
            "Use markdown."
        )
        try:
            raw_response, _ = await self.provider.chat_complete(prompt=prompt, system_instructions=system_prompt, response_mime_type="text/plain")
            return str(raw_response or "AI returned empty response.")
        except Exception as exc: return f"Mitigation XAI failed: {exc}"

    async def generate_narrative(self, dfd: DFDModel, system_name: str) -> str:
        """Generates a plain-text Architecture Narrative story for the entire model."""
        from threatpilot.core.dfd_converter import generate_deterministic_narrative
        
        base_narrative = generate_deterministic_narrative(dfd)
        
        prompt = (
            f"Here is a deterministic list of components and data flows for the system '{system_name}':\n\n"
            f"{base_narrative}\n\n"
            "Please rewrite this into a cohesive, highly descriptive narrative story. "
            "Write it in paragraphs (like 'A user interacts with the application...'). "
            "Explicitly mention how data traverses through components, when it crosses trust boundaries, "
            "and what sensitive assets are touched. Do not just list the components; tell the story of the data flow."
        )
        
        system_prompt = (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. "
            "You are a technical security architect. Output a professional architectural data-flow narrative. "
            "Use markdown format. Do not identify threats, just describe the architecture and flow."
        )
        
        try:
            ai_story, _ = await self.provider.chat_complete(prompt=prompt, system_instructions=system_prompt, response_mime_type="text/plain")
            if not ai_story:
                ai_story = "AI narrative generation returned empty."
        except Exception as exc:
            ai_story = f"AI narrative generation failed: {exc}"
            
        narrative = f"# Architecture Narrative: {system_name}\n\n"
        narrative += str(ai_story) + "\n\n"
        narrative += "---\n### Deterministic Flow Summary\n"
        narrative += base_narrative
        
        return narrative
