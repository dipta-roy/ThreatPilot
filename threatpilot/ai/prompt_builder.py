"""Prompt builder module for ThreatPilot.

Translates the Data Flow Diagram (DFD), system metadata, and user preferences
into structured natural language prompts for consumption by an AI model.
"""

from __future__ import annotations

from typing import Optional
from threatpilot.config.prompt_config import PromptConfig
from threatpilot.core.dfd_converter import DFDModel


class PromptBuilder:
    """Formatter that converts project models into AI-readable prompts.

    Handles construction of both global 'system' instructions and
    specific system-description 'user' prompts.
    """

    def __init__(self, config: PromptConfig) -> None:
        self.config = config

    def build_system_prompt(self) -> str:
        """Construct the context-setting system prompt.

        Returns:
            A string containing the AI's persona, industry context,
            and general security posture instructions.
        """
        prompt = (
            "You are 'ThreatPilot', an expert Cyber Security Architect. "
            "Your goal is to perform a detailed STRIDE threat analysis on "
            "the provided Data Flow Diagram (DFD).\n\n"
        )

        if self.config.industry_context:
            prompt += f"Target Industry: {self.config.industry_context}\n"

        prompt += f"Risk Preference: {self.config.risk_preference.upper()}\n"
        prompt += f"Security Posture: {self.config.security_posture}\n"

        if self.config.compliance_priority:
            prompt += f"Compliance Priority: {self.config.compliance_priority}\n"

        if self.config.business_context_policy:
            prompt += f"\nBusiness Context & Security Policy:\n{self.config.business_context_policy}\n"

        if self.config.custom_prompt:
            prompt += f"\nAdditional Instructions:\n{self.config.custom_prompt}\n"
        
        prompt += (
            "\nCRITICAL: You must adjust your threat identification, risk descriptions, and CVSS scores "
            "based on the specific values provided above for Industry, Risk Preference, Posture, and Policy. "
            "If a policy forbids certain data flows, those flows should be flagged with high priority.\n"
        )

        prompt += (
            "\nOutput Format Instructions:\n"
            "Return the analysis as a JSON list of threats. "
            "IMPORTANT: ALL OUTPUT MUST BE STRICTLY IN ENGLISH ONLY. Do not use any other language for any field.\n"
            "Analyze EVERY Data Flow (Edge) for communication-specific threats (e.g., Tampering, Information Disclosure) "
            "based on its protocol, and EVERY DFD Node for architectural threats.\n\n"
            "If a vulnerability affects multiple components or flows, "
            "you MUST output a SEPARATE threat entry for EACH affected item. "
            "Do NOT group multiple items into a single threat entry.\n\n"
            "Each threat must have fields: threat_id (uuid), category (STRIDE), title, "
            "description, impact (a concise sentence describing the technical or business impact), "
            "likelihood (1-5), recommended_mitigation, "
            "vulnerabilities (description of technical weaknesses that allow this threat), "
            "affected_components (exactly one name - either a component name or a data flow name), "
            "cvss_score (float, 0.0-10.0), and cvss_vector (CVSS 3.1 standard vector string)."
        )

        return prompt

    def build_user_prompt(self, dfd: DFDModel, system_name: str = "Target System") -> str:
        """Construct the user prompt describing the specific DFD.

        Args:
            dfd: The Data Flow Diagram model to analyze.
            system_name: Name of the project/system.

        Returns:
            A string listing all DFD nodes and edges for the AI.
        """
        prompt = f"Analyze the following architectural DFD for {system_name}:\n\n"

        # List Nodes
        prompt += "--- DFD NODES (Components) ---\n"
        for node in dfd.nodes:
            prompt += f"- Name: {node.name}\n"
            prompt += f"  Type: {node.type} | Element: {node.element_classification} | Asset: {node.asset_classification}\n"
            if node.description:
                prompt += f"  Desc: {node.description}\n"

        # List Edges (skip unmapped flows with no valid endpoints)
        prompt += "\n--- DFD EDGES (Data Flows) ---\n"
        valid_edge_count = 0
        for edge in dfd.edges:
            # Map IDs back to names for better context in STRIDE analysis
            src_name = next((n.name for n in dfd.nodes if n.id == edge.source_id), edge.source_id)
            dst_name = next((n.name for n in dfd.nodes if n.id == edge.target_id), edge.target_id)
            
            # Skip edges where both source and target are unmapped (empty strings)
            if not src_name.strip() and not dst_name.strip():
                continue
            
            valid_edge_count += 1
            prompt += f"- Flow: {edge.name} ({src_name} -> {dst_name})\n"
            prompt += f"  Protocol: {edge.protocol}\n"

        if valid_edge_count == 0:
            prompt += "(No data flows defined yet. Analyze each NODE for architectural threats regardless.)\n"

        prompt += "\nIMPORTANT: Identify specific potential threats based on the classifications and flow directions provided above."
        prompt += " Even if no data flows are listed, you MUST analyze EVERY node for architectural threats such as spoofing, tampering, repudiation, information disclosure, denial of service, and elevation of privilege."
        return prompt

    def build_vision_detection_prompt(self, system_name: str) -> str:
        """Construct the user prompt for visual architecture detection."""
        return (
            f"Analyze the attached architecture diagram for the system: '{system_name}'.\n\n"
            "Extract all components and data flows as a high-density JSON object.\n"
            "Keys for Components ('c'):\n"
            "- 'n': Name (from image labels)\n"
            "- 't': Type (Service, Datastore, Asset, Dataflow, or Trustboundary)\n"
            "- 'ec': Element Classification (Entity, Process, DataStore, or DataFlow)\n"
            "- 'ac': Asset Classification (Physical or Informational)\n\n"
            "Keys for Flows ('f'):\n"
            "- 'n': Flow Label\n"
            "- 's': Source component name\n"
            "- 'd': Destination component name\n"
            "- 'p': Protocol (e.g., HTTPS)\n\n"
            "IMPORTANT: ALL EXTRACTED LABELS AND TEXT MUST BE RETURNED IN ENGLISH ONLY.\n"
            "Return ONLY a strictly valid JSON object. Do not output any thinking or conversational text.\n"
            "Target Format:\n"
            "{\n"
            '  "c": [{"n": "A", "t": "Service", "ec": "Process", "ac": "Physical"}],\n'
            '  "f": [{"n": "F1", "s": "A", "d": "B", "p": "HTTPS"}]\n'
            "}"
        )
