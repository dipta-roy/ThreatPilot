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

        if self.config.custom_prompt:
            prompt += f"\nAdditional Instructions:\n{self.config.custom_prompt}\n"

        prompt += (
            "\nOutput Format Instructions:\n"
            "Return the analysis as a JSON list of threats. "
            "IMPORTANT: If the same type of vulnerability (e.g., Spoofing) affects multiple components, "
            "you MUST output a SEPARATE threat entry for EACH affected component. "
            "Do NOT group multiple components into a single threat entry.\n\n"
            "Each threat must have fields: threat_id (uuid), category (STRIDE), title, "
            "description, impact, likelihood (1-5), recommended_mitigation, "
            "affected_components (exactly one name), cvss_score (float, 0.0-10.0), and cvss_vector (CVSS 3.1 standard vector string)."
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
            prompt += f"- ID: {node.id} | Name: {node.name} | Type: {node.type}\n"
            if node.description:
                prompt += f"  Desc: {node.description}\n"

        # List Edges
        prompt += "\n--- DFD EDGES (Data Flows) ---\n"
        for edge in dfd.edges:
            prompt += f"- From: {edge.source_id} -> To: {edge.target_id}\n"
            prompt += f"  Name: {edge.name} | Protocol: {edge.protocol}\n"

        prompt += "\nIdentify specific potential threats based on STRIDE categories."
        return prompt

    def build_vision_detection_prompt(self, system_name: str) -> str:
        """Construct the user prompt for visual architecture detection."""
        return (
            f"Analyze the attached architecture diagram for the system: '{system_name}'.\n\n"
            "Your task is to identify and extract all key architectural components from the image.\n"
            "For each component, provide:\n"
            "1. Name of the component (extract from labels in the image).\n"
            "2. Type (Service, Datastore, Asset, Dataflow, or Trustboundary).\n"
            "3. Approximate bounding box coordinates in the format [x, y, width, height].\n\n"
            "Also identify data flows (arrows) and trust boundaries if visible.\n"
            "Represent all coordinates in a normalized range from 0 to 1000 relative to the image size.\n"
            "Return ONLY a strictly valid JSON object. SILENTLY perform all verification and do not output any draft reasoning or conversational text.\n"
            "The final response MUST start with '{' and end with '}'.\n"
            "Target Format:\n"
            "{\n"
            '  "components": [\n'
            '    {"name": "Verified Label", "type": "Service", "bounding_box": [x, y, w, h]},\n'
            "    ...\n"
            "  ]\n"
            "}"
        )
