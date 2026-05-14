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

    def __init__(self, config: PromptConfig, analysis_mode: str = "STRIDE") -> None:
        self.config = config
        self.analysis_mode = analysis_mode.upper()

    def _sanitize(self, text: str | None) -> str:
        """Escape XML delimiters and control characters (C.1)."""
        if not text:
            return ""
        str_val = str(text)
        str_val = str_val.replace("<", "[").replace(">", "]")
        str_val = str_val.replace("\n", " ").replace("\r", " ").replace("\t", " ")
        return str_val

    def build_system_prompt(self) -> str:
        """Construct the context-setting system prompt."""
        role = "Cyber Security Architect" if self.analysis_mode == "STRIDE" else "Privacy Architect"
        methodology = "STRIDE" if self.analysis_mode == "STRIDE" else "LINDDUN"
        
        prompt = (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English.\n\n"
            f"You are 'ThreatPilot', an expert {role}. "
            f"Your goal is to perform a detailed {methodology} analysis on "
            "the provided Data Flow Diagram (DFD).\n\n"
            "DEFINITIONS:\n"
            f"1. THREAT: A technical weakness in the system architecture (following {methodology} principles).\n"
            "2. VULNERABILITY: A description of HOW an exploit can be used on the identified threat/weakness to perform an attack.\n"
            "3. TRUST BOUNDARY: A perimeter of control. Elements with 'trust_boundary: None (External)' are beyond your control and should be treated as untrusted sources/sinks.\n"
            "4. NESTED BOUNDARY: Boundaries can be nested (e.g., App Zone inside Mobile Device Zone). This creates layers of defense-in-depth. Analyze threats considering the cumulative protections and exposures of the entire hierarchy.\n"
            "5. BIDIRECTIONAL FLOW: If a flow is marked 'is_bidirectional: True', it means communication occurs in both directions. You MUST identify threats for both the primary (Source -> Destination) and return (Destination -> Source) paths.\n\n"
        )

        if self.analysis_mode == "STRIDE":
            prompt += (
                "STRIDE Threat Categories (Weaknesses):\n"
                "- Spoofing: Impersonating something or someone else.\n"
                "- Tampering: Modifying data or code.\n"
                "- Repudiation: Claiming to not have performed an action.\n"
                "- Information Disclosure: Exposing information to unauthorized parties.\n"
                "- Denial of Service: Denying or degrading service to users.\n"
                "- Elevation of Privilege: Gaining capabilities without authorization.\n\n"
            )
        else:
            prompt += (
                "LINDDUN Privacy Threat Definitions (Weaknesses):\n"
                "- Linkability: Linking actions/data to a user without identifying them.\n"
                "- Identifiability: Identifying a user from a set.\n"
                "- Non-repudiation: User cannot deny an action.\n"
                "- Detectability: Distinguishing whether an item exists.\n"
                "- Disclosure of Information: Unauthorized access to PII.\n"
                "- Unawareness: User is unaware of data processing.\n"
                "- Non-compliance: Violating privacy laws/regulations.\n\n"
            )

        prompt += (
            f"Industry: {self._sanitize(self.config.industry_context)}\n"
            f"Risk: {self._sanitize(self.config.risk_preference.upper())}\n"
            f"Posture: {self._sanitize(self.config.security_posture)}\n\n"
            "OUTPUT FORMAT: Return a JSON list of threats.\n"
            "Each threat MUST have these fields:\n"
            f"- threat_id: UUID\n"
            f"- category: {methodology} category\n"
            "- title: Short name of the weakness\n"
            "- description: Technical detail of the weakness\n"
            "- vulnerabilities: List of specific exploit paths/flaws. Each description MUST be a concise, complete sentence. Format: [{\"description\": \"...\", \"mitigation\": \"...\"}]\n"
            "- impact: Technical/business impact\n"
            "- likelihood: 1-5\n"
            "- recommended_mitigation: Remediation steps\n"
            "- affected_components: The EXACT name of the component or data flow as provided in the DFD (e.g., 'Payment Gateway')\n"
            "- affected_element_type: (Process, Data Store, Data Flow, or Entity)\n"
            "- affected_asset_type: (Physical or Informational)\n"
            "- cvss_score: 0.0-10.0\n"
            "- cvss_vector: Full CVSS 3.1 vector string (FORMAT: 'CVSS:3.1/AV:[N/A]/AC:[N/A]/PR:[N/A]/UI:[N/A]/S:[N/A]/C:[N/A]/I:[N/A]/A:[N/A]')\n"
            "- mitre_attack_id: MITRE Technique ID\n\n"
            "COMPREHENSIVENESS RULE:\n"
            "Identify as many relevant threats as possible for EACH element. "
            "Do not stop at the first threat. For each component and flow, explore all relevant categories (e.g. for a database, check Tampering, Information Disclosure, and Denial of Service). "
            "Aim for a detailed and exhaustive register. If an element has multiple data flows, analyze each interaction separately.\n\n"
            "CRITICAL: Cross-boundary data flows (crossing from None to a named TB) are extremely high risk."
        )

        return prompt

    def build_user_prompt(self, dfd: DFDModel, system_name: str = "Target System") -> str:
        """Construct the user prompt describing the specific DFD."""
        prompt = f"Analyze the following architectural DFD for {system_name}:\n\n"
        prompt += "<architecture_context>\n"

        prompt += "\n--- ASSETS ---\n"
        if dfd.assets:
            for a in dfd.assets:
                prompt += f"- Name: {a.name} | Type: {a.type} | Criticality: {a.criticality} | Scope: {'Out of Scope' if a.is_out_of_scope else 'In Scope'}\n"
                if a.is_out_of_scope and a.out_of_scope_justification:
                    prompt += f"  Justification: {a.out_of_scope_justification}\n"
        else:
            prompt += "- No standalone assets defined.\n"
        
        prompt += "\n--- DFD NODES (Elements) ---\n"
        for node in dfd.nodes:
            tb_str = node.trust_boundary or "None"
            if node.parent_trust_boundary:
                tb_str = f"{tb_str} (Nested within {node.parent_trust_boundary})"
            
            prompt += f"- Element: {self._sanitize(node.name)}\n"
            prompt += f"  Properties: Type: {self._sanitize(node.type)} | Class: {node.element_type} | Asset: {node.asset_type} | Boundary: {tb_str}\n"
            if node.description:
                prompt += f"  Description: {self._sanitize(node.description)}\n"

        prompt += "\n--- DFD EDGES (Data Flows) ---\n"
        for edge in dfd.edges:
            src_name = next((n.name for n in dfd.nodes if n.id == edge.source_id), "(Unknown/Out-of-Scope)")
            dst_name = next((n.name for n in dfd.nodes if n.id == edge.target_id), "(Unknown/Out-of-Scope)")
            bi_tag = " (Bidirectional)" if edge.is_bidirectional else ""
            prompt += f"- Flow: {self._sanitize(edge.name)}{bi_tag} ({self._sanitize(src_name)} -> {self._sanitize(dst_name)})\n"
            prompt += f"  Protocol: {self._sanitize(edge.protocol)} | Boundary Context: {edge.trust_boundary}\n"

        prompt += "</architecture_context>\n"
        prompt += "\nIdentify threats focusing on the transition between trust boundaries."
        return prompt

    def build_vision_detection_prompt(self, system_name: str) -> str:
        """Construct the user prompt for visual architecture detection."""
        return (
            f"Analyze the attached architecture diagram for the system: '{system_name}'.\n\n"
            "STRICT GROUNDING RULES (Anti-Hallucination Protocol):\n"
            "1. NO LABEL, NO COMPONENT: Only report components that have an explicit text label in the image.\n"
            "2. NO INFERENCE: Do not assume the existence of items (Internet, Firewall, User) unless they are explicitly drawn and labeled.\n"
            "3. NO GENERIC INFRASTRUCTURE: Do not invent infrastructure layers that are not visually present.\n"
            "4. NO GUESSING: If text is blurry, skip it.\n"
            "5. EMPTY STATE: If the image is not a diagram, return an empty JSON object.\n\n"
            "TASK: Extract all architectural components (c), data flows (f), trust boundaries (tb), and assets (a).\n\n"
            "JSON OUTPUT FORMAT (MANDATORY):\n"
            "{\n"
            '  "c": [\n'
            '    {"n": "Component Name", "t": "Service/Database", "et": "Process/Data Store/Entity", "tb": "Trust Boundary Name"}\n'
            '  ],\n'
            '  "f": [\n'
            '    {"n": "Flow Name", "s": "Source Component Name", "d": "Target Component Name", "p": "Protocol (e.g. HTTPS)"}\n'
            '  ],\n'
            '  "tb": [\n'
            '    {"n": "Trust Boundary Name"}\n'
            '  ],\n'
            '  "a": [\n'
            '    {"n": "Asset Name", "t": "Informational/Physical", "d": "Description"}\n'
            '  ]\n'
            "}\n\n"
            "CRITICAL: Return ONLY the raw JSON object. No conversational text."
        )

    def build_reasoning_prompt(self, threat: any) -> str:
        """Construct a prompt to get the technical reasoning behind a single threat."""
        return f"Provide deep technical reasoning for this threat:\nTitle: {threat.title}\nCategory: {threat.category}\nDescription: {threat.description}"

    def build_vulnerability_reasoning_prompt(self, vuln: any) -> str:
        """Construct a prompt to get technical reasoning for a specific vulnerability."""
        prompt = (
            "Explain this specific security vulnerability in detail:\n\n"
            f"Vulnerability: {vuln.description}\n"
            f"Current Status: {vuln.status}\n"
            f"Current Mitigation: {vuln.mitigation}\n\n"
            "Please provide:\n"
            "1. Attack Scenario: How an attacker would exploit this.\n"
            "2. Root Cause: The underlying architectural or configuration flaw.\n"
            "3. Remediation Deep-Dive: Best practices for fixing this at scale."
        )
        return prompt
