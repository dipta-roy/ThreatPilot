"""Prompt builder module for ThreatPilot.

Translates the Data Flow Diagram (DFD), system metadata, and user preferences
into structured natural language prompts for consumption by an AI model.
"""

from __future__ import annotations
from typing import Optional
from threatpilot.config.prompt_config import PromptConfig
from threatpilot.core.dfd_converter import DFDModel

class PromptBuilder:
    """Translates project models and user configurations into structured AI prompts."""

    def __init__(self, config: PromptConfig, analysis_mode: str = "STRIDE") -> None:
        self.config = config
        self.analysis_mode = analysis_mode.upper()

    def _sanitize(self, text: str | None) -> str:
        """Escapes XML-sensitive characters and control symbols."""
        if not text: return ""
        s = str(text).replace("<", "[").replace(">", "]")
        return s.replace("\n", " ").replace("\r", " ").replace("\t", " ")

    def _sanitize_multiline(self, text: str | None) -> str:
        """Escapes XML-sensitive characters but preserves newlines."""
        if not text: return ""
        return str(text).replace("<", "[").replace(">", "]")

    def build_system_prompt(self) -> str:
        """Constructs the high-level operational context for the AI security analyst."""
        role = "Cyber Security Architect" if self.analysis_mode == "STRIDE" else "Privacy Architect"
        methodology = "STRIDE" if self.analysis_mode == "STRIDE" else "LINDDUN"
        
        prompt = (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. DO NOT use Chinese or any other language for any field.\n\n"
            f"You are 'ThreatPilot', an expert {role}. "
            f"Perform a detailed {methodology} analysis on the provided Data Flow Diagram (DFD).\n\n"
            "STRICT QUALITY GUIDELINES:\n"
            "1. DESCRIPTIVE TITLES: The 'title' field MUST describe specific ATTACKER BEHAVIOR (e.g., 'Forged JWT Accepted by Backend', 'API Resource Exhaustion'), NOT missing controls (e.g., DO NOT use 'Missing Rate Limiting').\n"
            "2. EVIDENCE vs ASSUMPTION: 'Evidence-based' MUST ONLY be used when the DFD explicitly shows the weakness (e.g., Protocol=HTTP). If you are inferring a missing control (like missing HSTS, WAF, mTLS, or internal validation) that is not explicitly in the DFD, you MUST classify finding_type as 'Assumption'.\n"
            "3. THREAT vs VULNERABILITY: First identify the observed weakness/assumption, then the Threat (attacker behavior), then the vulnerability and mitigation.\n"
            "4. DETERMINISTIC CANDIDATES: You will be provided a list of CANDIDATE THREAT CATEGORIES. You MUST ONLY evaluate and explain these specific candidates for the provided architecture segment. DO NOT invent new threat categories.\n"
            "5. MITRE ATT&CK: Use specific, non-generic MITRE ATT&CK techniques based on the exact attack pattern (avoid generic T1068 where possible).\n"
            "6. ENGLISH ONLY: All descriptions, titles, and mitigations must be in plain English.\n"
            "7. CVSS VERSION: You MUST use CVSS version 3.1 for all vectors. DO NOT use version 2.0 or 4.0.\n"
            "8. ARCHITECTURAL FOCUS: Focus on data flows crossing Trust Boundaries.\n\n"
            "DEFINITIONS:\n"
            f"1. THREAT: A technical weakness in the system architecture (following {methodology} principles).\n"
            "2. VULNERABILITY: A description of HOW an exploit can be used on the identified threat/weakness to perform an attack.\n"
            "3. TRUST BOUNDARY: elements with 'trust_boundary: None (External)' are beyond your control and should be treated as untrusted.\n"
            "4. NESTED BOUNDARY: Cumulative protections and exposures of the entire hierarchy must be considered.\n"
            "5. BIDIRECTIONAL FLOW: If 'is_bidirectional: True', identify threats for both primary and return paths.\n\n"
        )

        if self.analysis_mode == "STRIDE":
            prompt += (
                "STRIDE Threat Categories:\n"
                "- Spoofing: Impersonating something or someone else.\n"
                "- Tampering: Modifying data or code.\n"
                "- Repudiation: Claiming to not have performed an action.\n"
                "- Information Disclosure: Exposing information to unauthorized parties.\n"
                "- Denial of Service: Denying or degrading service to users.\n"
                "- Elevation of Privilege: Gaining capabilities without authorization.\n\n"
            )
        else:
            prompt += (
                "LINDDUN Privacy Threat Categories (Use these exact terms):\n"
                "- Linkability: Linking actions/data to a user.\n"
                "- Identifiability: Identifying a user from a set.\n"
                "- Non-repudiation: User cannot deny an action.\n"
                "- Detectability: Distinguishing whether an item exists.\n"
                "- Disclosure of Information: Unauthorized access to PII.\n"
                "- Unawareness: User is unaware of data processing.\n"
                "- Non-compliance: Violating privacy laws/regulations.\n\n"
            )

        business_context = "BUSINESS CONTEXT:\n"
        if self.config.industry_context.strip():
            business_context += f"- Industry Context: {self._sanitize(self.config.industry_context)}\n"
        if self.config.risk_preference.strip():
            business_context += f"- Risk Preference: {self._sanitize(self.config.risk_preference.upper())}\n"
        if self.config.security_posture.strip():
            business_context += f"- Security Posture: {self._sanitize(self.config.security_posture)}\n"
        if self.config.compliance_priority.strip():
            business_context += f"- Compliance Priority: {self._sanitize(self.config.compliance_priority)}\n"
        if self.config.business_context_policy.strip():
            business_context += f"- Business Context Policy: {self._sanitize_multiline(self.config.business_context_policy)}\n"
        if self.config.custom_prompt.strip():
            business_context += f"- Additional Global Instructions: {self._sanitize_multiline(self.config.custom_prompt)}\n"
        business_context += "\n"

        prompt += business_context

        prompt += (
            "OUTPUT FORMAT: Return a JSON object where the keys are EXACTLY the Threat Categories listed above. "
            "For each category, provide an array of threat objects. If a category is not applicable, provide an empty array [].\n"
            "Each threat object in the array must contain the following fields (ALL STRINGS MUST BE IN ENGLISH):\n"
            f"- threat_id, title (Unique descriptive name of attacker behavior, NOT missing control), description (English),\n"
            "- vulnerabilities (list of objects with 'title', 'description', and 'weakness_type' (e.g., Configuration weakness, Design weakness, Authorization weakness)), impact (English), likelihood (1-5), recommended_mitigation (English),\n"
            "- affected_components (EXACT NAME), affected_element_type, affected_asset_type,\n"
            "- cvss_score (float), cvss_vector (CVSS 3.1), mitre_attack_id,\n"
            "- reasoning (Explain the logic behind the finding, including evidence, attack preconditions, and specific architectural references),\n"
            "- finding_type ('Evidence-based' or 'Assumption'), confidence ('High', 'Medium', 'Low'),\n"
            "- source_dfd_node (string, the name or ID of the origin node or flow),\n"
            "- evidence_traversal_path (list of strings showing the flow of the threat from boundary to target)\n\n"
            "ZERO TRUST & COMPLIANCE MANDATES:\n"
            "1. Evaluate all flows explicitly against Zero Trust principles: identity verification, strict authorization, continuous verification, and least privilege.\n"
            "2. If a flow crosses a Trust Boundary, explicitly state how it verifies identity and authorizes access.\n\n"
            "CVSS GUIDELINE: Always provide a CVSS 3.1 vector string (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) and its corresponding base score.\n"
            f"SYSTEMATIC ENUMERATION: You MUST systematically populate the array for EVERY {methodology} category. Do not skip any category. "
            "If a data flow is bidirectional, analyze the Request path and Response path separately and note the direction in the title.\n"
            "REMEMBER: ENGLISH ONLY."
        )
        return prompt

    def build_user_prompt(self, dfd: DFDModel, system_name: str = "Target System", rag_context: str = "", candidates: Optional[list[str]] = None, narrative: str = "") -> str:
        """Serializes the architectural model into a detailed natural language description."""
        prompt = "LANGUAGE DIRECTIVE: You MUST respond exclusively in English.\n\n"
        
        if candidates:
            prompt += "--- CANDIDATE THREAT CATEGORIES TO EVALUATE ---\n"
            for c in candidates:
                prompt += f"- {c}\n"
            prompt += "\nEvaluate each of the above candidate categories for the given context. If a category does not apply, simply omit it from the JSON response.\n\n"
            
        if rag_context.strip():
            prompt += f"{rag_context}\n\n"
            
        if narrative.strip():
            prompt += f"--- ARCHITECTURE NARRATIVE ---\n{narrative}\n\n"
            
        prompt += f"Analyze the following architectural Tri-Graph for {system_name}:\n\n<architecture_context>\n"
        prompt += "\n--- DIMENSION 1: DATA GRAPH (ASSETS) ---\n"
        if dfd.assets:
            for a in dfd.assets:
                prompt += f"- {a.name} | Type: {a.type} | Criticality: {a.criticality} | Scope: {'Out' if a.is_out_of_scope else 'In'}\n"
                if getattr(a, "description", "").strip():
                    prompt += f"  Description: {self._sanitize(a.description)}\n"
                if a.is_out_of_scope and a.out_of_scope_justification: prompt += f"  Justification: {a.out_of_scope_justification}\n"
        else: prompt += "- No assets defined.\n"
        
        prompt += "\n--- DIMENSION 2: TRUST GRAPH (BOUNDARIES) ---\n"
        if getattr(dfd, "boundaries", []):
            for b in dfd.boundaries:
                parent_info = f" (Nested in {b.parent_boundary})" if b.parent_boundary else ""
                prompt += f"- Boundary: {self._sanitize(b.name)} | Type: {self._sanitize(b.type)}{parent_info}\n"
                if getattr(b, "description", "").strip():
                    prompt += f"  Description: {self._sanitize(b.description)}\n"
        else:
            prompt += "- No trust boundaries defined.\n"

        prompt += "\n--- DIMENSION 3: COMPONENT GRAPH (TOPOLOGY NODES) ---\n"
        for node in dfd.nodes:
            tb = node.trust_boundary or "None"
            if node.parent_trust_boundary: tb = f"{tb} (Nested in {node.parent_trust_boundary})"
            prompt += f"- Element: {self._sanitize(node.name)}\n  Properties: Type: {self._sanitize(node.type)} | Class: {node.element_type} | Asset: {node.asset_type} | Boundary: {tb}\n"
            if node.description: prompt += f"  Description: {self._sanitize(node.description)}\n"

        prompt += "\n--- DIMENSION 3: COMPONENT GRAPH (TOPOLOGY EDGES) ---\n"
        for edge in dfd.edges:
            src = next((n.name for n in dfd.nodes if n.id == edge.source_id), "(Unknown)")
            dst = next((n.name for n in dfd.nodes if n.id == edge.target_id), "(Unknown)")
            prompt += f"- Flow: {self._sanitize(edge.name)}{' (Bi)' if edge.is_bidirectional else ''} ({self._sanitize(src)} -> {self._sanitize(dst)})\n  Protocol: {self._sanitize(edge.protocol)} | Boundary: {edge.trust_boundary}\n"

        prompt += "</architecture_context>\n\n"
        prompt += "LANGUAGE DIRECTIVE: Respond EXCLUSIVELY in English. All field values must be in English. Provide unique, descriptive titles for every threat identified."
        return prompt

    def build_vision_detection_prompt(self, system_name: str) -> str:
        """Constructs the visual detection prompt for image-based architecture extraction."""
        return (
            f"You are an expert Cybersecurity Architect and Threat Modeling Specialist. "
            f"Analyze the attached architecture diagram for: '{system_name}' and extract its architectural elements.\n\n"
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English. All field values and names must be in English.\n"
            "STRICT GROUNDING: Do not assume items not explicitly labeled. Be exhaustive; do not truncate output.\n\n"
            "CLASSIFICATION RULES:\n"
            "1. COMPONENT (c):\n"
            "   - A system element that performs a function, provides a service, processes data, stores/transmits data, or controls access.\n"
            "   - Decision Test: Ask: 'Does this item perform an action, provide functionality, process data, store data, transmit data, or control access?'\n"
            "   - Examples: Web App, Mobile App, API Gateway, Database Server, Load Balancer, Identity Provider, Key Vault.\n"
            "2. ASSET (a):\n"
            "   - Something valuable that requires protection from unauthorized disclosure, modification, destruction, or misuse.\n"
            "   - Decision Test: Ask: 'If an attacker stole, modified, deleted, exposed, or corrupted this item, would it create business, security, privacy, regulatory, operational, or financial impact?'\n"
            "   - Examples: PII, PHI, User Credentials, Encryption Keys, Access/Refresh Tokens, Configuration Secrets, Audit Logs.\n"
            "3. COMMON MISCLASSIFICATIONS:\n"
            "   - Database Server = Component | Data inside Database = Asset\n"
            "   - Key Vault = Component | Encryption Keys/Secrets = Asset\n"
            "   - Identity Provider = Component | User Accounts & Credentials = Asset\n"
            "   - Cloud Storage Service = Component | Files/Data Stored Within = Asset\n\n"
            "COORDINATE FORMATS (0-1000 scale, where 0 is top/left, 1000 is bottom/right):\n"
            "- Components (c) and Boundaries (tb): Use bounding box format [ymin, xmin, ymax, xmax].\n"
            "- Flows (f): Use arrow path format [ys, xs, ye, xe] (Start Y, Start X, End Y, End X).\n\n"
            "JSON FORMAT (MUST BE VALID JSON):\n"
            "{\n"
            '  "c": [{"n": "Component Name", "t": "Subtype", "et": "Process|Data Store|Entity", "tb": "BoundaryName", "b": [ymin, xmin, ymax, xmax]}],\n'
            '  "f": [{"n": "Flow Name", "s": "Source Component Name", "d": "Target Component Name", "p": "Protocol", "b": [ys, xs, ye, xe]}],\n'
            '  "tb": [{"n": "Boundary Name", "b": [ymin, xmin, ymax, xmax]}],\n'
            '  "a": [{"n": "Asset Name", "t": "Physical|Informational", "d": "Description of why it requires protection"}]\n'
            "}"
        )

    def build_reasoning_prompt(self, threat: any) -> str:
        """Constructs a request for technical architectural reasoning for a specific threat."""
        term = "threat" if self.analysis_mode == "STRIDE" else "privacy risk"
        return (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English.\n\n"
            f"Provide deep technical reasoning for this {term}:\n"
            f"Title: {threat.title}\n"
            f"Category: {threat.category}\n"
            f"Description: {threat.description}\n"
            f"Affected Components: {threat.affected_components}\n\n"
            "Include technical justification for the classification and the potential impact on the system architecture."
        )

    def build_vulnerability_reasoning_prompt(self, vuln: any) -> str:
        """Constructs a request for root-cause analysis and remediation strategy for a vulnerability."""
        return (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English.\n\n"
            f"Vulnerability: {vuln.description}\nStatus: {vuln.status}\nMitigation: {vuln.mitigation}\n\n"
            "Provide: 1. Attack Scenario, 2. Root Cause, 3. Remediation Deep-Dive (Markdown)."
        )

    def build_mitigation_reasoning_prompt(self, req: any) -> str:
        """Constructs a request for root-cause analysis and remediation strategy for a mitigation requirement."""
        return (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English.\n\n"
            f"Control ID: {req.req_id}\n"
            f"Control Title: {req.title}\n"
            f"Affected Components: {req.affected_components}\n"
            f"Requirement Description: {req.mitigation}\n"
            f"Test Case: {req.test_case}\n\n"
            "Provide a detailed technical explanation of the security control, why it is necessary, how to implement it securely, "
            "and how to validate it (test strategy). Output the report in markdown format."
        )

    def build_narrative_prompt(self, dfd: DFDModel, system_name: str = "Target System") -> str:
        """Constructs a prompt for generating a plain-text Architecture Narrative story."""
        prompt = (
            "LANGUAGE DIRECTIVE: You MUST respond exclusively in English.\n\n"
            f"You are a Cybersecurity Architect describing the data flows of '{system_name}' in plain text.\n"
            "Based on the following architecture graph, tell a technical story about how data flows through the system, "
            "what trust boundaries are crossed, and what assets traverse the system.\n\n"
            "FORMAT REQUIREMENTS:\n"
            "You MUST format your output exactly with these sections (using Markdown):\n"
            "──────────────────────────────────────────\n"
            " Architecture Narrative\n"
            "──────────────────────────────────────────\n\n"
            "Request Flow\n"
            "1. [Step 1]\n"
            "2. [Step 2]\n\n"
            "Trust Boundary Crossings\n"
            "• [Source] -> [Target]\n\n"
            "Assets Traversing the System\n"
            "• [Asset Name]\n\n"
            "Technical Story: [A cohesive paragraph explaining the flow end-to-end]\n\n"
        )
        
        prompt += "<architecture_context>\n"
        for node in dfd.nodes:
            tb = node.trust_boundary or "None"
            prompt += f"- Component: {self._sanitize(node.name)} | Type: {self._sanitize(node.type)} | Boundary: {tb}\n"

        for edge in dfd.edges:
            src = next((n.name for n in dfd.nodes if n.id == edge.source_id), "(Unknown)")
            dst = next((n.name for n in dfd.nodes if n.id == edge.target_id), "(Unknown)")
            prompt += f"- Flow: {self._sanitize(edge.name)} ({self._sanitize(src)} -> {self._sanitize(dst)}) | Protocol: {self._sanitize(edge.protocol)}\n"

        for a in dfd.assets:
            prompt += f"- Asset: {a.name} | Type: {a.type}\n"
        prompt += "</architecture_context>\n"
        return prompt
