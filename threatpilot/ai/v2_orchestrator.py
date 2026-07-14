import json
import logging
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from pydantic import ValidationError

from threatpilot.core.v2_models import Threat, ThreatContext, AttackMemory

logger = logging.getLogger(__name__)

class LLMClient:
    """
    Lightweight, custom orchestrator for LLMs. 
    Explicitly avoiding LangChain to reduce bloat, improve debuggability, and maintain speed.
    Supports local Ollama and cloud Gemini.
    """
    def __init__(self, provider: str = "ollama", model: str = "llama3", api_key: str = None):
        self.provider = provider
        self.model = model
        self.api_key = api_key

    def generate(self, prompt: str) -> str:
        if self.provider == "ollama":
            return self._call_ollama(prompt)
        elif self.provider == "gemini":
            return self._call_gemini(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")

    def _call_ollama(self, prompt: str) -> str:
        # Simplistic HTTP POST to local Ollama instance
        url = "http://localhost:11434/api/generate"
        data = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode('utf-8'))
                return result.get("response", "")
        except urllib.error.URLError as e:
            logger.error(f"Failed to connect to Ollama: {e}")
            raise RuntimeError(f"Ollama connection failed: {e}") from e

    def _call_gemini(self, prompt: str) -> str:
        # Simplistic HTTP POST for Gemini API
        if not self.api_key:
            raise RuntimeError("Gemini API key is not configured.")
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        data = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"responseMimeType": "application/json"}
        }
        headers = {
            'Content-Type': 'application/json',
            'x-goog-api-key': self.api_key
        }
        req = urllib.request.Request(url, data=json.dumps(data).encode('utf-8'), headers=headers)
        try:
            with urllib.request.urlopen(req) as response:
                result = json.loads(response.read().decode('utf-8'))
                text = result.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])[0].get("text", "{}")
                return text
        except urllib.error.URLError as e:
            logger.error(f"Failed to connect to Gemini: {e}")
            raise RuntimeError(f"Gemini API connection failed: {e}") from e

class PromptBuilder:
    @staticmethod
    def build_threat_prompt(neighborhood: Dict[str, Any], context: ThreatContext, memory: AttackMemory, rag_context: str = "") -> str:
        """
        Constructs the highly scoped prompt for the Threat Agent.
        Passes the exact Neighborhood, Context, and Event Log to prevent LLM hallucination.
        """
        prompt = f"""
You are an expert security architect. Analyze the following localized component interactions and identify ONE critical threat.
Respond ONLY with valid JSON matching this schema:
{{
  "id": "TP-XXXXXX",
  "category": "Component Threat" | "Data Flow Threat" | "Attack Path Threat",
  "state": "New",
  "title": "Threat Title",
  "reason": "Detailed reasoning based on the context",
  "evidence": {{"traversal_path": ["id1", "id2"], "description": "How the attacker reached this point"}},
  "missing_controls": ["Control 1"],
  "recommended_mitigation": "Mitigation Strategy",
  "verification_method": "How to verify",
  "references": ["CWE-XYZ"]
}}

--- ARCHITECTURE NEIGHBORHOOD ---
{json.dumps(neighborhood, indent=2)}

--- THREAT CONTEXT ---
{context.model_dump_json(indent=2)}

--- ATTACK MEMORY (EVENT LOG) ---
{memory.model_dump_json(indent=2)}

{rag_context}
"""
        return prompt

    @staticmethod
    def build_mitigation_prompt(threat: Threat) -> str:
        return f"""
You are an expert security architect. Given the following threat, recommend a specific, actionable mitigation control.
Respond ONLY with a JSON array of strings containing the mitigations.

--- THREAT ---
{threat.model_dump_json(indent=2)}
"""

    @staticmethod
    def build_evidence_prompt(threat: Threat, memory: AttackMemory) -> str:
        return f"""
Analyze the Threat and the Attack Memory. Extract the exact traversal path nodes/edges that prove this threat.
Respond ONLY with a JSON array of strings representing the IDs in the traversal path.

--- THREAT ---
{threat.model_dump_json(indent=2)}

--- ATTACK MEMORY ---
{memory.model_dump_json(indent=2)}
"""

    @staticmethod
    def build_compliance_prompt(threat: Threat) -> str:
        return f"""
Map this threat to relevant compliance frameworks (e.g., OWASP ASVS, CWE, NIST).
Respond ONLY with a JSON array of strings.

--- THREAT ---
{threat.model_dump_json(indent=2)}
"""

class JSONValidator:
    @staticmethod
    def parse_and_validate(json_str: str) -> Optional[Threat]:
        """Parses the raw LLM output, cleans Markdown wrappers, and enforces Pydantic schemas."""
        try:
            json_str = json_str.strip()
            if json_str.startswith("```json"):
                json_str = json_str[7:]
            if json_str.startswith("```"):
                json_str = json_str[3:]
            if json_str.endswith("```"):
                json_str = json_str[:-3]
                
            data = json.loads(json_str.strip())
            return Threat(**data)
        except (json.JSONDecodeError, ValidationError) as e:
            logger.error(f"JSON Validation failed: {e}")
            return None

class ThreatAgent:
    """
    The first step of the Phased Agent Rollout.
    This agent solely identifies threats without trying to do compliance mapping simultaneously.
    """
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self.version = "1.0"  # This is the prompt version we will save to ThreatSession

    def analyze(self, neighborhood: Dict[str, Any], context: ThreatContext, memory: AttackMemory, retries: int = 2) -> Optional[Threat]:
        """Orchestrates the prompt building, LLM call, and JSON validation with auto-retry."""
        prompt = PromptBuilder.build_threat_prompt(neighborhood, context, memory)
        
        for attempt in range(retries):
            raw_response = self.llm.generate(prompt)
            threat = JSONValidator.parse_and_validate(raw_response)
            if threat:
                return threat
            
            logger.warning(f"Retry {attempt + 1}/{retries} due to invalid JSON.")
            prompt += "\n\nERROR: Your previous response was invalid JSON or did not match the schema. Please output ONLY valid JSON."
            
        return None

class MitigationAgent:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self.version = "1.0"

    def analyze(self, threat: Threat) -> Threat:
        prompt = PromptBuilder.build_mitigation_prompt(threat)
        raw_response = self.llm.generate(prompt)
        try:
            # Strip markdown if present
            raw_response = raw_response.strip()
            if raw_response.startswith("```json"): raw_response = raw_response[7:]
            if raw_response.startswith("```"): raw_response = raw_response[3:]
            if raw_response.endswith("```"): raw_response = raw_response[:-3]
            
            mitigations = json.loads(raw_response.strip())
            if isinstance(mitigations, list):
                threat.recommended_mitigation = ", ".join(mitigations)
        except json.JSONDecodeError:
            logger.error("MitigationAgent JSON parse failed")
        return threat

class EvidenceAgent:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self.version = "1.0"

    def analyze(self, threat: Threat, memory: AttackMemory) -> Threat:
        prompt = PromptBuilder.build_evidence_prompt(threat, memory)
        raw_response = self.llm.generate(prompt)
        try:
            raw_response = raw_response.strip()
            if raw_response.startswith("```json"): raw_response = raw_response[7:]
            if raw_response.startswith("```"): raw_response = raw_response[3:]
            if raw_response.endswith("```"): raw_response = raw_response[:-3]
            
            path = json.loads(raw_response.strip())
            if isinstance(path, list):
                threat.evidence.traversal_path = path
        except json.JSONDecodeError:
            logger.error("EvidenceAgent JSON parse failed")
        return threat

class ComplianceAgent:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self.version = "1.0"

    def analyze(self, threat: Threat) -> Threat:
        prompt = PromptBuilder.build_compliance_prompt(threat)
        raw_response = self.llm.generate(prompt)
        try:
            raw_response = raw_response.strip()
            if raw_response.startswith("```json"): raw_response = raw_response[7:]
            if raw_response.startswith("```"): raw_response = raw_response[3:]
            if raw_response.endswith("```"): raw_response = raw_response[:-3]
            
            refs = json.loads(raw_response.strip())
            if isinstance(refs, list):
                threat.references.extend(refs)
        except json.JSONDecodeError:
            logger.error("ComplianceAgent JSON parse failed")
        return threat

class ReportingAgent:
    def __init__(self, llm_client: LLMClient):
        self.llm = llm_client
        self.version = "1.0"

    def generate_report(self, threats: List[Threat]) -> str:
        """A simple non-LLM markdown generator, as reporting is often deterministic formatting."""
        report = "# ThreatPilot Analysis Report\n\n"
        for t in threats:
            report += f"## {t.id}: {t.title}\n"
            report += f"**Category:** {t.category.value}\n"
            report += f"**Reason:** {t.reason}\n"
            report += f"**Mitigation:** {t.recommended_mitigation}\n"
            report += f"**References:** {', '.join(t.references)}\n\n"
        return report
