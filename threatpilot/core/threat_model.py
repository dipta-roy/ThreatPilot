"""Core data models for security threats and vulnerability management."""

from __future__ import annotations
import uuid
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field

class STRIDECategory(str, Enum):
    """Classification for Security (STRIDE) and Privacy (LINDDUN) threat categories."""
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"
    LINKABILITY = "Linkability"
    IDENTIFIABILITY = "Identifiability"
    NON_REPUDIATION_PRIVACY = "Non-repudiation"
    DETECTABILITY = "Detectability"
    DISCLOSURE_OF_INFORMATION = "Disclosure of Information"
    UNAWARENESS = "Unawareness"
    NON_COMPLIANCE = "Non-compliance"

    @classmethod
    def get_stride_values(cls) -> list[str]:
        return [cls.SPOOFING.value, cls.TAMPERING.value, cls.REPUDIATION.value, 
                cls.INFORMATION_DISCLOSURE.value, cls.DENIAL_OF_SERVICE.value, cls.ELEVATION_OF_PRIVILEGE.value]

    @classmethod
    def get_linddun_values(cls) -> list[str]:
        return [cls.LINKABILITY.value, cls.IDENTIFIABILITY.value, cls.NON_REPUDIATION_PRIVACY.value, 
                cls.DETECTABILITY.value, cls.DISCLOSURE_OF_INFORMATION.value, cls.UNAWARENESS.value, cls.NON_COMPLIANCE.value]

class Vulnerability(BaseModel):
    """A specific flaw or exploit path associated with a threat."""
    vulnerability_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    title: str = "New Vulnerability"
    description: str = ""
    mitigation: str = ""
    status: str = "Open"
    reasoning: str = ""

class Threat(BaseModel):
    """A single identified security threat or privacy risk."""
    threat_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    category: STRIDECategory
    title: str = "New Threat"
    description: str = ""
    impact: str = ""
    likelihood: int = Field(default=3, ge=1, le=5)
    mitigation: str = ""
    is_accepted_risk: bool = False
    acceptance_justification: str = ""
    vulnerability_ids: List[str] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list, exclude=True)
    affected_components: str = ""
    affected_element_type: str = ""
    affected_asset_type: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    cvss_rationale: str = ""
    mitre_attack_id: str = ""
    mitre_attack_technique: str = ""
    reasoning: str = ""
    source_dfd_node: Optional[str] = None

    def resolve_affected_elements(self, project: Any) -> tuple[str, str]:
        """Resolves element and asset names from the project context."""
        from threatpilot.core.utils import resolve_architecture_elements
        
        display_elem = self.affected_element_type or ""
        display_asset = self.affected_asset_type or ""
        
        generic_types = ["data flow", "informational", "physical", "process", "data store", "external entity", "n/a", ""]
        if (not display_elem or not display_asset or display_elem.lower() in generic_types or display_asset.lower() in generic_types) and project:
            res_elem, res_asset = resolve_architecture_elements(
                description_haystack=f"{self.title} {self.description}",
                component_hint=self.affected_components,
                components=project.components,
                flows=project.flows
            )
            display_elem = display_elem if (display_elem and display_elem.lower() not in generic_types) else (res_elem or display_elem)
            display_asset = display_asset if (display_asset and display_asset.lower() not in generic_types) else (res_asset or display_asset)
            
        return display_elem, display_asset

class ThreatRegister(BaseModel):
    """Container for the project's threat inventory."""
    threats: List[Threat] = Field(default_factory=list)
    new_vulnerabilities: List[Vulnerability] = Field(default_factory=list, exclude=True)

    def add_threat(self, threat: Threat, skip_duplicates: bool = True) -> bool:
        """Adds a threat to the register, optionally skipping duplicates."""
        if skip_duplicates:
            for existing in self.threats:
                if (existing.title == threat.title and 
                    existing.description == threat.description and 
                    existing.affected_components == threat.affected_components):
                    return False
        
        self.threats.append(threat)
        return True

    def remove_threat(self, threat_id: str) -> bool:
        """Removes a threat from the register by its unique ID."""
        for i, t in enumerate(self.threats):
            if t.threat_id == threat_id:
                self.threats.pop(i)
                return True
        return False

class VulnerabilityRegister(BaseModel):
    """Global registry for all identified vulnerabilities in the project."""
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """Adds a vulnerability if it doesn't already exist in the registry."""
        if not any(v.vulnerability_id == vuln.vulnerability_id for v in self.vulnerabilities):
            self.vulnerabilities.append(vuln)

    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """Retrieves a vulnerability by its ID."""
        for v in self.vulnerabilities:
            if v.vulnerability_id == vuln_id:
                return v
        return None
