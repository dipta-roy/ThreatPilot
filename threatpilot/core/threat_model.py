"""Threat model data structure for ThreatPilot.

Defines the core ``Threat`` model representing a single security risk found
during analysis and the ``ThreatRegister`` containing the full set.
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class STRIDECategory(str, Enum):
    """Broad classification for both Security (STRIDE) and Privacy (LINDDUN) threats."""

    # STRIDE Security
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"
    
    # LINDDUN Privacy
    LINKABILITY = "Linkability"
    IDENTIFIABILITY = "Identifiability"
    NON_REPUDIATION_PRIVACY = "Non-repudiation"
    DETECTABILITY = "Detectability"
    DISCLOSURE_OF_INFORMATION = "Disclosure of Information"
    UNAWARENESS = "Unawareness"
    NON_COMPLIANCE = "Non-compliance"


class Threat(BaseModel):
    """A single identified security threat.

    Attributes:
        threat_id: Unique identifier for this instance.
        category: Standard STRIDE classification.
        title: Short descriptive name.
        description: Deep technical detail of the threat.
        impact: Analysis of the potential business/system damage.
        likelihood: Numeric probability score (1-5).
        mitigation: Proposed remediation steps.
        source_dfd_node: Optional ID of the node this threat applies to.
    """

    threat_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    category: STRIDECategory
    title: str = "New Threat"
    description: str = ""
    impact: str = ""
    likelihood: int = Field(default=3, ge=1, le=5)
    mitigation: str = ""
    is_accepted_risk: bool = False
    acceptance_justification: str = ""
    vulnerabilities: str = ""
    affected_components: str = ""
    affected_element: str = ""
    affected_asset: str = ""
    cvss_score: float = 0.0
    cvss_vector: str = ""
    mitre_attack_id: str = ""
    mitre_attack_technique: str = ""
    reasoning: str = ""
    source_dfd_node: Optional[str] = None


class ThreatRegister(BaseModel):
    """A collection of all threats for a project."""

    threats: List[Threat] = Field(default_factory=list)

    def add_threat(self, threat: Threat, skip_duplicates: bool = True) -> bool:
        """Add a threat to the register.
        
        If skip_duplicates is True, the threat is only added if no identical 
        threat (same title, description, and affected_components) exists.
        
        Returns:
            True if the threat was added, False if it was skipped as a duplicate.
        """
        if skip_duplicates:
            for existing in self.threats:
                if (existing.title == threat.title and 
                    existing.description == threat.description and 
                    existing.affected_components == threat.affected_components):
                    return False
        
        self.threats.append(threat)
        return True

    def remove_threat(self, threat_id: str) -> bool:
        """Remove a threat by its ID.

        Returns:
            True if removed, False if not found.
        """
        for i, t in enumerate(self.threats):
            if t.threat_id == threat_id:
                self.threats.pop(i)
                return True
        return False
