"""Risk engine and threat templating module for ThreatPilot.

Contains the definitions for reusable threat templates, allowing users to
quickly apply standard security findings across different components or
projects.
"""

from __future__ import annotations

import uuid
from typing import List, Optional
from pydantic import BaseModel, Field

from threatpilot.core.threat_model import STRIDECategory, Threat


class ThreatTemplate(BaseModel):
    """A reusable pattern for a security threat.

    Attributes:
        template_id: Unique identifier for the template.
        category: Standard STRIDE classification.
        title: Short name (e.g. 'Insecure API Authentication').
        description: Generic description of the vulnerability.
        impact: Default impact description.
        mitigation: Standard recommended mitigation.
    """

    template_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    category: STRIDECategory
    title: str
    description: str = ""
    impact: str = ""
    mitigation: str = ""

    def instantiate(self) -> Threat:
        """Construct a concrete ``Threat`` instance based on this template."""
        return Threat(
            category=self.category,
            title=self.title,
            description=self.description,
            impact=self.impact,
            mitigation=self.mitigation
        )


class RiskEngine:
    """Manages threat templates and risk-related logic for the application."""

    def __init__(self) -> None:
        # Default global templates maybe?
        self._templates: List[ThreatTemplate] = []

    def add_template(self, template: ThreatTemplate, skip_duplicates: bool = True) -> bool:
        """Register a new reusable template, skipping duplicates if requested."""
        if skip_duplicates:
            for existing in self._templates:
                if (existing.category == template.category and 
                    existing.title == template.title and 
                    existing.description == template.description):
                    return False
        
        self._templates.append(template)
        return True

    def get_templates(self) -> List[ThreatTemplate]:
        """Retrieve all currently defined templates."""
        return self._templates
