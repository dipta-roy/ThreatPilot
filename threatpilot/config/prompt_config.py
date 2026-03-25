"""Prompt configuration module for ThreatPilot.

Contains the ``PromptConfig`` model for structured and free-text prompt customisation.
"""

from __future__ import annotations

from pydantic import BaseModel


class PromptConfig(BaseModel):
    """Configuration for prompt generation.

    Attributes:
        risk_preference: Risk preference level ('low', 'medium', 'high').
        security_posture: Security posture description.
        compliance_priority: Compliance frameworks to prioritise.
        industry_context: Industry context for threat analysis
            (e.g. 'healthcare', 'finance', 'government').
        custom_prompt: Free-text prompt additions supplied by the user.
    """

    risk_preference: str = "medium"
    security_posture: str = "standard"
    compliance_priority: str = ""
    industry_context: str = ""
    business_context_policy: str = ""
    custom_prompt: str = ""
