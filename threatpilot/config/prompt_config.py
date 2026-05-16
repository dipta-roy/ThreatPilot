"""Prompt configuration module for ThreatPilot.

Contains the ``PromptConfig`` model for structured and free-text prompt customisation.
"""

from __future__ import annotations
from pydantic import BaseModel

class PromptConfig(BaseModel):
    """Encapsulates user preferences and contextual parameters for AI prompt generation."""
    risk_preference: str = "medium"
    security_posture: str = "standard"
    compliance_priority: str = ""
    industry_context: str = ""
    business_context_policy: str = ""
    custom_prompt: str = ""
