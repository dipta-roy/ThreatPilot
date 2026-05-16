"""Data models for architectural elements detected via computer vision or AI."""

from __future__ import annotations
from pydantic import BaseModel, Field

class DetectedBox(BaseModel):
    """Base class for rectangular architectural elements."""
    x: int
    y: int
    width: int
    height: int
    confidence: float = 1.0

class DetectedComponent(DetectedBox):
    """Represents a logical component (Process, Data Store, etc.)."""
    label: str = "New Component"
    element_type: str = "Process"

class DetectedFlow(BaseModel):
    """Represents a data flow between two points."""
    name: str = "Data Flow"
    source_id: str = ""
    target_id: str = ""
    points: list[tuple[int, int]] = Field(default_factory=list)
    confidence: float = 1.0

class DetectedBoundary(DetectedBox):
    """Represents a trust boundary container."""
    label: str = "Trust Boundary"

class TextLabel(BaseModel):
    """Represents a text snippet extracted from a diagram."""
    text: str
    x: int
    y: int
    width: int
    height: int
    confidence: float = 1.0
