"""Trust boundary detection module for ThreatPilot.

Identifies potential trust boundaries (typically larger containers or 
dashed/dotted rectangles) in diagram images.
"""

from __future__ import annotations
from pathlib import Path
from pydantic import BaseModel

from threatpilot.detection.models import DetectedBoundary

def detect_boundaries(image_path: str | Path) -> list[DetectedBoundary]:
    """Traditional Computer Vision (OpenCV) is disabled. 
    
    This function currently serves as a stub for AI-driven detection orchestration.
    """
    return []
