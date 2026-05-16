"""Component detection module for ThreatPilot.

Uses OpenCV to identify potential architectural components (primarily boxes)
within a diagram image.
"""

from __future__ import annotations
from pathlib import Path
from pydantic import BaseModel

from threatpilot.detection.models import DetectedComponent

def detect_components(image_path: str | Path) -> list[DetectedComponent]:
    """Traditional Computer Vision (OpenCV) is disabled. 
    
    This function currently serves as a stub for AI-driven detection orchestration.
    """
    return []