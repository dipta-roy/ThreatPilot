"""Flow detection module for ThreatPilot.

Uses OpenCV Hough line transformation to identify data-flow arrows
within arch diagrams and determine their approximate direction.
"""

from __future__ import annotations
from pathlib import Path
from pydantic import BaseModel

from threatpilot.detection.models import DetectedFlow

def detect_flows(image_path: str | Path) -> list[DetectedFlow]:
    """Traditional Computer Vision (OpenCV) is disabled. 
    
    This function currently serves as a stub for AI-driven detection orchestration.
    """
    return []
