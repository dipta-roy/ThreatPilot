"""Flow detection module for ThreatPilot.

Uses OpenCV Hough line transformation to identify data-flow arrows
within arch diagrams and determine their approximate direction.
"""

from __future__ import annotations

# import cv2
# import numpy as np
from pathlib import Path
from pydantic import BaseModel


class DetectedFlow(BaseModel):
    """Represents a data flow detected in a diagram.

    Attributes:
        start_x: X coordinate of the flow start.
        start_y: Y coordinate of the flow start.
        end_x: X coordinate of the flow end.
        end_y: Y coordinate of the flow end.
        label: Extracted or default protocol label (e.g. 'HTTPS').
        confidence: Confidence score (0.0 - 1.0).
    """

    start_x: int
    start_y: int
    end_x: int
    end_y: int
    label: str = "HTTPS"
    confidence: float = 1.0


def detect_flows(image_path: str | Path) -> list[DetectedFlow]:
    """Identify data-flow lines/arrows in an image using OpenCV.

    Processes using Canny edge detection and Probabilistic Hough Line
    Transform (HoughLinesP).

    Args:
        image_path: Path to the diagram image.

    Returns:
        A list of ``DetectedFlow`` objects with pixel coordinates.

    Raises:
        FileNotFoundError: If the image file path is invalid.
        RuntimeError: If OpenCV processing fails.
    """
    raise RuntimeError("Traditional Computer Vision (OpenCV) has been removed to reduce bundle size. Please use AI-driven detection instead.")

    # Pre-processing
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    
    # Canny Edge detection
    edges = cv2.Canny(blurred, 50, 150, apertureSize=3)

    # Probabilistic Hough Line Transform
    # Parameters: (image, rho, theta, threshold, minLineLength, maxLineGap)
    lines = cv2.HoughLinesP(
        edges, 1, np.pi / 180,
        threshold=50,
        minLineLength=60, # Increased from 40 to ignore noise
        maxLineGap=15
    )

    results: list[DetectedFlow] = []
    
    if lines is not None:
        for line in lines:
            x1, y1, x2, y2 = line[0]
            
            # Simple heuristic: ignore extremely short artifacts
            dist = np.sqrt((x2 - x1) ** 2 + (y2 - y1) ** 2)
            if dist < 60: # Increased from 30
                continue

            # Crude deduplication to prevent 50 overlapping lines for a single arrow
            is_dup = False
            for r in results:
                if (abs(r.start_x - x1) < 25 and abs(r.start_y - y1) < 25) or (abs(r.end_x - x2) < 25 and abs(r.end_y - y2) < 25):
                    is_dup = True
                    break
            
            if is_dup:
                continue
            
            results.append(DetectedFlow(
                start_x=int(x1),
                start_y=int(y1),
                end_x=int(x2),
                end_y=int(y2),
                label="HTTPS",  # Default per requirement REQ-010
                confidence=0.8
            ))

    return results
