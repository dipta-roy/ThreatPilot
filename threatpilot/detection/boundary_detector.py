"""Trust boundary detection module for ThreatPilot.

Identifies potential trust boundaries (typically larger containers or 
dashed/dotted rectangles) in diagram images.
"""

from __future__ import annotations
from pathlib import Path
from pydantic import BaseModel

class DetectedBoundary(BaseModel):
    """Represents a trust boundary detected in a diagram.

    Attributes:
        x: Top-left X coordinate.
        y: Top-left Y coordinate.
        width: Width of the boundary box.
        height: Height of the boundary box.
        label: Default label for the boundary.
        confidence: Confidence score (0.0 - 1.0).
    """

    x: int
    y: int
    width: int
    height: int
    label: str = "Trust Boundary"
    confidence: float = 1.0

def detect_boundaries(image_path: str | Path) -> list[DetectedBoundary]:
    """Identify trust boundary boxes in a diagram using OpenCV.

    Focuses on identifying larger-scale rectangular containers that
    contain other components.

    Args:
        image_path: Path to the diagram image.

    Returns:
        A list of ``DetectedBoundary`` objects with pixel coordinates.

    Raises:
        FileNotFoundError: If the image path is invalid.
        RuntimeError: If OpenCV processing fails.
    """
    raise RuntimeError("Traditional Computer Vision (OpenCV) has been removed to reduce bundle size. Please use AI-driven detection instead.")

    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    blurred = cv2.bilateralFilter(gray, 9, 75, 75)

    thresh = cv2.adaptiveThreshold(
        blurred, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY_INV, 15, 3
    )

    contours, _ = cv2.findContours(
        thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE
    )

    results: list[DetectedBoundary] = []
    img_h, img_w = gray.shape
    
    min_area = (img_w * img_h) * 0.10
    max_area = (img_w * img_h) * 0.9

    for cnt in contours:
        area = cv2.contourArea(cnt)
        if area < min_area or area > max_area:
            continue

        peri = cv2.arcLength(cnt, True)
        approx = cv2.approxPolyDP(cnt, 0.02 * peri, True)
        if 4 <= len(approx) <= 8:
            x, y, w, h = cv2.boundingRect(approx)
            aspect_ratio = float(w) / h
            if 0.1 < aspect_ratio < 10.0:
                results.append(DetectedBoundary(
                    x=int(x),
                    y=int(y),
                    width=int(w),
                    height=int(h),
                    confidence=0.75
                ))

    return results
