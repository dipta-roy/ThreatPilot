"""Component detection module for ThreatPilot.

Uses OpenCV to identify potential architectural components (primarily boxes)
within a diagram image.
"""

from __future__ import annotations

import cv2
import numpy as np
from pathlib import Path
from pydantic import BaseModel


class DetectedComponent(BaseModel):
    """Represents a component detected in a diagram.

    Attributes:
        x: Top-left X coordinate in the image.
        y: Top-left Y coordinate in the image.
        width: Width of the detected box.
        height: Height of the detected box.
        confidence: A heuristic confidence score (e.g. 0.0-1.0).
    """

    x: int
    y: int
    width: int
    height: int
    confidence: float = 1.0


def detect_components(image_path: str | Path) -> list[DetectedComponent]:
    """Identify architectural boxes/components in an image using OpenCV.

    Processes the image using grayscale conversion, thresholding, and
    contour detection to find rectangular shapes.

    Args:
        image_path: Path to the source diagram image.

    Returns:
        A list of ``DetectedComponent`` objects with their pixel coordinates.

    Raises:
        FileNotFoundError: If the image path is invalid.
        RuntimeError: If OpenCV processing fails.
    """
    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(f"Diagram image for detection not found: {path}")

    # Load image via OpenCV
    # Note: image_path is converted to string for OpenCV compatibility
    img = cv2.imread(str(path))
    if img is None:
        raise RuntimeError(f"OpenCV could not load image: {path}")

    # --- Pre-processing ---
    # 1. Grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    
    # 2. Gaussian blur to remove noise
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    
    # 3. Canny Edge Detection (much better for line-drawn diagrams than simple thresholding)
    edges = cv2.Canny(blurred, 50, 150)
    
    # 4. Dilate the edges to connect any broken lines in the drawing
    kernel = np.ones((3, 3), np.uint8)
    dilated = cv2.dilate(edges, kernel, iterations=1)

    # --- Shape Detection ---
    # 5. Find contours (use RETR_LIST to catch nested boxes, not just the outermost ones)
    contours, _ = cv2.findContours(
        dilated, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE
    )

    results: list[DetectedComponent] = []
    
    # Filter constraints based on typical architectural diagrams
    img_h, img_w = gray.shape
    min_area = (img_w * img_h) * 0.0005  # Lowered to 0.05% - extremely sensitive
    max_area = (img_w * img_h) * 0.5     # Ignore entire image frames or massive backgrounds

    for cnt in contours:
        area = cv2.contourArea(cnt)
        if area < min_area or area > max_area:
            continue

        # Approximate to polygon
        peri = cv2.arcLength(cnt, True)
        approx = cv2.approxPolyDP(cnt, 0.02 * peri, True)

        # 5. Check if it's rectangular (4 vertices)
        if len(approx) == 4:
            x, y, w, h = cv2.boundingRect(approx)
            
            # Additional heuristic: aspect ratio should be reasonable for a box
            aspect_ratio = float(w) / h
            if 0.2 < aspect_ratio < 5.0:
                
                # De-duplicate nested/overlapping contour artefacts
                is_dup = False
                for r in results:
                    # If centers are tight and dimensions are similar, it's examining the inner/outer stroke of the same shape
                    cx1, cy1 = x + w/2, y + h/2
                    cx2, cy2 = r.x + r.width/2, r.y + r.height/2
                    if abs(cx1 - cx2) < 25 and abs(w - r.width) < 25 and abs(h - r.height) < 25:
                        is_dup = True
                        break
                        
                if not is_dup:
                    results.append(DetectedComponent(
                        x=int(x),
                        y=int(y),
                        width=int(w),
                        height=int(h),
                        confidence=0.9  # Placeholder for more complex ML confidence
                    ))

    return results
