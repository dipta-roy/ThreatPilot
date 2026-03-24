"""OCR text extraction module for ThreatPilot.

Uses ``pytesseract`` to extract text labels and their positions from diagram
images. This is used for component naming and flow labels.
"""

from __future__ import annotations

import pytesseract
from PIL import Image
from pathlib import Path
from pydantic import BaseModel


class TextLabel(BaseModel):
    """Represents a text snippet found in a diagram.

    Attributes:
        text: The extracted text string.
        x: Top-left X coordinate in the image.
        y: Top-left Y coordinate in the image.
        width: Width of the bounding box.
        height: Height of the bounding box.
        confidence: Confidence score (0-100) from the OCR engine.
    """

    text: str
    x: int
    y: int
    width: int
    height: int
    confidence: float


def extract_text_labels(image_path: str | Path) -> list[TextLabel]:
    """Perform OCR on an image to extract text labels and bounding boxes.

    Args:
        image_path: Path to the source image file.

    Returns:
        A list of ``TextLabel`` objects found in the image.

    Raises:
        FileNotFoundError: If the image file does not exist.
        ImportError: If pytesseract or Tesseract-OCR is not correctly configured.
    """
    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(f"Image for OCR not found: {path}")

    try:
        # Load image via PIL
        img = Image.open(path)
        
        # Perform OCR with data (bounding boxes + confidence)
        # Output format is a dictionary with keys: 'level', 'page_num', 'block_num',
        # 'par_num', 'line_num', 'word_num', 'left', 'top', 'width', 'height',
        # 'conf', 'text'
        data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        
        labels: list[TextLabel] = []
        n_boxes = len(data['text'])
        
        for i in range(n_boxes):
            text = data['text'][i].strip()
            conf = float(data['conf'][i])
            
            # Filter out empty strings and low confidence trash
            if text and conf > 30:
                labels.append(TextLabel(
                    text=text,
                    x=data['left'][i],
                    y=data['top'][i],
                    width=data['width'][i],
                    height=data['height'][i],
                    confidence=conf,
                ))
                
        return labels

    except pytesseract.TesseractNotFoundError:
        # Re-raise with a more helpful message
        raise ImportError(
            "Tesseract-OCR binary not found. Please install Tesseract-OCR "
            "on your system and ensure it is in your PATH."
        )
    except Exception as exc:
        raise RuntimeError(f"OCR extraction failed: {exc}")
