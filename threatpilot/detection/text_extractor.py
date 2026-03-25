import logging
# import pytesseract (Removed as Tesseract is no longer on device)
from PIL import Image
from pathlib import Path
from pydantic import BaseModel

logger = logging.getLogger(__name__)

class TextLabel(BaseModel):
    """Represents a text snippet found in a diagram."""

    text: str
    x: int
    y: int
    width: int
    height: int
    confidence: float


def extract_text_labels(image_path: str | Path) -> list[TextLabel]:
    """OCR is disabled on this system because Tesseract-OCR is missing.
    
    Returns an empty list by default.
    """
    logger.warning("OCR Text Extraction requested but Tesseract-OCR is disabled or removed.")
    return []
