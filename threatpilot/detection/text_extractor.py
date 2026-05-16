import logging
from PIL import Image
from pathlib import Path
from pydantic import BaseModel

logger = logging.getLogger(__name__)

from threatpilot.detection.models import TextLabel

logger = logging.getLogger(__name__)

def extract_text_labels(image_path: str | Path) -> list[TextLabel]:
    """OCR Text Extraction is disabled. 
    
    This function currently serves as a stub for potential AI-driven OCR.
    """
    logger.warning("OCR Text Extraction requested but Tesseract-OCR is disabled or removed.")
    return []
