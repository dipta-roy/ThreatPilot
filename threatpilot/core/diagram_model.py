"""Diagram data model for ThreatPilot.

Defines the ``Diagram`` pydantic model that holds metadata for an imported
architecture diagram image.
"""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any
from pydantic import BaseModel

class Diagram(BaseModel):
    """Metadata for a single imported architecture diagram.

    Attributes:
        diagram_id: Unique identifier for the diagram.
        file_path: Path to the image file relative to the project
            ``diagrams/`` directory.
        original_name: Original filename as imported by the user.
        created_at: ISO-8601 creation timestamp.
        width: Image width in pixels (populated after loading).
        height: Image height in pixels (populated after loading).
    """

    diagram_id: str = ""
    file_path: str = ""
    original_name: str = ""
    created_at: str = ""
    width: int = 0
    height: int = 0

    @classmethod
    def create(cls, original_name: str, file_path: str) -> Diagram:
        """Create a new ``Diagram`` instance with a generated ID and timestamp.

        Args:
            original_name: The original filename supplied by the user.
            file_path: Relative path inside the project ``diagrams/`` folder.

        Returns:
            A new ``Diagram`` with a unique ID and current UTC timestamp.
        """
        return cls(
            diagram_id=uuid.uuid4().hex,
            file_path=file_path,
            original_name=original_name,
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert the diagram to a JSON-serialisable dictionary.

        Returns:
            Dictionary of all diagram metadata fields.
        """
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Diagram:
        """Construct a ``Diagram`` from a dictionary.

        Args:
            data: Dictionary previously produced by ``to_dict``.

        Returns:
            A fully populated ``Diagram`` instance.
        """
        return cls.model_validate(data)
