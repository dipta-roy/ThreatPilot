"""Project versioning module for ThreatPilot.

Provides logic to create snapshots and track historical versions of a
threat modeling project.
"""

from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import List, Optional
from pydantic import BaseModel


class ProjectVersion(BaseModel):
    """Metadata for a project version snapshot.

    Attributes:
        version_id: Unique string for the version (e.g. 'v1.0').
        timestamp: ISO-8601 creation time.
        description: Brief user-supplied reason for the version.
        file_path: Relative path to the snapshot file within the project.
    """

    version_id: str
    timestamp: str
    description: str = ""
    file_path: str


def create_version_snapshot(
    project_path: str,
    version_id: str,
    description: str = ""
) -> ProjectVersion:
    """Create a point-in-time snapshot of the current project state.

    Copies the ``project.json`` to a ``versions/`` subdirectory with a
    timestamped filename.

    Args:
        project_path: Absolute path to the project root directory.
        version_id: User-supplied version identifier.
        description: Optional notes about this version.

    Returns:
        A ``ProjectVersion`` metadata object.

    Raises:
        FileNotFoundError: If the main project.json is missing.
        OSError: If snapshot folder creation or file copying fails.
    """
    root = Path(project_path)
    source_file = root / "project.json"
    if not source_file.exists():
        raise FileNotFoundError(f"Project metadata not found at {source_file}")

    # Create versions directory
    versions_dir = root / "versions"
    versions_dir.mkdir(exist_ok=True)

    # Generate unique timestamped filename
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    sanitized_id = "".join(c for c in version_id if c.isalnum() or c in "-._")
    dest_filename = f"project_{sanitized_id}_{timestamp}.json"
    dest_path = versions_dir / dest_filename

    # Perform snapshot
    shutil.copy2(source_file, dest_path)

    return ProjectVersion(
        version_id=version_id,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        description=description,
        file_path=str(Path("versions") / dest_filename)
    )
