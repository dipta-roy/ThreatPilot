"""Project manager module for ThreatPilot.

Handles creation, loading, and saving of threat modeling projects.
Each project is stored as a directory containing a project.json metadata file.

All data models use pydantic ``BaseModel`` for validation and serialisation.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field
from threatpilot.config.prompt_config import PromptConfig
from threatpilot.core.diagram_model import Diagram
from threatpilot.core.threat_model import ThreatRegister
from threatpilot.core.domain_models import Component, Flow, TrustBoundary








class Project(BaseModel):
    """Represents a ThreatPilot project.

    Attributes:
        project_id: Unique identifier for the project.
        project_name: Human-readable project name.
        created_at: ISO-8601 creation timestamp.
        updated_at: ISO-8601 last-updated timestamp.
        ai_config: AI provider configuration.
        prompt_config: Prompt generation configuration.
        project_path: Filesystem path to the project directory
            (runtime-only, excluded from serialisation).
    """

    project_id: str = ""
    project_name: str = ""
    created_at: str = ""
    updated_at: str = ""
    prompt_config: PromptConfig = Field(default_factory=PromptConfig)
    diagrams: list[Diagram] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    flows: list[Flow] = Field(default_factory=list)
    boundaries: list[TrustBoundary] = Field(default_factory=list)
    threat_register: ThreatRegister = Field(default_factory=ThreatRegister)
    custom_component_types: list[str] = Field(default_factory=list)
    project_path: str = Field(default="", exclude=True)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Convert the project to a JSON-serialisable dictionary.

        The ``project_path`` field is excluded because it is runtime-only.

        Returns:
            A dictionary containing all project metadata.
        """
        data = self.model_dump(exclude={"project_path"})
            
        return data

    @classmethod
    def from_dict(cls, data: dict[str, Any], project_path: str = "") -> Project:
        """Construct a Project instance from a dictionary.

        Args:
            data: Dictionary previously produced by ``to_dict``.
            project_path: Filesystem path to the project directory.

        Returns:
            A fully populated ``Project`` instance.
        """
        if "ai_config" in data:
            del data["ai_config"]
            
        return cls(**data, project_path=project_path)


# ======================================================================
# Public API
# ======================================================================

_PROJECT_FILE = "project.json"


def create_project(project_name: str, parent_dir: str | Path | None = None) -> Project:
    """Create a new ThreatPilot project. (M.4)"""
    if parent_dir is None:
        parent_dir = Path.cwd()
    else:
        parent_dir = Path(parent_dir).resolve() # Normalize path (M.4)

    # Path Traversal Protection: Block system-sensitive folders (M.4)
    path_str = str(parent_dir).lower()
    
    # 1. Block known system folders
    restricted_keywords = ["windows", "system32", "program files", "programdata", "etc", "var", "usr", "bin", "sbin", "tmp"]
    for kw in restricted_keywords:
        if f"\\{kw}" in path_str or f"/{kw}" in path_str or path_str.endswith(f"\\{kw}") or path_str.endswith(f"/{kw}"):
            raise ValueError(f"Restricted directory detected: '{kw}'. Please choose a different workspace.")

    # 2. Block direct drive roots (e.g., C:\)
    if len(parent_dir.parts) <= 1:
        raise ValueError("Cannot create projects directly in the drive root. Please choose a sub-folder.")

    # 3. Block user-sensitive shared roots
    if path_str.endswith(":\\"):
        raise ValueError("Drive root detected. Please choose a specific user subdirectory.")

    project_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()

    # Create a safe folder name from the user's project_name
    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', project_name)
    if not safe_name.strip('_'):
        safe_name = "threatpilot_project"

    project_dir = parent_dir / safe_name
    
    # Avoid collisions if a folder with that name already exists
    counter = 1
    while project_dir.exists():
        project_dir = parent_dir / f"{safe_name}_{counter}"
        counter += 1

    project_dir.mkdir(parents=True, exist_ok=False)

    # Create sub-directories expected by later modules
    (project_dir / "diagrams").mkdir()

    project = Project(
        project_id=project_id,
        project_name=project_name,
        created_at=now,
        updated_at=now,
        prompt_config=PromptConfig(),
        project_path=str(project_dir),
    )

    _write_project_file(project)
    return project


def load_project(project_path: str | Path) -> Project:
    """Load an existing ThreatPilot project from disk.

    Args:
        project_path: Path to the project directory (must contain a
            ``project.json`` file).

    Returns:
        The loaded ``Project`` instance.

    Raises:
        FileNotFoundError: If ``project.json`` does not exist.
        json.JSONDecodeError: If the file contains invalid JSON.
    """
    project_dir = Path(project_path)
    project_file = project_dir / _PROJECT_FILE

    if not project_file.exists():
        raise FileNotFoundError(
            f"Project file not found: {project_file}"
        )

    with project_file.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)

    # Load architecture
    arch_file = project_dir / "architecture.json"
    if arch_file.exists():
        with arch_file.open("r", encoding="utf-8") as fh:
            data.update(json.load(fh))

    # Load threats
    threats_file = project_dir / "threats.json"
    if threats_file.exists():
        with threats_file.open("r", encoding="utf-8") as fh:
            data.update(json.load(fh))

    return Project.from_dict(data, project_path=str(project_dir))


def save_project(project: Project) -> None:
    """Persist the project metadata to disk.

    The ``updated_at`` timestamp is refreshed automatically.

    Args:
        project: The ``Project`` instance to save.

    Raises:
        ValueError: If the project has no ``project_path`` set.
        OSError: If the file cannot be written.
    """
    if not project.project_path:
        raise ValueError("Cannot save a project without a project_path.")

    project.updated_at = datetime.now(timezone.utc).isoformat()
    _write_project_file(project)


# ======================================================================
# Internal helpers
# ======================================================================


def _write_project_file(project: Project) -> None:
    """Write the project metadata to ``project.json``.

    Args:
        project: The ``Project`` instance whose data is written.
    """
    project_dir = Path(project.project_path)
    project_dir.mkdir(parents=True, exist_ok=True)

    data = project.to_dict()

    # Split architecture data
    arch_keys = ["diagrams", "components", "flows", "boundaries", "custom_component_types"]
    arch_data = {k: data.pop(k, []) for k in arch_keys}

    # Split threat data
    threats_keys = ["threat_register"]
    threats_data = {k: data.pop(k, {}) for k in threats_keys}

    # Write project.json (Core Config)
    project_file = project_dir / _PROJECT_FILE
    with project_file.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)

    # Write architecture.json
    arch_file = project_dir / "architecture.json"
    with arch_file.open("w", encoding="utf-8") as fh:
        json.dump(arch_data, fh, indent=2, ensure_ascii=False)

    # Write threats.json
    threats_file = project_dir / "threats.json"
    with threats_file.open("w", encoding="utf-8") as fh:
        json.dump(threats_data, fh, indent=2, ensure_ascii=False)
