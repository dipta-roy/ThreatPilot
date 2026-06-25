"""Project lifecycle and persistence management for ThreatPilot."""

from __future__ import annotations
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from pydantic import BaseModel, Field
from threatpilot.config.prompt_config import PromptConfig
from threatpilot.core.diagram_model import Diagram
from threatpilot.core.domain_models import Component, Flow, TrustBoundary, Asset, MitigationRequirement
from threatpilot.core.threat_model import ThreatRegister, VulnerabilityRegister
from threatpilot.core.migrations import migrate_legacy_data, migrate_vulnerabilities
from threatpilot.core.constants import PROJECT_FILE_NAME, RESTRICTED_PATH_KEYWORDS

class Project(BaseModel):
    """Data model representing a ThreatPilot project and its security state."""
    project_id: str = ""
    project_name: str = ""
    created_at: str = ""
    updated_at: str = ""
    prompt_config: PromptConfig = Field(default_factory=PromptConfig)
    diagrams: list[Diagram] = Field(default_factory=list)
    components: list[Component] = Field(default_factory=list)
    flows: list[Flow] = Field(default_factory=list)
    boundaries: list[TrustBoundary] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    threat_register: ThreatRegister = Field(default_factory=ThreatRegister)
    vulnerability_register: VulnerabilityRegister = Field(default_factory=VulnerabilityRegister)
    custom_component_types: list[str] = Field(default_factory=list)
    mitigation_requirements: list[MitigationRequirement] = Field(default_factory=list)
    mitigation_excel_path: str | None = ""
    project_path: str = Field(default="", exclude=True)

    def to_dict(self) -> dict[str, Any]:
        """Serializes the project to a dictionary, excluding runtime-only fields."""
        return self.model_dump(exclude={"project_path"})

    @classmethod
    def from_dict(cls, data: dict[str, Any], project_path: str = "") -> Project:
        """Hydrates a Project instance from a dictionary and applies data migrations."""
        data = migrate_legacy_data(data)
        project = cls.model_validate(data)
        project.project_path = project_path
        migrate_vulnerabilities(project, data)
        return project

_PROJECT_FILE = PROJECT_FILE_NAME

def create_project(project_name: str, parent_dir: str | Path | None = None) -> Project:
    """Creates a new project directory structure and metadata file."""
    if parent_dir is None:
        parent_dir = Path.cwd()
    else:
        parent_dir = Path(parent_dir).resolve()

    path_str = str(parent_dir).lower()
    for kw in RESTRICTED_PATH_KEYWORDS:
        if f"\\{kw}" in path_str or f"/{kw}" in path_str or path_str.endswith(f"\\{kw}") or path_str.endswith(f"/{kw}"):
            raise ValueError(f"Restricted directory detected: '{kw}'. Please choose a different workspace.")

    if len(parent_dir.parts) <= 1:
        raise ValueError("Cannot create projects directly in the drive root. Please choose a sub-folder.")

    if path_str.endswith(":\\"):
        raise ValueError("Drive root detected. Please choose a specific user subdirectory.")

    project_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '_', project_name)
    if not safe_name.strip('_'):
        safe_name = "threatpilot_project"
    
    project_dir = parent_dir / safe_name
    counter = 1
    while project_dir.exists():
        project_dir = parent_dir / f"{safe_name}_{counter}"
        counter += 1
        
    project_dir.mkdir(parents=True, exist_ok=False)
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
    """Loads project metadata and sidecar data from a given directory."""
    project_dir = Path(project_path)
    project_file = project_dir / _PROJECT_FILE

    if not project_file.exists():
        raise FileNotFoundError(f"Project file not found: {project_file}")

    with project_file.open("r", encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)

    for sidecar in ["architecture.json", "threats.json", "vulnerabilities.json", "mitigations.json"]:
        sidecar_path = project_dir / sidecar
        if sidecar_path.exists():
            with sidecar_path.open("r", encoding="utf-8") as fh:
                data.update(json.load(fh))

    return Project.from_dict(data, project_path=str(project_dir))

def save_project(project: Project) -> None:
    """Persists the current project state to disk with an updated timestamp."""
    if not project.project_path:
        raise ValueError("Cannot save a project without a project_path.")

    project.updated_at = datetime.now(timezone.utc).isoformat()
    _write_project_file(project)

def _atomic_write_json(file_path: Path, data: dict[str, Any]) -> None:
    """Writes data to a temporary file and then atomically replaces the target file."""
    # Use the same directory as the target file to ensure os.replace works (must be same filesystem)
    temp_fd, temp_path = tempfile.mkstemp(dir=file_path.parent, prefix=file_path.name, suffix=".tmp")
    try:
        with os.fdopen(temp_fd, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)
            fh.flush()
            os.fsync(fh.fileno())
        # Atomic replacement
        os.replace(temp_path, file_path)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise

def _write_project_file(project: Project) -> None:
    """Writes core metadata and specialized sidecar files to the project directory."""
    project_dir = Path(project.project_path)
    project_dir.mkdir(parents=True, exist_ok=True)

    data = project.to_dict()

    arch_keys = ["diagrams", "components", "flows", "boundaries", "assets", "custom_component_types"]
    arch_data = {k: data.pop(k, []) for k in arch_keys}
    
    threats_data = {"threat_register": data.pop("threat_register", {})}
    vuln_data = {"vulnerability_register": data.pop("vulnerability_register", {})}

    mitigation_keys = ["mitigation_requirements", "mitigation_excel_path"]
    mitigation_data = {k: data.pop(k, [] if k == "mitigation_requirements" else "") for k in mitigation_keys}

    # Perform atomic writes for all project files
    _atomic_write_json(project_dir / _PROJECT_FILE, data)
    _atomic_write_json(project_dir / "architecture.json", arch_data)
    _atomic_write_json(project_dir / "threats.json", threats_data)
    _atomic_write_json(project_dir / "vulnerabilities.json", vuln_data)
    _atomic_write_json(project_dir / "mitigations.json", mitigation_data)
