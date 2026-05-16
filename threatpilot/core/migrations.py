"""Migration utilities for ThreatPilot projects.

Handles legacy data transformation and project structure updates.
"""

from __future__ import annotations
import uuid
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from threatpilot.core.project_manager import Project

def migrate_legacy_data(data: dict[str, Any]) -> dict[str, Any]:
    """Transform legacy project data to the current schema.
    
    Handles:
    - Component to Asset mirroring
    - Removal of deprecated config fields
    """
    if "ai_config" in data:
        del data["ai_config"]

    # Migration: Mirror components to assets if missing
    components = data.get("components", [])
    assets = data.get("assets", [])
    
    existing_asset_names = {a.get("name") for a in assets}
    migrated_any = False
    
    for c in components:
        a_name = c.get("name", "Unknown Element")
        if a_name not in existing_asset_names:
            a_type_raw = c.get("asset_type")
            a_type = "Informational" if str(a_type_raw).lower() == "informational" else "Physical"
            
            asset_dict = {
                "asset_id": uuid.uuid4().hex,
                "name": a_name,
                "type": a_type,
                "description": c.get("description", ""),
                "criticality": c.get("criticality_description") or c.get("criticality", "Medium"),
                "is_out_of_scope": c.get("is_out_of_scope", False),
                "out_of_scope_justification": c.get("out_of_scope_justification", "")
            }
            assets.append(asset_dict)
            existing_asset_names.add(a_name)
            migrated_any = True
            
    if migrated_any:
        data["assets"] = assets
        
    return data

def migrate_vulnerabilities(project: Project, data: dict[str, Any]) -> None:
    """Decouple vulnerabilities from threats and move to global register.
    
    Used during project load to ensure data consistency.
    """
    from threatpilot.core.threat_model import Vulnerability
    
    raw_threat_reg = data.get("threat_register")
    if not isinstance(raw_threat_reg, dict): return
        
    raw_threats = raw_threat_reg.get("threats", [])
    for rt in raw_threats:
        tid = rt.get("threat_id")
        legacy_vulns = rt.get("vulnerabilities", [])
        if not legacy_vulns: continue

        target_threat = next((t for t in project.threat_register.threats if t.threat_id == tid), None)
        if target_threat:
            for lv in legacy_vulns:
                if isinstance(lv, dict):
                    try:
                        v_obj = Vulnerability.model_validate(lv)
                        project.vulnerability_register.add_vulnerability(v_obj)
                        if v_obj.vulnerability_id not in target_threat.vulnerability_ids:
                            target_threat.vulnerability_ids.append(v_obj.vulnerability_id)
                    except Exception: continue
