"""CVSS Calculator module for ThreatPilot.

Provides logic to calculate CVSS v3.1 scores (Base) for identified threats.
Supports vector generation and numeric score calculation.
"""

from __future__ import annotations

from typing import Dict, Optional
import math
from pydantic import BaseModel


class CVSSMetrics(BaseModel):
    """Base metrics for CVSS v3.1."""

    attack_vector: str = "Network"
    attack_complexity: str = "Low"
    privileges_required: str = "None"
    user_interaction: str = "None"
    scope: str = "Unchanged"
    confidentiality: str = "None"
    integrity: str = "None"
    availability: str = "None"


def calculate_cvss_base_score(metrics: CVSSMetrics) -> float:
    """Calculate the Base CVSS v3.1 score of a threat."""
    
    av_weights = {"Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.2}
    ac_weights = {"Low": 0.77, "High": 0.44}
    
    if metrics.scope == "Unchanged":
        pr_weights = {"None": 0.85, "Low": 0.62, "High": 0.27}
    else:
        pr_weights = {"None": 0.85, "Low": 0.68, "High": 0.50}
        
    ui_weights = {"None": 0.85, "Required": 0.62}
    cia_weights = {"None": 0, "Low": 0.22, "High": 0.56}

    iss = 1 - (
        (1 - cia_weights.get(metrics.confidentiality, 0)) * 
        (1 - cia_weights.get(metrics.integrity, 0)) * 
        (1 - cia_weights.get(metrics.availability, 0))
    )

    if metrics.scope == "Unchanged":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = (
        8.22 * 
        av_weights.get(metrics.attack_vector, 0.85) * 
        ac_weights.get(metrics.attack_complexity, 0.77) * 
        pr_weights.get(metrics.privileges_required, 0.85) * 
        ui_weights.get(metrics.user_interaction, 0.85)
    )

    if impact <= 0:
        return 0.0
    
    if metrics.scope == "Unchanged":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    return math.ceil(score * 10) / 10.0

def get_cvss_severity(score: float) -> str:
    """Return the CVSS v3.1 severity rating based on score."""
    if score == 0:
        return "None"
    if 0.1 <= score <= 3.9:
        return "Low"
    if 4.0 <= score <= 6.9:
        return "Medium"
    if 7.0 <= score <= 8.9:
        return "High"
    if 9.0 <= score <= 10.0:
        return "Critical"
    return "Unknown"


def parse_cvss_vector(vector: str) -> CVSSMetrics:
    """Parse a CVSS v3.1 vector string into CVSSMetrics."""
    metrics = CVSSMetrics()
    if not vector or not vector.startswith("CVSS:3.1/"):
        return metrics
    
    parts = vector.split("/")
    mapping = {
        "AV": ("attack_vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
        "AC": ("attack_complexity", {"L": "Low", "H": "High"}),
        "PR": ("privileges_required", {"N": "None", "L": "Low", "H": "High"}),
        "UI": ("user_interaction", {"N": "None", "R": "Required"}),
        "S": ("scope", {"U": "Unchanged", "C": "Changed"}),
        "C": ("confidentiality", {"N": "None", "L": "Low", "H": "High"}),
        "I": ("integrity", {"N": "None", "L": "Low", "H": "High"}),
        "A": ("availability", {"N": "None", "L": "Low", "H": "High"}),
    }
    
    for part in parts[1:]:
        if ":" in part:
            key, val = part.split(":", 1)
            if key in mapping:
                attr, val_map = mapping[key]
                if val in val_map:
                    setattr(metrics, attr, val_map[val])
                    
    return metrics


def generate_cvss_vector(metrics: CVSSMetrics) -> str:
    """Generate a CVSS v3.1 vector string from CVSSMetrics."""
    mapping = {
        "attack_vector": ("AV", {"Network": "N", "Adjacent": "A", "Local": "L", "Physical": "P"}),
        "attack_complexity": ("AC", {"Low": "L", "High": "H"}),
        "privileges_required": ("PR", {"None": "N", "Low": "L", "High": "H"}),
        "user_interaction": ("UI", {"None": "N", "Required": "R"}),
        "scope": ("S", {"Unchanged": "U", "Changed": "C"}),
        "confidentiality": ("C", {"None": "N", "Low": "L", "High": "H"}),
        "integrity": ("I", {"None": "N", "Low": "L", "High": "H"}),
        "availability": ("A", {"None": "N", "Low": "L", "High": "H"}),
    }
    
    parts = ["CVSS:3.1"]
    for attr, (key, val_map) in mapping.items():
        val = getattr(metrics, attr)
        parts.append(f"{key}:{val_map.get(val, 'N')}")
        
    return "/".join(parts)
