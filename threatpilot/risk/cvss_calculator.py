"""CVSS Calculator module for ThreatPilot.

Provides logic to calculate CVSS v3.1 scores (Base) for identified threats.
Supports vector generation and numeric score calculation.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Optional
from pydantic import BaseModel


class CVSSMetrics(BaseModel):
    """Base metrics for CVSS v3.1."""

    # Exploitability Metrics
    attack_vector: str = "Network"       # N, A, L, P
    attack_complexity: str = "Low"       # L, H
    privileges_required: str = "None"     # N, L, H
    user_interaction: str = "None"       # N, R
    scope: str = "Unchanged"             # U, C

    # Impact Metrics
    confidentiality: str = "None"         # N, L, H
    integrity: str = "None"               # N, L, H
    availability: str = "None"            # N, L, H


def calculate_cvss_base_score(metrics: CVSSMetrics) -> float:
    """Calculate the Base CVSS v3.1 score of a threat.

    Note: This is a simplified implementation of the standard formula.
    Standard values for weights:
    AV: N:0.85, A:0.62, L:0.55, P:0.2
    AC: L:0.77, H:0.44
    PR: N:0.85, L:0.62(U) 0.68(C), H:0.27(U) 0.5(C)
    UI: N:0.85, R:0.62
    S: U:1.0, C:1.0
    C,I,A: N:0, L:0.22, H:0.56
    """
    
    # Mapping metrics to numeric weights
    av_weights = {"Network": 0.85, "Adjacent": 0.62, "Local": 0.55, "Physical": 0.2}
    ac_weights = {"Low": 0.77, "High": 0.44}
    
    # PR depends on Scope
    if metrics.scope == "Unchanged":
        pr_weights = {"None": 0.85, "Low": 0.62, "High": 0.27}
    else:
        pr_weights = {"None": 0.85, "Low": 0.68, "High": 0.50}
        
    ui_weights = {"None": 0.85, "Required": 0.62}
    cia_weights = {"None": 0, "Low": 0.22, "High": 0.56}

    # Calculations
    iss = 1 - (
        (1 - cia_weights[metrics.confidentiality]) * 
        (1 - cia_weights[metrics.integrity]) * 
        (1 - cia_weights[metrics.availability])
    )

    if metrics.scope == "Unchanged":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

    exploitability = (
        8.22 * 
        av_weights[metrics.attack_vector] * 
        ac_weights[metrics.attack_complexity] * 
        pr_weights[metrics.privileges_required] * 
        ui_weights[metrics.user_interaction]
    )

    if impact <= 0:
        return 0.0
    
    if metrics.scope == "Unchanged":
        score = min(impact + exploitability, 10)
    else:
        score = min(1.08 * (impact + exploitability), 10)

    # Return rounded to 1 decimal place
    import math
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
