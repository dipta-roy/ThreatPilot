"""Risk calculation and mapping utilities for ThreatPilot."""

from __future__ import annotations

def score_to_impact_score(cvss_score: float) -> int:
    """Maps a numeric CVSS score (0.0-10.0) to a 1-5 Impact rating.
    
    1: Low (< 2.0)
    2: Minor (< 4.0)
    3: Mid (< 7.0)
    4: Major (< 9.0)
    5: Critical (>= 9.0)
    """
    if cvss_score >= 9.0:
        return 5
    if cvss_score >= 7.0:
        return 4
    if cvss_score >= 4.0:
        return 3
    if cvss_score >= 2.0:
        return 2
    return 1

def calculate_risk_rating(likelihood: int, impact: int) -> int:
    """Calculates a composite Risk Rating (1-25) based on Likelihood and Impact."""
    return likelihood * impact

def get_risk_label(cvss_score: float) -> str:
    """Returns a text label ('None', 'Low', 'Medium', 'High', 'Critical') for a CVSS score."""
    from threatpilot.risk.cvss_calculator import get_cvss_severity
    return get_cvss_severity(cvss_score)

def get_risk_color(score: float | int) -> tuple[str, str]:
    """Returns (background_hex, text_hex) for a given CVSS score or Risk Rating.
    
    If the score is <= 10.0, it is treated as a CVSS v3.1 score.
    If the score is > 10.0, it is treated as a composite Risk Rating (1-25).
    """
    # Composite Risk Rating (1-25)
    if score > 10.0:
        if score >= 15: return ("#8B0000", "#FFFFFF")  # Critical
        if score >= 10: return ("#D73A49", "#FFFFFF")  # High
        if score >= 6:  return ("#D29922", "#000000")  # Medium
        if score >= 3:  return ("#30363D", "#FFFFFF")  # Low
        return ("#238636", "#FFFFFF")                  # Very Low

    # CVSS v3.1 Score (0.0-10.0)
    if score >= 9.0: return ("#8B0000", "#FFFFFF")  # Critical
    if score >= 7.0: return ("#D73A49", "#FFFFFF")  # High
    if score >= 4.0: return ("#D29922", "#000000")  # Medium
    if score >= 0.1: return ("#30363D", "#FFFFFF")  # Low
    return ("#238636", "#FFFFFF")                  # None
