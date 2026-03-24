"""CVSS 3.1 Base Score Calculation Utility for ThreatPilot."""

def calculate_cvss_31(vector_str: str) -> tuple[float, str]:
    """Calculate the CVSS 3.1 Base Score from a vector string.
    
    Example Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    Returns: (Score, Vector)
    """
    if not vector_str.startswith("CVSS:3.1/"):
        return 0.0, vector_str

    try:
        # 1. Parse parts
        parts = {}
        for part in vector_str.split("/")[1:]:
            k, v = part.split(":")
            parts[k] = v

        # 2. Extract values based on standard 3.1 weights
        # Exploitability Metrics
        AV_MAP = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
        AC_MAP = {"L": 0.77, "H": 0.44}
        PR_MAP_U = {"N": 0.85, "L": 0.62, "H": 0.27}  # Scope Unchanged
        PR_MAP_C = {"N": 0.85, "L": 0.68, "H": 0.5}   # Scope Changed
        UI_MAP = {"N": 0.85, "R": 0.62}

        # Impact Metrics
        ISS_MAP = {"N": 0.0, "L": 0.22, "H": 0.56}

        av = AV_MAP.get(parts.get("AV"), 0.85)
        ac = AC_MAP.get(parts.get("AC"), 0.77)
        ui = UI_MAP.get(parts.get("UI"), 0.85)
        scope = parts.get("S", "U")
        
        pr_map = PR_MAP_C if scope == "C" else PR_MAP_U
        pr = pr_map.get(parts.get("PR"), 0.85)

        c = ISS_MAP.get(parts.get("C"), 0.0)
        i = ISS_MAP.get(parts.get("I"), 0.0)
        a = ISS_MAP.get(parts.get("A"), 0.0)

        # 3. Calculation Formula
        iss = 1 - ((1 - c) * (1 - i) * (1 - a))
        
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02)**15)
        
        exploitability = 8.22 * av * ac * pr * ui
        
        if impact <= 0:
            return 0.0, vector_str
        
        if scope == "U":
            score = min(impact + exploitability, 10.0)
        else:
            score = min(1.08 * (impact + exploitability), 10.0)

        # Special case: if no impact, score is 0
        if c == 0 and i == 0 and a == 0:
            return 0.0, vector_str

        # Round up to 1 decimal place (CVMSS 3.1 rounding is complex, using simple ciel for now)
        import math
        score = math.ceil(score * 10) / 10.0
        
        return score, vector_str
        
    except Exception:
        return 0.0, vector_str
