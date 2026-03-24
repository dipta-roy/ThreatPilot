"""Excel export module for ThreatPilot.

Provides logic to export the threat register into Microsoft Excel (.xlsx)
format for reporting and external compliance tracking.
"""

from __future__ import annotations

import pandas as pd
from pathlib import Path
from typing import List

from threatpilot.core.threat_model import ThreatRegister


def export_to_excel(register: ThreatRegister, output_path: str | Path) -> None:
    """Export the contents of a ThreatRegister into an Excel file.

    Flattens threat models into a table format and saves them using pandas.

    Args:
        register: The project's current threat registry.
        output_path: Where to save the resulting .xlsx file.

    Raises:
        ValueError: If the register is empty or invalid.
        OSError: If the file cannot be written.
    """
    if not register.threats:
        raise ValueError("Cannot export empty threat register.")

    # Flatten threats to dictionary list for pandas
    data = []
    for t in register.threats:
        data.append({
            "Threat ID": t.threat_id,
            "Category (STRIDE)": t.category.value,
            "Title": t.title,
            "Description": t.description,
            "Impact": t.impact,
            "Likelihood (1-5)": t.likelihood,
            "CVSS Score": t.cvss_score,
            "CVSS Vector": t.cvss_vector,
            "Affected Components": t.affected_components,
            "Mitigation": t.mitigation,
            "Accepted Risk": "Yes" if t.is_accepted_risk else "No",
            "Acceptance Rationale": t.acceptance_justification or ""
        })

    # Create DataFrame
    df = pd.DataFrame(data)

    # Save to Excel
    # engine='openpyxl' is required for .xlsx
    df.to_excel(output_path, index=False, engine='openpyxl')
