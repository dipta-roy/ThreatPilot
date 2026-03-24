"""Control Mapping module for ThreatPilot.

Maps identified threats (by category) to standard security controls
from established frameworks (NIST, OWASP, CIS, etc.).
"""

from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel

from threatpilot.core.threat_model import STRIDECategory


class SecurityControl(BaseModel):
    """A standard security control recommended to mitigate a threat.

    Attributes:
        code: Framework code (e.g. 'NIST AC-2').
        name: Short name of the control.
        description: Full text description of the control's purpose.
    """

    code: str
    name: str
    description: str


# A default library of standard STRIDE-to-control mappings
DEFAULT_CONTROL_LIBRARY: Dict[STRIDECategory, List[SecurityControl]] = {
    STRIDECategory.SPOOFING: [
        SecurityControl(
            code="NIST AC-2",
            name="Account Management",
            description="Manage information system accounts and control access."
        ),
        SecurityControl(
            code="OWASP-A07",
            name="Identification and Authentication Failures",
            description="Ensure robust credential management and MFA."
        )
    ],
    STRIDECategory.TAMPERING: [
        SecurityControl(
            code="NIST SI-7",
            name="Software/Firmware Integrity",
            description="Employ integrity verification tools to detect unauthorised changes."
        ),
        SecurityControl(
            code="NIST AU-11",
            name="Audit Record Retention",
            description="Retain audit records to support after-the-fact investigations."
        )
    ],
    STRIDECategory.REPUDIATION: [
        SecurityControl(
            code="NIST AU-10",
            name="Non-repudiation",
            description="Ensure that events can be linked back to specific persons/entities."
        )
    ],
    STRIDECategory.INFORMATION_DISCLOSURE: [
        SecurityControl(
            code="NIST SC-28",
            name="Protection of Information at Rest",
            description="Protect the confidentiality and integrity of information at rest."
        ),
        SecurityControl(
            code="OWASP-A02",
            name="Cryptographic Failures",
            description="Implement strong hashing and encryption for sensitive data."
        )
    ],
    STRIDECategory.DENIAL_OF_SERVICE: [
        SecurityControl(
            code="NIST SC-5",
            name="Denial-of-Service Protection",
            description="Implement rate-limiting and traffic filtering to mitigate DoS attacks."
        )
    ],
    STRIDECategory.ELEVATION_OF_PRIVILEGE: [
        SecurityControl(
            code="NIST AC-6",
            name="Least Privilege",
            description="Employ the principle of least privilege, allowing only necessary access."
        )
    ]
}


def get_suggested_controls(category: STRIDECategory) -> List[SecurityControl]:
    """Retrieve standard security control suggestions for a STRIDE category.

    Args:
        category: The STRIDE category to lookup.

    Returns:
        A list of ``SecurityControl`` objects mapped to that category.
    """
    return DEFAULT_CONTROL_LIBRARY.get(category, [])
