"""Centralized constants and default values for ThreatPilot."""

from __future__ import annotations

# =============================================================================
# Application Metadata
# =============================================================================
# The official name of the application, used in titles and process identification.
APP_NAME = "ThreatPilot"

# The name of the organization or author for OS-level registration.
ORGANIZATION_NAME = "Dipta Roy"

# A brief, punchy marketing tagline for the application.
APP_TAGLINE = "AI-Powered Threat Modeling Platform"

# A comprehensive description of the application's core functionality.
APP_DESCRIPTION = (
    "ThreatPilot combines computer vision and Large Language Models "
    "to automatically identify security risks from architectural "
    "diagrams. It performs STRIDE and LINDDUN based threat analysis, generates "
    "CVSS scores, and produces comprehensive security reports."
)

# Legal and framework metadata.
LICENSE_TYPE = "Proprietary"
DEVELOPMENT_FRAMEWORK = "Python 3.11"
SUPPORTED_AI_ENGINES = "Gemini · Ollama"
COPYRIGHT_TEXT = "© 2026 Dipta Roy. All rights reserved."

# =============================================================================
# Project Defaults
# =============================================================================
# The default name suggested when creating a new threat modeling project.
DEFAULT_PROJECT_NAME = "ThreatPilot Project"

# The internal filename used to store project metadata and architectural data.
PROJECT_FILE_NAME = "project.json"

# =============================================================================
# AI Configuration Defaults
# =============================================================================
# The default AI provider type used if no configuration exists (e.g., "ollama" or "gemini").
DEFAULT_AI_PROVIDER = "ollama"

# The default local address for the Ollama inference server.
DEFAULT_OLLAMA_ENDPOINT = "http://localhost:11434"

# The official base URL for Google's Gemini API services.
DEFAULT_GEMINI_ENDPOINT = "https://generativelanguage.googleapis.com"

# The default creativity/randomness setting for LLM responses (0.0 to 1.0).
DEFAULT_TEMPERATURE = 0.7

# The default maximum token limit for AI completions, ensuring large architectural reviews.
DEFAULT_MAX_TOKENS = 16384

# The default network timeout in seconds for AI provider requests.
DEFAULT_TIMEOUT = 3600

# The frequency (in minutes) for automatic project state persistence.
DEFAULT_AUTOSAVE_INTERVAL = 5

# =============================================================================
# Analysis Constants
# =============================================================================
# The maximum number of DFD nodes analyzed in a single AI request pass to avoid context saturation.
ANALYSIS_BATCH_THRESHOLD = 6

# The minimum required completion token limit to ensure structured JSON output is not truncated.
MIN_ANALYSIS_TOKENS = 16384

# =============================================================================
# AI Response Field Mapping
# =============================================================================
# Maps non-standardized AI-generated field names to the internal Threat domain model fields.
# This ensures compatibility with various LLM models that might use slightly different naming.
AI_FIELD_MAPPING = {
    "threat": "title", 
    "name": "title", 
    "mitigation": "mitigation", 
    "recommended_mitigation": "mitigation", 
    "remediation": "mitigation", 
    "stride": "category", 
    "threat_category": "category", 
    "type": "category", 
    "mitre_technique_id": "mitre_attack_id", 
    "mitre_id": "mitre_attack_id", 
    "attack_id": "mitre_attack_id", 
    "mitre_technique": "mitre_attack_technique", 
    "attack_technique": "mitre_attack_technique", 
    "affected_element": "affected_components", 
    "affected_item": "affected_components", 
    "component": "affected_components", 
    "element_type": "affected_element_type", 
    "asset_type": "affected_asset_type", 
    "score": "cvss_score", 
    "cvss": "cvss_score", 
    "vector": "cvss_vector", 
    "cvss_31_vector": "cvss_vector"
}

# List of keys the AI might use to provide nested vulnerability data within a threat object.
AI_VULN_KEYS = [
    "vulnerabilities", "vulns", "exploits", "flaws", 
    "security_vulnerabilities", "exploit_paths"
]

# =============================================================================
# UI Layout Constants
# =============================================================================
# The percentage of the screen width the application should occupy upon first launch (0.0 to 1.0).
WINDOW_WIDTH_PERCENT = 0.8

# The percentage of the screen height the application should occupy upon first launch (0.0 to 1.0).
WINDOW_HEIGHT_PERCENT = 0.8

# The absolute minimum width allowed for the main window to ensure layout integrity.
MIN_WINDOW_WIDTH = 1000

# The absolute minimum height allowed for the main window to ensure layout integrity.
MIN_WINDOW_HEIGHT = 650

# =============================================================================
# Security & Workspace Safeguards
# =============================================================================
# Keywords representing system-critical or restricted directories.
# These are used to prevent users from accidentally saving projects in sensitive OS locations.
RESTRICTED_PATH_KEYWORDS = [
    "windows", "system32", "program files", "programdata", 
    "etc", "var", "usr", "bin", "sbin", "tmp"
]
