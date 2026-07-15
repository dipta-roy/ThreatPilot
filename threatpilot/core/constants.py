"""Core application constants for ThreatPilot."""

from __future__ import annotations

import re

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
    "ThreatPilot combines computer vision, native structured AI outputs, and "
    "Large Language Models to automatically extract components, assets, trust boundaries, "
    "and flows from architectural diagrams. It performs STRIDE and LINDDUN based "
    "threat analysis, generates CVSS scores, resolves connections via spatial proximity, "
    "and produces comprehensive security reports."
)

# Legal and framework metadata.
LICENSE_TYPE = "Apache License, Version 2.0"
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

# =============================================================================
# AI Processing Constants
# =============================================================================
# The number of mitigations to send to the AI in a single batch during consolidation.
# Smaller batch sizes improve map-reduce deduplication accuracy for local LLMs.
AI_MITIGATION_BATCH_SIZE = 15

# The minimum keyword-based Jaccard similarity (0.0 to 1.0) for two mitigations
# to be considered duplicates and merged. Uses keyword extraction with stop-word
# removal to compare only the distinguishing security terms, not boilerplate.
# After stop-word removal, cross-control pairs score 0.0 while within-control
# duplicates score 0.15-0.25. A threshold of 0.15 is the tested sweet spot.
MITIGATION_SIMILARITY_THRESHOLD = 0.15

# =============================================================================
# Cryptography & Security Constants
# =============================================================================
SERVICE_NAME = "ThreatPilot"
KEY_ID = "MasterEncryptionKey"
SALT = b"\x89\x1e(\xca\x0c\x84W\x8e\x9c\xd8\x8f\x8e\xe6\xcf\x80\xb0"
SECRET_PATTERNS = [
    re.compile(r"API_KEY=[\"']?(?P<secret>[a-zA-Z0-9_\-]{16,})[\"']?", re.IGNORECASE),
    re.compile(r"Bearer\s+(?P<secret>[a-zA-Z0-9_\-\.]{16,})", re.IGNORECASE),
    re.compile(r"([?&](?:key|token|auth|secret)=)(?P<secret>[a-zA-Z0-9_\-]{16,})", re.IGNORECASE),
    re.compile(r"(\"(?:api_key|secret|token|password|key)\":\s*\")(?P<secret>[a-zA-Z0-9_\-\.]{8,})(\")", re.IGNORECASE),
    re.compile(r"x-goog-api-key\s*:\s*(?P<secret>[a-zA-Z0-9_\-]{16,})", re.IGNORECASE),
]

# =============================================================================
# Computer Vision Constants
# =============================================================================
MAX_VISION_DIMENSION = 4096  # Maximum dimension for storage and UI display
MAX_AI_DIMENSION = 1536      # Maximum dimension for AI processing (Ollama/Gemini)

# =============================================================================
# XAI Mapping Constants
# =============================================================================
XAI_SECTION_MAP = {
    "attack_path": "### 1. Attack Path",
    "attack_vector": "### 1. Attack Path", 
    "privacy_impact_path": "### 1. Privacy Impact Path",
    "architectural_root_cause": "### 2. Architectural Root Cause", 
    "risk_rationalization": "### 3. Risk Rationalization", 
    "framework_alignment": "### 4. Framework Alignment"
}

# =============================================================================
# Threat Methodology Categories
# =============================================================================
STRIDE_CATEGORIES = {
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
    "Denial of Service", "Elevation of Privilege"
}
LINDDUN_CATEGORIES = {
    "Linkability", "Identifiability", "Non-repudiation", "Detectability",
    "Disclosure of Information", "Unawareness", "Non-compliance"
}

# =============================================================================
# UI HTML Templates
# =============================================================================
AUTH_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ThreatPilot Web Workspace Authentication</title>
  <style>
    body {
      background: #0b0f19;
      color: #f3f4f6;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
    }
    .card {
      background: #111827;
      border: 1px solid #1f2937;
      padding: 2.5rem;
      border-radius: 1rem;
      box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
      width: 100%;
      max-width: 380px;
      text-align: center;
      box-sizing: border-box;
    }
    h2 {
      margin-top: 0;
      color: #3b82f6;
      font-size: 1.5rem;
    }
    p {
      color: #9ca3af;
      font-size: 0.875rem;
      line-height: 1.5;
      margin-bottom: 2rem;
    }
    input {
      width: 100%;
      background: #1f2937;
      border: 1px solid #374151;
      padding: 0.75rem;
      color: #fff;
      font-size: 1.25rem;
      letter-spacing: 0.25em;
      text-align: center;
      border-radius: 0.5rem;
      margin-bottom: 1.5rem;
      box-sizing: border-box;
    }
    input:focus {
      outline: none;
      border-color: #3b82f6;
    }
    button {
      width: 100%;
      background: #2563eb;
      color: #fff;
      border: none;
      padding: 0.75rem;
      font-size: 0.875rem;
      font-weight: bold;
      border-radius: 0.5rem;
      cursor: pointer;
      transition: background 0.2s;
    }
    button:hover {
      background: #1d4ed8;
    }
    .error {
      color: #ef4444;
      font-size: 0.875rem;
      margin-top: 1rem;
      display: none;
    }
  </style>
</head>
<body>
  <div class="card">
    <h2>ThreatPilot Workspace</h2>
    <p>Please enter the 8-digit PIN generated by the ThreatPilot desktop application to access this visual architecture model.</p>
    <input type="text" id="pin" maxlength="8" placeholder="00000000" autocomplete="off" />
    <button onclick="verifyPin()">Authenticate Session</button>
    <div class="error" id="error">Invalid PIN. Please try again.</div>
  </div>

  <script>
    async function verifyPin() {
      const pin = document.getElementById('pin').value;
      const errorDiv = document.getElementById('error');
      errorDiv.style.display = 'none';

      try {
        const res = await fetch('/api/auth/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ pin })
        });
        if (res.ok) {
          // The backend sets the HttpOnly cookie securely via the Set-Cookie header.
          window.location.href = '/';
        } else {
          errorDiv.style.display = 'block';
        }
      } catch (e) {
        console.error(e);
        errorDiv.innerText = 'Connection error. Please try again.';
        errorDiv.style.display = 'block';
      }
    }
    document.getElementById('pin').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') {
        verifyPin();
      }
    });
  </script>
</body>
</html>
"""
