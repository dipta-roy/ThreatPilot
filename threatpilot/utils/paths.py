"""Path utilities for ThreatPilot.

Centralizes filesystem path calculations to ensure consistency and 
avoid repetition across the codebase.
"""

from pathlib import Path

# The root of the threatpilot source package
PACKAGE_ROOT = Path(__file__).parent.parent

# The root of the entire project repository
PROJECT_ROOT = PACKAGE_ROOT.parent

# Resource directory
RESOURCES_DIR = PACKAGE_ROOT / "resources"

# Persistent User Data
THREATPILOT_HOME = Path.home() / ".threatpilot"
CONFIG_FILE = THREATPILOT_HOME / "config.env"
RECENT_PROJECTS_FILE = THREATPILOT_HOME / "recent_projects.json"
KEYSTORE_FILE = THREATPILOT_HOME / ".keystore"
SSL_CERT_FILE = THREATPILOT_HOME / "cert.pem"
SSL_KEY_FILE = THREATPILOT_HOME / "key.pem"
# Log directory
LOG_DIR = THREATPILOT_HOME / "logs"
LOG_FILENAME = "threatpilot.log"

def get_resource_path(relative_path: str) -> Path:
    """Returns the absolute filesystem path to a bundled resource file."""
    return RESOURCES_DIR / relative_path

def get_app_icon_path() -> Path:
    """Returns the absolute filesystem path to the application's primary icon."""
    return get_resource_path("app-icon.png")

def get_recent_project_file() -> Path:
    """Returns the filesystem path to the recent project tracking metadata."""
    return RECENT_PROJECTS_FILE

def get_designer_dist_path() -> Path:
    """Returns the path to the Architecture Designer's built static files (dist)."""
    import sys
    if getattr(sys, "frozen", False):
        # cx_Freeze places include_files relative to the executable root
        return Path(sys.executable).parent / "designer" / "dist"
    else:
        # Development mode
        return PROJECT_ROOT / "designer" / "dist"
