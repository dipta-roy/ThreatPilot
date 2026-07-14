"""ThreatPilot application entry point.

Usage:
    python main.py
"""

from __future__ import annotations
import sys
import os
try:
    import torch
except ImportError:
    pass

from pathlib import Path
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication
from threatpilot import __version__
from threatpilot.ui.main_window import MainWindow
from threatpilot.utils.logger import setup_logging
from threatpilot.utils.paths import get_app_icon_path, get_resource_path

from threatpilot.core.constants import APP_NAME, ORGANIZATION_NAME

def main() -> None:
    """Launch the ThreatPilot desktop application."""
    setup_logging()
    
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORGANIZATION_NAME)
    app.setApplicationVersion(__version__)
    
    icon_path = get_app_icon_path()
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))
    
    _load_initial_stylesheet(app)

    window = MainWindow()
    window.showMaximized()
    sys.exit(app.exec())

def _load_initial_stylesheet(app: QApplication) -> None:
    """Load the default light theme from the resources directory."""
    style_path = get_resource_path("style_light.qss")
    if style_path.exists():
        app.setStyleSheet(style_path.read_text(encoding="utf-8"))

if __name__ == "__main__":
    main()