"""ThreatPilot application entry point.

Usage:
    python main.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from threatpilot.ui.main_window import MainWindow
from threatpilot.utils.logger import setup_logging


def main() -> None:
    """Launch the ThreatPilot desktop application."""
    # Initialize logging infrastructure
    setup_logging()
    
    app = QApplication(sys.argv)
    app.setApplicationName("ThreatPilot")
    app.setOrganizationName("Dipta Roy")
    app.setApplicationVersion("0.5.0")
    
    # Set global application icon
    icon_path = Path(__file__).parent / "threatpilot" / "resources" / "app-icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # Apply initial theme
    _load_initial_stylesheet(app)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())

def _load_initial_stylesheet(app: QApplication) -> None:
    """Load the default dark theme from the resources directory."""
    style_path = Path(__file__).parent / "threatpilot" / "resources" / "style.qss"
    if style_path.exists():
        app.setStyleSheet(style_path.read_text())


if __name__ == "__main__":
    main()
