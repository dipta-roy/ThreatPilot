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


def main() -> None:
    """Launch the ThreatPilot desktop application."""
    app = QApplication(sys.argv)
    app.setApplicationName("ThreatPilot")
    app.setOrganizationName("ThreatPilot")
    app.setApplicationVersion("0.1.0")
    
    # Set global application icon
    icon_path = Path(__file__).parent / "threatpilot" / "resources" / "app-icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    # Apply a dark, modern stylesheet
    app.setStyleSheet(_build_stylesheet())

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


def _build_stylesheet() -> str:
    """Return a dark-themed stylesheet for the entire application.

    Returns:
        A CSS-like Qt stylesheet string.
    """
    return """
    /* ── Global ───────────────────────────────────────────── */
    QMainWindow, QWidget {
        background-color: #1e1e2e;
        color: #cdd6f4;
        font-family: "Segoe UI", "Inter", sans-serif;
        font-size: 13px;
    }

    /* ── Menu bar ─────────────────────────────────────────── */
    QMenuBar {
        background-color: #181825;
        color: #cdd6f4;
        border-bottom: 1px solid #313244;
        padding: 2px 0;
    }
    QMenuBar::item {
        padding: 5px 12px;
        border-radius: 4px;
    }
    QMenuBar::item:selected {
        background-color: #45475a;
    }
    QMenu {
        background-color: #1e1e2e;
        border: 1px solid #313244;
        border-radius: 6px;
        padding: 4px 0;
    }
    QMenu::item {
        padding: 6px 28px 6px 20px;
    }
    QMenu::item:selected {
        background-color: #45475a;
        border-radius: 4px;
    }
    QMenu::separator {
        height: 1px;
        background: #313244;
        margin: 4px 10px;
    }

    /* ── Toolbar ──────────────────────────────────────────── */
    QToolBar {
        background-color: #181825;
        border-bottom: 1px solid #313244;
        padding: 3px 6px;
        spacing: 4px;
    }
    QToolButton {
        background-color: transparent;
        color: #cdd6f4;
        border: none;
        border-radius: 4px;
        padding: 5px 10px;
    }
    QToolButton:hover {
        background-color: #313244;
    }
    QToolButton:pressed {
        background-color: #45475a;
    }

    /* ── Dock widgets ─────────────────────────────────────── */
    QDockWidget {
        color: #cdd6f4;
        titlebar-close-icon: none;
    }
    QDockWidget::title {
        background-color: #181825;
        padding: 8px 12px;
        border-bottom: 1px solid #313244;
        font-weight: bold;
        font-size: 12px;
    }
    QDockWidget::close-button,
    QDockWidget::float-button {
        background: transparent;
        border: none;
        padding: 2px;
    }
    QDockWidget::close-button:hover,
    QDockWidget::float-button:hover {
        background-color: #45475a;
        border-radius: 3px;
    }

    /* ── Graphics view (canvas) ───────────────────────────── */
    QGraphicsView {
        background-color: #11111b;
        border: none;
    }

    /* ── Status bar ───────────────────────────────────────── */
    QStatusBar {
        background-color: #181825;
        color: #a6adc8;
        border-top: 1px solid #313244;
        font-size: 12px;
        padding: 2px 8px;
    }

    /* ── Scrollbars ───────────────────────────────────────── */
    QScrollBar:vertical {
        background: #1e1e2e;
        width: 10px;
        border-radius: 5px;
    }
    QScrollBar::handle:vertical {
        background: #45475a;
        min-height: 30px;
        border-radius: 5px;
    }
    QScrollBar::handle:vertical:hover {
        background: #585b70;
    }
    QScrollBar::add-line:vertical,
    QScrollBar::sub-line:vertical {
        height: 0;
    }
    QScrollBar:horizontal {
        background: #1e1e2e;
        height: 10px;
        border-radius: 5px;
    }
    QScrollBar::handle:horizontal {
        background: #45475a;
        min-width: 30px;
        border-radius: 5px;
    }
    QScrollBar::handle:horizontal:hover {
        background: #585b70;
    }
    QScrollBar::add-line:horizontal,
    QScrollBar::sub-line:horizontal {
        width: 0;
    }
    """


if __name__ == "__main__":
    main()
