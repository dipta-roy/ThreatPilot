"""About dialog for ThreatPilot.

Provides a polished, branded About window with logo, version info,
author details, and application description.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QPixmap
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QVBoxLayout,
    QWidget,
)


class AboutDialog(QDialog):
    """Premium About dialog for ThreatPilot branding."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("About ThreatPilot")
        self.setFixedSize(520, 440)
        self._setup_ui()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Top banner area ──────────────────────────────────
        banner = QWidget()
        banner.setStyleSheet(
            "background: qlineargradient("
            "x1:0, y1:0, x2:1, y2:1, "
            "stop:0 #0d1117, stop:0.5 #161b22, stop:1 #1a1e2e);"
        )
        banner_layout = QVBoxLayout(banner)
        banner_layout.setContentsMargins(30, 28, 30, 22)
        banner_layout.setSpacing(12)

        # Logo + app name row
        header_row = QHBoxLayout()
        header_row.setSpacing(16)

        icon_path = Path(__file__).parent.parent / "resources" / "app-icon.png"
        if icon_path.exists():
            logo_label = QLabel()
            pixmap = QPixmap(str(icon_path)).scaled(
                72, 72, Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            logo_label.setPixmap(pixmap)
            logo_label.setFixedSize(72, 72)
            logo_label.setStyleSheet("background: transparent;")
            header_row.addWidget(logo_label)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        app_name = QLabel("ThreatPilot")
        app_name.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        app_name.setStyleSheet("color: #58a6ff; background: transparent;")
        title_col.addWidget(app_name)

        tagline = QLabel("AI-Powered Threat Modeling Platform")
        tagline.setFont(QFont("Segoe UI", 10))
        tagline.setStyleSheet("color: #8b949e; background: transparent;")
        title_col.addWidget(tagline)

        header_row.addLayout(title_col)
        header_row.addStretch()
        banner_layout.addLayout(header_row)

        # Version badge
        version_badge = QLabel("  v0.3 Beta  ")
        version_badge.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        version_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_badge.setFixedWidth(90)
        version_badge.setStyleSheet(
            "color: #f0f6fc; background-color: #238636; "
            "border-radius: 10px; padding: 3px 8px;"
        )
        banner_layout.addWidget(version_badge, alignment=Qt.AlignmentFlag.AlignLeft)

        root.addWidget(banner)

        # ── Separator ────────────────────────────────────────
        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #30363d;")
        root.addWidget(sep)

        # ── Content area ─────────────────────────────────────
        content = QWidget()
        content.setStyleSheet("background-color: #0d1117;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(30, 22, 30, 16)
        content_layout.setSpacing(14)

        desc = QLabel(
            "ThreatPilot combines computer vision and Large Language Models "
            "to automatically identify security risks from architectural "
            "diagrams. It performs STRIDE-based threat analysis, generates "
            "CVSS scores, and produces comprehensive security reports."
        )
        desc.setWordWrap(True)
        desc.setFont(QFont("Segoe UI", 10))
        desc.setStyleSheet("color: #c9d1d9; background: transparent; line-height: 150%;")
        content_layout.addWidget(desc)

        # Info grid
        info_items = [
            ("Author", "Dipta Roy"),
            ("License", "Proprietary"),
            ("Framework", "PySide6 / Python 3.11+"),
            ("AI Engines", "Gemini · Claude · Ollama · Custom API"),
        ]

        for label_text, value_text in info_items:
            row = QHBoxLayout()
            row.setSpacing(8)

            lbl = QLabel(f"{label_text}:")
            lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            lbl.setStyleSheet("color: #58a6ff; background: transparent;")
            lbl.setFixedWidth(95)
            row.addWidget(lbl)

            val = QLabel(value_text)
            val.setFont(QFont("Segoe UI", 10))
            val.setStyleSheet("color: #c9d1d9; background: transparent;")
            row.addWidget(val)

            row.addStretch()
            content_layout.addLayout(row)

        content_layout.addStretch()

        # Copyright
        copyright_label = QLabel("© 2026 Dipta Roy. All rights reserved.")
        copyright_label.setFont(QFont("Segoe UI", 9))
        copyright_label.setStyleSheet("color: #484f58; background: transparent;")
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(copyright_label)

        root.addWidget(content, 1)

        # ── Close button ─────────────────────────────────────
        btn_bar = QWidget()
        btn_bar.setStyleSheet("background-color: #161b22; border-top: 1px solid #30363d;")
        btn_layout = QHBoxLayout(btn_bar)
        btn_layout.setContentsMargins(20, 10, 20, 10)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        btns.setStyleSheet(
            "QPushButton { background-color: #21262d; color: #c9d1d9; "
            "border: 1px solid #30363d; border-radius: 6px; "
            "padding: 6px 20px; font-weight: bold; }"
            "QPushButton:hover { background-color: #30363d; border-color: #58a6ff; }"
        )
        btn_layout.addStretch()
        btn_layout.addWidget(btns)

        root.addWidget(btn_bar)
