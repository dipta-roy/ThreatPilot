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

    def __init__(self, parent: QWidget | None = None, is_dark: bool = True) -> None:
        super().__init__(parent)
        self.setWindowTitle("About ThreatPilot")
        self.setFixedSize(520, 440)
        self._is_dark = is_dark
        self._setup_ui()

    def _setup_ui(self) -> None:
        dark = self._is_dark

        if dark:
            banner_grad   = "stop:0 #0d1117, stop:0.5 #161b22, stop:1 #1a1e2e"
            app_name_col  = "#58a6ff"
            tagline_col   = "#8b949e"
            sep_col       = "#30363d"
            content_bg    = "#0d1117"
            desc_col      = "#c9d1d9"
            label_col     = "#58a6ff"
            value_col     = "#c9d1d9"
            copy_col      = "#484f58"
            btn_bar_bg    = "#161b22"
            btn_bar_bdr   = "#30363d"
            btn_bg        = "#21262d"
            btn_fg        = "#c9d1d9"
            btn_bdr       = "#30363d"
            btn_hover_bg  = "#30363d"
            btn_hover_bdr = "#58a6ff"
        else:
            banner_grad   = "stop:0 #f6f8fa, stop:0.5 #eaeef2, stop:1 #dce3eb"
            app_name_col  = "#0969da"
            tagline_col   = "#57606a"
            sep_col       = "#d0d7de"
            content_bg    = "#ffffff"
            desc_col      = "#24292f"
            label_col     = "#0969da"
            value_col     = "#24292f"
            copy_col      = "#8c959f"
            btn_bar_bg    = "#f6f8fa"
            btn_bar_bdr   = "#d0d7de"
            btn_bg        = "#f6f8fa"
            btn_fg        = "#24292f"
            btn_bdr       = "#d0d7de"
            btn_hover_bg  = "#eaeef2"
            btn_hover_bdr = "#0969da"

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        banner = QWidget()
        banner.setStyleSheet(
            f"background: qlineargradient("
            f"x1:0, y1:0, x2:1, y2:1, {banner_grad});"
        )
        banner_layout = QVBoxLayout(banner)
        banner_layout.setContentsMargins(30, 28, 30, 22)
        banner_layout.setSpacing(12)

        header_row = QHBoxLayout()
        header_row.setSpacing(16)

        icon_path = Path(__file__).parent.parent / "resources" / "app-icon.png"
        if icon_path.exists():
            logo_label = QLabel()
            pixmap = QPixmap(str(icon_path)).scaled(
                72, 72,
                Qt.AspectRatioMode.KeepAspectRatio,
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
        app_name.setStyleSheet(f"color: {app_name_col}; background: transparent;")
        title_col.addWidget(app_name)

        tagline = QLabel("AI-Powered Threat Modeling Platform")
        tagline.setFont(QFont("Segoe UI", 10))
        tagline.setStyleSheet(f"color: {tagline_col}; background: transparent;")
        title_col.addWidget(tagline)

        header_row.addLayout(title_col)
        header_row.addStretch()
        banner_layout.addLayout(header_row)

        version_badge = QLabel("  v1.2.0  ")
        version_badge.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        version_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_badge.setFixedWidth(90)
        version_badge.setStyleSheet(
            "color: #f0f6fc; background-color: #238636; "
            "border-radius: 10px; padding: 3px 8px;"
        )
        banner_layout.addWidget(version_badge, alignment=Qt.AlignmentFlag.AlignLeft)
        root.addWidget(banner)

        sep = QWidget()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background-color: {sep_col};")
        root.addWidget(sep)
        content = QWidget()
        content.setStyleSheet(f"background-color: {content_bg};")
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
        desc.setStyleSheet(f"color: {desc_col}; background: transparent; line-height: 150%;")
        content_layout.addWidget(desc)

        info_items = [
            ("Author",    "Dipta Roy"),
            ("License",   "Proprietary"),
            ("Framework", "PySide6 / Python 3.11+"),
            ("AI Engines", "Gemini ·  Ollama"),
        ]

        for label_text, value_text in info_items:
            row = QHBoxLayout()
            row.setSpacing(8)
            lbl = QLabel(f"{label_text}:")
            lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            lbl.setStyleSheet(f"color: {label_col}; background: transparent;")
            lbl.setFixedWidth(95)
            row.addWidget(lbl)
            val = QLabel(value_text)
            val.setFont(QFont("Segoe UI", 10))
            val.setStyleSheet(f"color: {value_col}; background: transparent;")
            row.addWidget(val)
            row.addStretch()
            content_layout.addLayout(row)

        content_layout.addStretch()

        copyright_label = QLabel("© 2026 Dipta Roy. All rights reserved.")
        copyright_label.setFont(QFont("Segoe UI", 9))
        copyright_label.setStyleSheet(f"color: {copy_col}; background: transparent;")
        copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        content_layout.addWidget(copyright_label)
        root.addWidget(content, 1)

        btn_bar = QWidget()
        btn_bar.setStyleSheet(
            f"background-color: {btn_bar_bg}; border-top: 1px solid {btn_bar_bdr};"
        )
        btn_layout = QHBoxLayout(btn_bar)
        btn_layout.setContentsMargins(20, 10, 20, 10)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        btns.setStyleSheet(
            f"QPushButton {{ background-color: {btn_bg}; color: {btn_fg}; "
            f"border: 1px solid {btn_bdr}; border-radius: 6px; "
            f"padding: 6px 20px; font-weight: bold; }}"
            f"QPushButton:hover {{ background-color: {btn_hover_bg}; border-color: {btn_hover_bdr}; }}"
        )
        btn_layout.addStretch()
        btn_layout.addWidget(btns)
        root.addWidget(btn_bar)
