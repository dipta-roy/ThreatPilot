"""About dialog for ThreatPilot.

Provides a polished, branded About window with logo, version info,
author details, and application description.
"""

from __future__ import annotations
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
from threatpilot.utils.paths import get_app_icon_path
from threatpilot.core.constants import (
    APP_NAME, ORGANIZATION_NAME, APP_TAGLINE, APP_DESCRIPTION,
    LICENSE_TYPE, DEVELOPMENT_FRAMEWORK, SUPPORTED_AI_ENGINES, COPYRIGHT_TEXT
)

class AboutDialog(QDialog):
    """Premium About dialog for ThreatPilot branding."""

    def __init__(self, parent: QWidget | None = None, is_dark: bool = True) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_NAME}")
        self.setMinimumSize(520, 440)
        self.setSizeGripEnabled(True)
        self._is_dark = is_dark
        self._setup_ui()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Banner Section
        banner = QWidget()
        banner.setObjectName("about_banner")
        banner_layout = QVBoxLayout(banner)
        banner_layout.setContentsMargins(30, 28, 30, 22)
        banner_layout.setSpacing(12)

        header_row = QHBoxLayout()
        header_row.setSpacing(16)

        icon_path = get_app_icon_path()
        if icon_path.exists():
            logo_label = QLabel()
            pixmap = QPixmap(str(icon_path)).scaled(
                72, 72,
                Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation,
            )
            logo_label.setPixmap(pixmap)
            logo_label.setFixedSize(72, 72)
            logo_label.setObjectName("about_logo")
            header_row.addWidget(logo_label)

        title_col = QVBoxLayout()
        title_col.setSpacing(2)

        app_name = QLabel(APP_NAME)
        app_name.setObjectName("about_app_name")
        app_name.setFont(QFont("Segoe UI", 22, QFont.Weight.Bold))
        title_col.addWidget(app_name)

        tagline = QLabel(APP_TAGLINE)
        tagline.setObjectName("about_tagline")
        tagline.setFont(QFont("Segoe UI", 10))
        title_col.addWidget(tagline)

        header_row.addLayout(title_col)
        header_row.addStretch()
        banner_layout.addLayout(header_row)

        from threatpilot import __version__
        version_badge = QLabel(f"  v{__version__}  ")
        version_badge.setObjectName("about_version_badge")
        version_badge.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
        version_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        version_badge.setFixedWidth(90)
        version_badge.setStyleSheet(
            "color: #f0f6fc; background-color: #238636; "
            "border-radius: 10px; padding: 3px 8px;"
        )
        banner_layout.addWidget(version_badge, alignment=Qt.AlignmentFlag.AlignLeft)
        root.addWidget(banner)

        # Separator Line
        sep = QWidget()
        sep.setObjectName("about_separator")
        sep.setFixedHeight(1)
        root.addWidget(sep)

        # Main Content Area
        content = QWidget()
        content.setObjectName("about_content")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(30, 22, 30, 16)
        content_layout.setSpacing(14)

        desc = QLabel(APP_DESCRIPTION)
        desc.setObjectName("about_desc")
        desc.setWordWrap(True)
        desc.setFont(QFont("Segoe UI", 10))
        content_layout.addWidget(desc)

        info_items = [
            ("Author",    ORGANIZATION_NAME),
            ("License",   LICENSE_TYPE),
            ("Framework", DEVELOPMENT_FRAMEWORK),
            ("AI Engines", SUPPORTED_AI_ENGINES),
        ]

        for label_text, value_text in info_items:
            row = QHBoxLayout()
            row.setSpacing(8)
            
            lbl = QLabel(f"{label_text}:")
            lbl.setObjectName("about_info_label")
            lbl.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            lbl.setFixedWidth(95)
            row.addWidget(lbl)
            
            val = QLabel(value_text)
            val.setObjectName("about_info_value")
            val.setFont(QFont("Segoe UI", 10))
            row.addWidget(val)
            
            row.addStretch()
            content_layout.addLayout(row)

        content_layout.addStretch()

        copy_label = QLabel(COPYRIGHT_TEXT)
        copy_label.setObjectName("about_copyright")
        copy_label.setFont(QFont("Segoe UI", 9))
        content_layout.addWidget(copy_label, alignment=Qt.AlignmentFlag.AlignCenter)
        root.addWidget(content, 1)

        # Button Bar
        btn_bar = QWidget()
        btn_bar.setObjectName("about_btn_bar")
        btn_layout = QHBoxLayout(btn_bar)
        btn_layout.setContentsMargins(20, 10, 20, 10)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.setObjectName("about_btns")
        btns.rejected.connect(self.reject)
        
        btn_layout.addStretch()
        btn_layout.addWidget(btns)
        root.addWidget(btn_bar)
