"""Dialog and utility widget modules for ThreatPilot.
"""

from __future__ import annotations
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTextEdit,
    QWidget,
    QLabel
)


class ReasoningDisplayDialog(QDialog):
    """A dedicated dialog for displaying long-form technical reasoning.
    
    Provides a wider, scrollable view with markdown support, making
    technical reports much easier to read than a standard message box.
    """
    def __init__(self, title: str, reasoning: str, parent: QWidget | None = None, show_regenerate: bool = False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(800, 650)
        self.setMinimumWidth(700)
        
        layout = QVBoxLayout(self)
        
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setMarkdown(reasoning)
        # Ensure high readability
        self.text_area.setStyleSheet("QTextEdit { padding: 15px; background: palette(base); }")
        layout.addWidget(self.text_area)
        
        self.buttons = QHBoxLayout()
        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self.accept)
        
        self.regenerate_clicked = False
        if show_regenerate:
            self.btn_regen = QPushButton("Regenerate Analysis")
            self.btn_regen.setProperty("class", "btn-primary")
            self.btn_regen.clicked.connect(self._on_regen)
            self.buttons.addWidget(self.btn_regen)
            
        self.buttons.addStretch()
        self.buttons.addWidget(self.btn_close)
        layout.addLayout(self.buttons)

    def _on_regen(self):
        self.regenerate_clicked = True
        self.accept()


class PlaceholderPanel(QWidget):
    """A temporary placeholder widget used for dock panels.

    Each panel displays a centred label indicating its purpose.
    """

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        label = QLabel(title)
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(11)
        font.setBold(True)
        label.setFont(font)
        label.setObjectName("placeholder_label")
        layout.addWidget(label)
