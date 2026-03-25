"""Quick Start Wizard for new users of ThreatPilot."""

from __future__ import annotations
from pathlib import Path
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap, QFont
from PySide6.QtWidgets import (
    QWizard,
    QWizardPage,
    QVBoxLayout,
    QLabel,
    QApplication,
)

class QuickStartWizard(QWizard):
    """Guide the user through their first session with ThreatPilot."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ThreatPilot Quick Start")
        self.setWizardStyle(QWizard.WizardStyle.ClassicStyle)
        
        # Nuclear option: Force dark palette and stylesheet regardless of parent state
        from PySide6.QtGui import QPalette, QColor
        palette = self.palette()
        palette.setColor(QPalette.ColorRole.Window, QColor("#0d1117"))
        palette.setColor(QPalette.ColorRole.WindowText, QColor("#ffffff"))
        palette.setColor(QPalette.ColorRole.Base, QColor("#0d1117"))
        palette.setColor(QPalette.ColorRole.Text, QColor("#ffffff"))
        palette.setColor(QPalette.ColorRole.Button, QColor("#21262d"))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor("#ffffff"))
        self.setPalette(palette)
        
        self.setStyleSheet("""
            QWizard, QWizardPage, QWidget { 
                background-color: #0d1117; 
                color: #ffffff; 
            }
            QLabel { 
                background-color: transparent; 
                color: #ffffff; 
                font-size: 13px;
            }
            QPushButton { 
                background-color: #21262d; 
                color: #ffffff; 
                border: 1px solid #30363d; 
                padding: 6px 20px;
                border-radius: 4px;
            }
        """)

        # Re-Add Pages (Ensuring they are populated)
        self.addPage(WelcomePage(self))
        self.addPage(ProjectPage(self))
        self.addPage(AIAnalysisPage(self))
        self.addPage(FinalPage(self))
        
        # Style individual pages (final visibility guarantee)
        for pid in self.pageIds():
            page = self.page(pid)
            page.setStyleSheet("background-color: #0d1117; color: #ffffff;")

        self.resize(600, 450)

class WelcomePage(QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Welcome to ThreatPilot")
        layout = QVBoxLayout(self)
        
        desc = QLabel(
            "ThreatPilot is a modern, AI-augmented security analysis suite designed to simplify "
            "architectural reviews and threat modeling."
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
        
        msg = QLabel("\nThis wizard will guide you through the initial steps.")
        layout.addWidget(msg)

class ProjectPage(QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("1. Create a Project")
        layout = QVBoxLayout(self)
        
        img_label = QLabel()
        # project_root = Path(__file__).parent.parent.parent
        # image_path = project_root / "threatpilot" / "resources" / "app-icon.png"
        # image = QPixmap(str(image_path)).scaledToHeight(64, Qt.TransformationMode.SmoothTransformation)
        # img_label.setPixmap(image)
        # layout.addWidget(img_label, alignment=Qt.AlignmentFlag.AlignCenter)
        
        desc = QLabel(
            "Every assessment starts with a **Project**. Projects store architectural diagrams, "
            "detected entities, and the resulting Threat Register.\n\n"
            "Go to **File > New Project** to get started."
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)

class AIAnalysisPage(QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("2. AI Analysis")
        layout = QVBoxLayout(self)
        
        desc = QLabel(
            "ThreatPilot uses powerful AI providers (like Gemini, Claude, or local Ollama) "
            "to automatically identify security risks based on your architectural design.\n\n"
            "Make sure to configure your **AI Settings** under the **Intelligence** menu."
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)

class FinalPage(QWizardPage):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setTitle("Happy Hunting")
        layout = QVBoxLayout(self)
        
        desc = QLabel(
            "You're all set! If you have any questions, check the documentation "
            "or reach out to the development team.\n\n"
            "Ready to pilot your first threat model?"
        )
        desc.setWordWrap(True)
        layout.addWidget(desc)
