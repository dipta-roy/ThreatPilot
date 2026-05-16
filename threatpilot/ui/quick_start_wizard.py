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

    def __init__(self, parent=None, is_dark: bool = True):
        super().__init__(parent)
        self.setWindowTitle("ThreatPilot Quick Start")
        self.setWizardStyle(QWizard.WizardStyle.ClassicStyle)


        self.addPage(WelcomePage(self))
        self.addPage(ProjectPage(self))
        self.addPage(AIAnalysisPage(self))
        self.addPage(FinalPage(self))

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
            "ThreatPilot uses powerful AI providers (like Gemini or local Ollama) "
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
