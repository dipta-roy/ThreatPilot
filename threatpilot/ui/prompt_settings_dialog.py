"""Prompt configuration dialog for ThreatPilot.

Provides a ``QDialog`` for customising prompt generation parameters:
- Risk preference levels
- Security posture and compliance priorities
- Industry context
- Custom instruction free-text area
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from threatpilot.config.prompt_config import PromptConfig


class PromptSettingsDialog(QDialog):
    """Configuration dialog for prompt customisation settings.

    Args:
        config: The current ``PromptConfig`` to modify.
        parent: The parent widget.
    """

    def __init__(self, config: PromptConfig, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Prompt Configuration")
        self.setFixedWidth(500)
        self.setMinimumHeight(450)
        
        # We work on a copy to allow cancellation
        self._config = config.model_copy()

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Initialise structured fields and free-text area."""
        layout = QVBoxLayout(self)

        form = QFormLayout()

        # Risk Preference
        self._risk_preference = QComboBox()
        self._risk_preference.addItems(["low", "medium", "high"])
        self._risk_preference.setCurrentText(self._config.risk_preference)
        form.addRow("Risk Preference:", self._risk_preference)

        # Security Posture
        self._security_posture = QLineEdit(self._config.security_posture)
        self._security_posture.setPlaceholderText("e.g. Zero Trust Architecture, Defense-in-depth")
        form.addRow("Security Posture:", self._security_posture)

        # Compliance Priority
        self._compliance_priority = QLineEdit(self._config.compliance_priority)
        self._compliance_priority.setPlaceholderText("e.g. HIPAA, PCI-DSS v4.0, SOC2 Type II")
        form.addRow("Compliance Priority:", self._compliance_priority)

        # Industry Context
        self._industry_context = QLineEdit(self._config.industry_context)
        self._industry_context.setPlaceholderText("e.g. FinTech / Banking, Healthcare Provider")
        form.addRow("Industry Context:", self._industry_context)

        layout.addLayout(form)

        # Custom Prompt (Free-text)
        layout.addWidget(QWidget())  # spacer
        layout.addSpacing(10)
        from PySide6.QtWidgets import QLabel
        layout.addWidget(QLabel("Additional Global Instructions (Free-text):"))
        
        self._custom_prompt = QTextEdit(self._config.custom_prompt)
        self._custom_prompt.setPlaceholderText(
            "Enter any extra rules or context for the AI threat analysis..."
        )
        layout.addWidget(self._custom_prompt)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def get_config(self) -> PromptConfig:
        """Return the updated ``PromptConfig`` from form data."""
        self._config.risk_preference = self._risk_preference.currentText()
        self._config.security_posture = self._security_posture.text()
        self._config.compliance_priority = self._compliance_priority.text()
        self._config.industry_context = self._industry_context.text()
        self._config.custom_prompt = self._custom_prompt.toPlainText()
        return self._config
