"""AI settings dialog for ThreatPilot.

Provides a ``QDialog`` for configuring the AI provider:
- Backend selection (Ollama/External API)
- Endpoint URL and model name
- Inference parameters (temperature, max tokens, timeout)
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFormLayout,
    QLineEdit,
    QPushButton,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from threatpilot.config.ai_config import AIConfig
from threatpilot.ai.factory import create_ai_provider
import httpx


class AISettingsDialog(QDialog):
    """Configuration dialog for AI provider settings.

    Args:
        config: The current ``AIConfig`` to modify.
        parent: The parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("AI Settings")
        self.setFixedWidth(400)
        
        # We work on a copy so we can cancel without mutation
        self._config = AIConfig.load()

        self._setup_ui()
        self._on_provider_changed(self._provider_type.currentText())
        
        # Restore the user's custom model name that may have been temporarily 
        # overwritten by the default provider switching logic during setup.
        if self._config.model_name:
            self._model_name.setCurrentText(self._config.model_name)

    def _setup_ui(self) -> None:
        """Initialise form fields and button box."""
        layout = QVBoxLayout(self)

        self._form = QFormLayout()

        # Provider Type
        self._provider_type = QComboBox()
        self._provider_type.addItems(["ollama", "gemini"])
        self._provider_type.setCurrentText(self._config.provider_type)
        self._provider_type.currentTextChanged.connect(self._on_provider_changed)
        self._form.addRow("Provider Type:", self._provider_type)

        # Endpoint URL
        self._endpoint_url = QLineEdit(self._config.endpoint_url)
        self._form.addRow("Endpoint URL:", self._endpoint_url)

        # Model Name
        self._model_name = QComboBox()
        self._model_name.setEditable(True)
        self._form.addRow("Model Name:", self._model_name)

        self._gemini_key = QLineEdit(self._config.gemini_api_key)
        self._gemini_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._form.addRow("Gemini API Key:", self._gemini_key)

        # Temperature
        self._temperature = QDoubleSpinBox()
        self._temperature.setRange(0.0, 2.0)
        self._temperature.setSingleStep(0.1)
        self._temperature.setValue(self._config.temperature)
        self._form.addRow("Temperature:", self._temperature)

        # Max Tokens
        self._max_tokens = QSpinBox()
        self._max_tokens.setRange(1, 128000)
        self._max_tokens.setValue(self._config.max_tokens)
        self._form.addRow("Max Tokens:", self._max_tokens)

        # Timeout
        self._timeout = QSpinBox()
        self._timeout.setRange(1, 3600)
        self._timeout.setValue(self._config.timeout)
        self._form.addRow("Timeout (sec):", self._timeout)

        layout.addLayout(self._form)

        # Test Connection Button
        self._btn_test = QPushButton("Test Connection")
        self._btn_test.clicked.connect(self._on_test_connection)
        layout.addWidget(self._btn_test)

        # Buttons
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_test_connection(self) -> None:
        """Instantiates the selected provider and checks for basic endpoint reachability."""
        config = self.get_config()
        try:
            provider = create_ai_provider(config)
            if provider.is_available():
                QMessageBox.information(self, "Connection Test", f"Successfully connected to {config.provider_type} endpoint!")
            else:
                QMessageBox.warning(self, "Connection Test", f"Failed to connect to {config.provider_type}. Please check your network and settings.")
        except Exception as exc:
            QMessageBox.critical(self, "Connection Test Error", f"An error occurred while testing the connection:\n{exc}")

    def _on_provider_changed(self, provider_type: str) -> None:
        """Show or hide fields and update model defaults based on the selected backend."""
        # 1. Row Visibility
        show_endpoint = provider_type in ("ollama", "gemini")
        self._set_row_visible(self._endpoint_url, show_endpoint)
        
        # 2. Sensible Model Defaults
        model_defaults = {
            "gemini": "gemini-3.1-flash-lite-preview",
            "ollama": "qwen2.5vl:3b"
        }
        
        endpoint_defaults = {
            "gemini": "https://generativelanguage.googleapis.com",
            "ollama": "http://localhost:11434"
        }
        
        if provider_type in endpoint_defaults:
            self._endpoint_url.setText(endpoint_defaults[provider_type])

        self._model_name.clear()

        if provider_type == "ollama":
            url = endpoint_defaults["ollama"]
            if hasattr(self, "_endpoint_url") and self._endpoint_url.text():
                url = self._endpoint_url.text()
            
            try:
                with httpx.Client(timeout=1.0) as client:
                    resp = client.get(f"{url}/api/tags")
                    resp.raise_for_status()
                    models = [m.get("name") for m in resp.json().get("models", [])]
                    if models:
                        self._model_name.addItems(models)
                        self._model_name.setCurrentText(models[0])
                    else:
                        self._model_name.addItem("No Models Detected")
                        self._model_name.setCurrentText("No Models Detected")
            except Exception:
                self._model_name.addItem("No Models Detected")
                self._model_name.setCurrentText("No Models Detected")
        
        elif provider_type == "gemini":
            self._model_name.addItems([
                "gemini-3.1-flash-lite-preview",
                "gemini-2.0-flash", 
                "gemini-1.5-flash"
            ])
            self._model_name.setCurrentText(model_defaults.get("gemini", "gemini-3.1-flash-lite-preview"))

    def _set_row_visible(self, widget: QWidget, visible: bool) -> None:
        """Helper to hide/show a field and its associated layout label."""
        label = self._form.labelForField(widget)
        if label:
            label.setVisible(visible)
        widget.setVisible(visible)

    def get_config(self) -> AIConfig:
        """Return the updated ``AIConfig`` object from form data."""
        self._config.provider_type = self._provider_type.currentText()
        self._config.endpoint_url = self._endpoint_url.text()
        self._config.model_name = self._model_name.currentText()
        self._config.gemini_api_key = self._gemini_key.text()
        self._config.temperature = self._temperature.value()
        self._config.max_tokens = self._max_tokens.value()
        self._config.timeout = self._timeout.value()
        return self._config