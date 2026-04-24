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
from PySide6.QtCore import QObject, QThread, Signal
from threatpilot.config.ai_config import AIConfig
from threatpilot.ai.factory import create_ai_provider
from threatpilot.utils.logger import sanitize_text
import httpx
from urllib.parse import urlparse

class _OllamaFetchWorker(QObject):
    """Fetches the list of locally available Ollama models on a background thread.

    Signals:
        finished(list[str]): Emitted with the model names when the request
            completes (may be an empty list on failure).
    """

    finished: Signal = Signal(list)

    def __init__(self, url: str) -> None:
        super().__init__()
        self._url = url

    def run(self) -> None: 
        models: list[str] = []
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{self._url}/api/tags")
                resp.raise_for_status()
                models = [m.get("name", "") for m in resp.json().get("models", []) if m.get("name")]
        except Exception:
            pass
        self.finished.emit(models)


class AISettingsDialog(QDialog):
    """Configuration dialog for AI provider settings.

    Args:
        config: The current ``AIConfig`` to modify.
        parent: The parent widget.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("AI Settings")
        self.setFixedWidth(550)

        self._fetch_thread: QThread | None = None
        self._fetch_worker: _OllamaFetchWorker | None = None

        self._config = AIConfig.load()

        self._setup_ui()
        self._on_provider_changed(self._provider_type.currentText())

        if self._config.model_name:
            self._model_name.setCurrentText(self._config.model_name)

    def _setup_ui(self) -> None:
        """Initialise form fields and button box."""
        layout = QVBoxLayout(self)

        self._form = QFormLayout()

        self._provider_type = QComboBox()
        self._provider_type.addItems(["ollama", "gemini"])
        self._provider_type.setCurrentText(self._config.provider_type)
        self._provider_type.currentTextChanged.connect(self._on_provider_changed)
        self._form.addRow("Provider Type:", self._provider_type)

        self._endpoint_url = QLineEdit(self._config.endpoint_url)
        self._form.addRow("Endpoint URL:", self._endpoint_url)
        self._model_name = QComboBox()
        self._model_name.setEditable(True)
        self._form.addRow("Model Name:", self._model_name)
        self._gemini_key = QLineEdit(self._config.gemini_api_key.get_secret_value())
        self._gemini_key.setEchoMode(QLineEdit.EchoMode.Password)
        self._form.addRow("Gemini API Key:", self._gemini_key)
        self._temperature = QDoubleSpinBox()
        self._temperature.setRange(0.0, 2.0)
        self._temperature.setSingleStep(0.1)
        self._temperature.setValue(self._config.temperature)
        self._form.addRow("Temperature:", self._temperature)
        self._max_tokens = QSpinBox()
        self._max_tokens.setRange(1, 128000)
        self._max_tokens.setValue(self._config.max_tokens)
        self._form.addRow("Max Tokens:", self._max_tokens)
        self._timeout = QSpinBox()
        self._timeout.setRange(1, 86400)
        self._timeout.setValue(self._config.timeout)
        self._form.addRow("Timeout (sec):", self._timeout)
        from PySide6.QtWidgets import QFrame, QLabel
        line_sec = QFrame()
        line_sec.setFrameShape(QFrame.Shape.HLine)
        line_sec.setFrameShadow(QFrame.Shadow.Sunken)
        self._form.addRow(line_sec)
        self._privacy_warning = QLabel(
            "⚠️ Data Privacy Warning: When using 'gemini', your architectural data (Diagrams and DFD) "
            "will be sent to Google Cloud for analysis. Ensure this complies with your security policy."
        )
        self._privacy_warning.setWordWrap(True)
        self._privacy_warning.setStyleSheet("color: #d73a49; font-style: italic; font-size: 10px; margin: 4px;")
        self._privacy_warning.setVisible(False)
        self._form.addRow(self._privacy_warning)
        from PySide6.QtWidgets import QFrame, QLabel
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setFrameShadow(QFrame.Shadow.Sunken)
        self._form.addRow(line)

        lbl_general = QLabel("General Application Settings")
        lbl_general.setStyleSheet("font-weight: bold; color: #58a6ff; margin-top: 10px;")
        self._form.addRow(lbl_general)
        self._autosave = QSpinBox()
        self._autosave.setRange(1, 60)
        self._autosave.setSuffix(" min")
        self._autosave.setValue(self._config.autosave_interval)
        self._form.addRow("Auto-save Interval:", self._autosave)
        layout.addLayout(self._form)
        self._btn_test = QPushButton("Test Connection")
        self._btn_test.clicked.connect(self._on_test_connection)
        layout.addWidget(self._btn_test)
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
        show_endpoint = provider_type in ("ollama", "gemini")
        self._set_row_visible(self._endpoint_url, show_endpoint)
        self._set_row_visible(self._gemini_key, provider_type == "gemini")
        self._privacy_warning.setVisible(provider_type == "gemini")

        endpoint_defaults = {
            "gemini": "https://generativelanguage.googleapis.com",
            "ollama": "http://localhost:11434",
        }

        if provider_type in endpoint_defaults:
            self._endpoint_url.setText(endpoint_defaults[provider_type])

        self._model_name.clear()

        if provider_type == "ollama":
            self._model_name.addItem("Fetching models…")
            self._model_name.setEnabled(False)

            url = self._endpoint_url.text().strip() or endpoint_defaults["ollama"]
            self._start_ollama_fetch(url)

        elif provider_type == "gemini":
            self._model_name.setEnabled(True)
            self._model_name.addItems([
                "gemini-3.1-flash-lite-preview",
                "gemini-2.0-flash",
                "gemini-1.5-flash",
            ])
            self._model_name.setCurrentText("gemini-3.1-flash-lite-preview")

    def _start_ollama_fetch(self, url: str) -> None:
        """Spin up a background thread to retrieve available Ollama models."""
        if self._fetch_thread and self._fetch_thread.isRunning():
            self._fetch_thread.quit()
            self._fetch_thread.wait(500)

        self._fetch_worker = _OllamaFetchWorker(url)
        self._fetch_thread = QThread(self)

        self._fetch_worker.moveToThread(self._fetch_thread)
        self._fetch_thread.started.connect(self._fetch_worker.run)
        self._fetch_worker.finished.connect(self._on_ollama_models_ready)
        self._fetch_worker.finished.connect(self._fetch_thread.quit)

        self._fetch_thread.start()

    def _on_ollama_models_ready(self, models: list) -> None:
        """Called on the UI thread once the background fetch finishes."""
        if self._provider_type.currentText() != "ollama":
            return

        self._model_name.clear()
        self._model_name.setEnabled(True)

        if models:
            self._model_name.addItems(models)
            current = self._config.model_name
            if current in models:
                self._model_name.setCurrentText(current)
            else:
                self._model_name.setCurrentIndex(0)
        else:
            self._model_name.addItem("No Connection")

    def _set_row_visible(self, widget: QWidget, visible: bool) -> None:
        """Helper to hide/show a field and its associated layout label."""
        label = self._form.labelForField(widget)
        if label:
            label.setVisible(visible)
        widget.setVisible(visible)

    def get_config(self) -> AIConfig:
        """Return the updated ``AIConfig`` object from form data."""
        url_raw = self._endpoint_url.text().strip()
        try:
             parsed = urlparse(url_raw)
             host = str(parsed.hostname).lower() if parsed.hostname else url_raw.lower()

             is_restricted = any(kw in host for kw in ["169.254", "metadata.google", "metadata.internal", "instance-data"])

             if self._provider_type.currentText() != "ollama" or "localhost" not in host:
                  if host.startswith("127.") or host.startswith("10.") or host.startswith("192.168.") or host.startswith("172."):
                       is_restricted = True

             if is_restricted:
                  QMessageBox.warning(self, "Security Warning", "Restricted or internal endpoint detected. Please use a public AI provider URL.")
                  return self._config
        except Exception:
             pass

        self._config.provider_type = self._provider_type.currentText()
        self._config.endpoint_url = self._endpoint_url.text()
        self._config.model_name = self._model_name.currentText()
        self._config.api_key = self._gemini_key.text()
        self._config.temperature = self._temperature.value()
        self._config.max_tokens = self._max_tokens.value()
        self._config.timeout = self._timeout.value()
        self._config.autosave_interval = self._autosave.value()
        return self._config