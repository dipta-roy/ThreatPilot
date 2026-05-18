"""ThreatPilot - Standalone Vulnerability Title Generator Utility.

This is a separate PyQt-based graphical utility to automatically generate
concise titles for existing vulnerabilities using the configured ThreatPilot AI backend.
"""

from __future__ import annotations
import sys
import os
import json
import tempfile
import asyncio
from pathlib import Path
from typing import Dict, Any, List

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLineEdit,
    QLabel,
    QFileDialog,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QProgressBar,
    QMessageBox,
    QCheckBox,
    QTextEdit,
    QFrame,
)

# -----------------------------------------------------------------------------
# Setup sys.path to allow importing from the main threatpilot package
# -----------------------------------------------------------------------------
workspace_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if workspace_root not in sys.path:
    sys.path.insert(0, workspace_root)

try:
    from threatpilot.config.ai_config import AIConfig
    from threatpilot.ai.factory import create_ai_provider
    from threatpilot.core.constants import APP_NAME
except ImportError as exc:
    print(f"Error: Could not import ThreatPilot modules. Make sure to run this script from the workspace root or with sys.path correctly configured.\nDetails: {exc}")
    sys.exit(1)


# -----------------------------------------------------------------------------
# CSS Styling - Premium Dark Theme
# -----------------------------------------------------------------------------
STYLE_SHEET = """
QWidget {
    background-color: #0f172a; /* Deep Slate 900 */
    color: #f8fafc; /* Slate 50 */
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}

QFrame#card {
    background-color: #1e293b; /* Slate 800 */
    border: 1px solid #334155; /* Slate 700 */
    border-radius: 8px;
}

QLabel#title-lbl {
    color: #38bdf8; /* Sky 400 */
    font-weight: bold;
    font-size: 18px;
}

QLabel#subtitle-lbl {
    color: #94a3b8; /* Slate 400 */
    font-size: 12px;
}

QLineEdit {
    background-color: #0f172a;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 6px 10px;
    color: #f8fafc;
}

QLineEdit:focus {
    border: 1px solid #38bdf8; /* Sky 400 */
}

QPushButton {
    background-color: #1e293b;
    border: 1px solid #475569;
    border-radius: 6px;
    padding: 8px 16px;
    color: #f8fafc;
    font-weight: 600;
    min-height: 32px;
}

QPushButton:hover {
    background-color: #334155;
    border-color: #64748b;
}

QPushButton:pressed {
    background-color: #0f172a;
}

QPushButton#btn-browse {
    background-color: #334155;
    border: 1px solid #475569;
}

QPushButton#btn-generate {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2563eb, stop:1 #1d4ed8); /* Blue 600 to 700 */
    border: none;
    color: #ffffff;
}

QPushButton#btn-generate:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #3b82f6, stop:1 #2563eb);
}

QPushButton#btn-generate:disabled {
    background: #334155;
    color: #94a3b8;
}

QPushButton#btn-save {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #059669, stop:1 #047857); /* Emerald 600 to 700 */
    border: none;
    color: #ffffff;
}

QPushButton#btn-save:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #10b981, stop:1 #059669);
}

QPushButton#btn-save:disabled {
    background: #334155;
    color: #94a3b8;
}

QTableWidget {
    background-color: #1e293b;
    border: 1px solid #334155;
    gridline-color: #334155;
    border-radius: 8px;
    color: #e2e8f0;
}

QTableWidget::item {
    padding: 6px;
}

QTableWidget::item:selected {
    background-color: #2563eb;
    color: #ffffff;
}

QHeaderView::section {
    background-color: #0f172a;
    color: #94a3b8;
    padding: 6px;
    border: none;
    font-weight: bold;
    border-bottom: 1px solid #334155;
}

QScrollBar:vertical {
    border: none;
    background: #0f172a;
    width: 10px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #475569;
    min-height: 20px;
    border-radius: 5px;
}

QScrollBar::handle:vertical:hover {
    background: #64748b;
}

QProgressBar {
    border: 1px solid #334155;
    border-radius: 6px;
    text-align: center;
    background-color: #1e293b;
    color: #ffffff;
    font-weight: bold;
}

QProgressBar::chunk {
    background-color: #2563eb;
    border-radius: 5px;
}

QTextEdit {
    background-color: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    color: #cbd5e1;
    font-family: "Consolas", monospace;
    font-size: 12px;
}

QCheckBox {
    spacing: 8px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 1px solid #475569;
    border-radius: 4px;
    background-color: #0f172a;
}

QCheckBox::indicator:hover {
    border-color: #38bdf8;
}

QCheckBox::indicator:checked {
    background-color: #2563eb;
    border-color: #2563eb;
    image: url(resources/check.png); /* Fallback to standard check if no image */
}
"""


# -----------------------------------------------------------------------------
# QThread Worker for Background Title Generation
# -----------------------------------------------------------------------------
class TitleGeneratorWorker(QThread):
    progress = Signal(int, int)  # current, total
    vulnerability_processed = Signal(str, str)  # vuln_id, generated_title
    log_signal = Signal(str)
    error_signal = Signal(str)
    finished = Signal(int)  # count of successfully processed vulns

    def __init__(self, vulns_to_process: List[Dict[str, Any]], ai_config: AIConfig):
        super().__init__()
        self.vulns = vulns_to_process
        self.config = ai_config
        self._is_running = True

    def stop(self):
        self._is_running = False

    def run(self):
        # Establish async event loop for the providers
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            provider = create_ai_provider(self.config)
        except Exception as e:
            self.error_signal.emit(f"Failed to create AI Provider: {e}")
            return

        total = len(self.vulns)
        success_count = 0
        self.log_signal.emit(f"Starting title generation using '{self.config.provider_type}' ({self.config.model_name or 'Default Model'}) backend.")

        for idx, vuln in enumerate(self.vulns):
            if not self._is_running:
                self.log_signal.emit("Process cancelled by user.")
                break

            vuln_id = vuln.get("vulnerability_id", "Unknown")
            description = vuln.get("description", "").strip()

            if not description:
                self.log_signal.emit(f"Skipping ID {vuln_id[:8]} - Empty description.")
                self.progress.emit(idx + 1, total)
                continue

            self.log_signal.emit(f"Generating title for ID {vuln_id[:8]}...")
            
            prompt = (
                "You are an expert Cyber Security Architect.\n"
                "Given the following vulnerability description:\n"
                f"\"{description}\"\n\n"
                "Task: Generate a very short, highly descriptive, and professional title (maximum 5-6 words) that concisely identifies this vulnerability.\n"
                "Strict Rules:\n"
                "- Do NOT include any introductory or concluding text (e.g. do not say 'Here is the title:' or 'Title:').\n"
                "- Do NOT wrap the title in quotes.\n"
                "- Do NOT use the word 'vulnerability' in the title unless absolutely necessary.\n"
                "- Return ONLY the raw title text in English."
            )

            try:
                # Execute async call requesting plain text response to prevent JSON mode conflicts in local models
                resp_text, _ = loop.run_until_complete(provider.chat_complete(prompt, response_mime_type="text/plain"))
                
                # Cleanup the response
                raw_clean = resp_text.strip()
                
                # Strip markdown code blocks if the model returned them
                if raw_clean.startswith("```"):
                    lines = raw_clean.splitlines()
                    if len(lines) >= 2 and lines[-1].startswith("```"):
                        if lines[0].startswith("```"):
                            raw_clean = "\n".join(lines[1:-1]).strip()
                
                cleaned_title = raw_clean
                
                # If the title is wrapped in JSON, parse and extract the inner value
                if cleaned_title.startswith("{") and cleaned_title.endswith("}"):
                    try:
                        data = json.loads(cleaned_title)
                        if isinstance(data, dict):
                            for k in ["title", "vulnerability_title", "generated_title"]:
                                if k in data and isinstance(data[k], str):
                                    cleaned_title = data[k]
                                    break
                            else:
                                for val in data.values():
                                    if isinstance(val, str):
                                        cleaned_title = val
                                        break
                    except Exception:
                        pass
                
                # Final cleanup of quotes, newlines, and prefix patterns
                cleaned_title = cleaned_title.strip().strip("'\"").replace("\n", "").replace("\r", "")
                if cleaned_title.lower().startswith("title:"):
                    cleaned_title = cleaned_title[6:].strip()
                
                # Robust fallback if model still returned empty, placeholder, or JSON braces
                if cleaned_title in ("{}", "") or not cleaned_title:
                    self.log_signal.emit(f"Warning: Model returned empty or JSON placeholder for ID {vuln_id[:8]}. Attempting plain-text fallback...")
                    words = description.split()
                    cleaned_title = " ".join(words[:5]).strip(".")
                    if len(words) > 5:
                        cleaned_title += "..."
                
                if cleaned_title:
                    self.vulnerability_processed.emit(vuln_id, cleaned_title)
                    self.log_signal.emit(f"Success! Generated title: '{cleaned_title}'")
                    success_count += 1
                else:
                    self.log_signal.emit(f"Failed for ID {vuln_id[:8]} - Received empty response.")
            except Exception as e:
                self.log_signal.emit(f"Error generating title for ID {vuln_id[:8]}: {e}")

            # Pacing delay to avoid hitting free-tier API rate limits (e.g., 15 requests per minute)
            if idx < total - 1 and self._is_running:
                loop.run_until_complete(asyncio.sleep(3.0))

            self.progress.emit(idx + 1, total)

        self.finished.emit(success_count)


# -----------------------------------------------------------------------------
# Main GUI Window
# -----------------------------------------------------------------------------
class TitleGeneratorUtility(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ThreatPilot - Vulnerability Title Generator Utility")
        self.resize(900, 650)
        self.setStyleSheet(STYLE_SHEET)

        self.project_path = ""
        self.vulnerabilities_data: Dict[str, Any] = {}
        self.loaded_file_path = ""
        
        # Load global AIConfig from main app
        try:
            self.ai_config = AIConfig.load()
        except Exception as e:
            self.ai_config = None
            QMessageBox.critical(self, "Config Error", f"Failed to load global ThreatPilot AI Settings:\n{e}")

        self._setup_ui()

    def _setup_ui(self):
        central_widget = QWidget(self)
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(12)

        # 1. Header Card
        header_card = QFrame()
        header_card.setObjectName("card")
        header_layout = QVBoxLayout(header_card)
        header_layout.setContentsMargins(15, 12, 15, 12)
        
        title_lbl = QLabel("Vulnerability Title Backfill Utility")
        title_lbl.setObjectName("title-lbl")
        subtitle_lbl = QLabel("Select a project vulnerabilities.json file to batch generate short, descriptive titles for legacy entries using AI.")
        subtitle_lbl.setObjectName("subtitle-lbl")
        
        header_layout.addWidget(title_lbl)
        header_layout.addWidget(subtitle_lbl)
        main_layout.addWidget(header_card)

        # 2. File Selection Panel
        file_panel = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Select vulnerabilities.json path...")
        self.btn_browse = QPushButton("Browse...")
        self.btn_browse.setObjectName("btn-browse")
        self.btn_browse.clicked.connect(self._on_browse_file)
        
        self.btn_load = QPushButton("Load Database")
        self.btn_load.clicked.connect(self._on_load_database)
        
        file_panel.addWidget(self.file_input)
        file_panel.addWidget(self.btn_browse)
        file_panel.addWidget(self.btn_load)
        main_layout.addLayout(file_panel)

        # AI Context Summary Label
        self.ai_summary_lbl = QLabel()
        if self.ai_config:
            self.ai_summary_lbl.setText(f"Active Provider: <b>{self.ai_config.provider_type.upper()}</b> | Model: <b>{self.ai_config.model_name or 'Default'}</b> | Endpoint: <b>{self.ai_config.endpoint_url}</b>")
        else:
            self.ai_summary_lbl.setText("No active AI Config loaded. Check main application settings.")
        self.ai_summary_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        main_layout.addWidget(self.ai_summary_lbl)

        # 3. Filter Options & Table
        filter_panel = QHBoxLayout()
        self.only_missing_chk = QCheckBox("Only target missing or placeholder titles (e.g. 'New Vulnerability', empty)")
        self.only_missing_chk.setChecked(True)
        
        filter_panel.addWidget(self.only_missing_chk)
        filter_panel.addStretch()
        main_layout.addLayout(filter_panel)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["", "ID", "Current Title", "Vulnerability Description", "Status"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents) # check
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents) # ID
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)          # Title
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)          # Description
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents) # Status
        main_layout.addWidget(self.table)

        # 4. Activity Logs
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setPlaceholderText("Execution log outputs will be populated here...")
        self.log_view.setMaximumHeight(120)
        main_layout.addWidget(self.log_view)

        # 5. Progress Bar & Action Controls
        progress_panel = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        
        self.btn_generate = QPushButton("Generate Titles")
        self.btn_generate.setObjectName("btn-generate")
        self.btn_generate.clicked.connect(self._on_generate_titles)
        self.btn_generate.setEnabled(False)

        self.btn_save = QPushButton("Save Changes")
        self.btn_save.setObjectName("btn-save")
        self.btn_save.clicked.connect(self._on_save_changes)
        self.btn_save.setEnabled(False)

        progress_panel.addWidget(self.progress_bar)
        progress_panel.addWidget(self.btn_generate)
        progress_panel.addWidget(self.btn_save)
        main_layout.addLayout(progress_panel)

        self._log("Utility initialized. Ready to load database.")

    def _log(self, text: str):
        self.log_view.append(text)
        # Scroll to bottom
        self.log_view.ensureCursorVisible()

    def _on_browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open vulnerabilities.json File",
            "",
            "JSON Database (vulnerabilities.json *.json);;All Files (*)",
        )
        if file_path:
            self.file_input.setText(file_path)

    def _on_load_database(self):
        file_path = self.file_input.text().strip()
        if not file_path or not Path(file_path).exists():
            QMessageBox.critical(self, "File Error", "The specified vulnerabilities file path does not exist.")
            return

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                self.vulnerabilities_data = json.load(f)
            self.loaded_file_path = file_path
        except Exception as e:
            QMessageBox.critical(self, "Load Error", f"Failed to load or parse JSON database:\n{e}")
            return

        self._log(f"Successfully loaded database from {file_path}")
        self._populate_table()

    def _populate_table(self):
        self.table.setRowCount(0)
        
        # Safe traversal of project vulnerabilities JSON structure
        vuln_register = self.vulnerabilities_data.get("vulnerability_register", {})
        vulnerabilities = vuln_register.get("vulnerabilities", [])

        if not vulnerabilities:
            self._log("No vulnerabilities found in the selected register.")
            self.btn_generate.setEnabled(False)
            return

        self.table.setRowCount(len(vulnerabilities))
        only_missing = self.only_missing_chk.isChecked()

        for idx, vuln in enumerate(vulnerabilities):
            vuln_id = vuln.get("vulnerability_id", "N/A")
            title = vuln.get("title", "").strip()
            desc = vuln.get("description", "").strip()
            status_val = vuln.get("status", "Open")

            # Check logic for whether to select by default
            is_placeholder = not title or title.lower() in ["new vulnerability", "placeholder", "n/a", ""]
            should_check = is_placeholder if only_missing else True

            # Checkbox Item
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk_item.setCheckState(Qt.CheckState.Checked if should_check else Qt.CheckState.Unchecked)
            self.table.setItem(idx, 0, chk_item)

            # ID Item
            id_item = QTableWidgetItem(vuln_id[:8])
            id_item.setData(Qt.ItemDataRole.UserRole, vuln) # Store reference to original dict
            id_item.setFlags(id_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(idx, 1, id_item)

            # Title Item
            title_item = QTableWidgetItem(title if title else "[No Title]")
            self.table.setItem(idx, 2, title_item)

            # Description Item
            desc_item = QTableWidgetItem(desc)
            desc_item.setFlags(desc_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            desc_item.setToolTip(desc)
            self.table.setItem(idx, 3, desc_item)

            # Status Item
            status_item = QTableWidgetItem(status_val)
            status_item.setFlags(status_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(idx, 4, status_item)

        self.btn_generate.setEnabled(True)
        self.btn_save.setEnabled(False)
        self._log(f"Table populated with {len(vulnerabilities)} vulnerabilities.")

    def _on_generate_titles(self):
        if not self.ai_config:
            QMessageBox.critical(self, "AI Config Error", "No active AI Config found. Utility cannot generate titles.")
            return

        to_process = []
        for idx in range(self.table.rowCount()):
            chk_item = self.table.item(idx, 0)
            if chk_item and chk_item.checkState() == Qt.CheckState.Checked:
                id_item = self.table.item(idx, 1)
                vuln_dict = id_item.data(Qt.ItemDataRole.UserRole)
                to_process.append(vuln_dict)

        if not to_process:
            QMessageBox.warning(self, "Selection", "No vulnerabilities selected for generation.")
            return

        self.btn_generate.setEnabled(False)
        self.btn_save.setEnabled(False)
        self.btn_browse.setEnabled(False)
        self.btn_load.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(to_process))

        self.worker = TitleGeneratorWorker(to_process, self.ai_config)
        self.worker.progress.connect(self._on_worker_progress)
        self.worker.vulnerability_processed.connect(self._on_vulnerability_title_generated)
        self.worker.log_signal.connect(self._log)
        self.worker.error_signal.connect(self._on_worker_error)
        self.worker.finished.connect(self._on_worker_finished)
        self.worker.start()

    def _on_worker_progress(self, current: int, total: int):
        self.progress_bar.setValue(current)

    def _on_vulnerability_title_generated(self, vuln_id: str, generated_title: str):
        # 1. Directly update the original dictionary in self.vulnerabilities_data
        vuln_register = self.vulnerabilities_data.get("vulnerability_register", {})
        vulnerabilities = vuln_register.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            if vuln.get("vulnerability_id") == vuln_id:
                vuln["title"] = generated_title
                break

        # 2. Update the UI table item and the associated UserRole data copy
        for idx in range(self.table.rowCount()):
            id_item = self.table.item(idx, 1)
            vuln_dict = id_item.data(Qt.ItemDataRole.UserRole)
            if vuln_dict and vuln_dict.get("vulnerability_id") == vuln_id:
                # Update UI Table row
                self.table.item(idx, 2).setText(generated_title)
                self.table.item(idx, 2).setForeground(Qt.GlobalColor.green)
                
                # Sync stored UserRole dict copy
                vuln_dict["title"] = generated_title
                id_item.setData(Qt.ItemDataRole.UserRole, vuln_dict)
                break

    def _on_worker_error(self, error_msg: str):
        QMessageBox.critical(self, "AI Generation Error", error_msg)
        self._enable_controls_after_worker()

    def _on_worker_finished(self, success_count: int):
        self._log(f"Process complete. Successfully generated titles for {success_count} entries.")
        self._enable_controls_after_worker()
        self.btn_save.setEnabled(True)

    def _enable_controls_after_worker(self):
        self.btn_generate.setEnabled(True)
        self.btn_browse.setEnabled(True)
        self.btn_load.setEnabled(True)

    def _on_save_changes(self):
        if not self.loaded_file_path or not self.vulnerabilities_data:
            QMessageBox.critical(self, "Save Error", "No loaded database found to write changes back to.")
            return

        file_path = Path(self.loaded_file_path)
        
        # Atomic Write Pattern to avoid corruption
        temp_fd, temp_path = tempfile.mkstemp(dir=file_path.parent, prefix=file_path.name, suffix=".tmp")
        try:
            with os.fdopen(temp_fd, 'w', encoding='utf-8') as fh:
                json.dump(self.vulnerabilities_data, fh, indent=2, ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            
            # Atomic replacement
            os.replace(temp_path, file_path)
            self._log(f"Successfully saved changes back to file: {file_path}")
            QMessageBox.information(self, "Save Successful", "Vulnerabilities database successfully updated!")
            self.btn_save.setEnabled(False)
            
            # Reset visual colors on titles
            for idx in range(self.table.rowCount()):
                self.table.item(idx, 2).setForeground(Qt.GlobalColor.white)
                
        except Exception as e:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            QMessageBox.critical(self, "Save Error", f"Failed to save changes atomically:\n{e}")


# -----------------------------------------------------------------------------
# Main Startup Entrypoint
# -----------------------------------------------------------------------------
def main():
    app = QApplication(sys.argv)
    window = TitleGeneratorUtility()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
