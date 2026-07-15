"""ThreatPilot - Standalone Mitigation Generator Utility.

This is a separate PyQt-based graphical utility to automatically generate
mitigations for existing vulnerabilities and threats using the configured
ThreatPilot AI backend.
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
    background-color: #0f172a;
    color: #f8fafc;
    font-family: "Segoe UI", "Inter", sans-serif;
    font-size: 13px;
}

QFrame#card {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
}

QLabel#title-lbl {
    color: #10b981; /* Emerald 500 */
    font-weight: bold;
    font-size: 18px;
}

QLabel#subtitle-lbl {
    color: #94a3b8;
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
    border: 1px solid #10b981;
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
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #059669, stop:1 #047857);
    border: none;
    color: #ffffff;
}

QPushButton#btn-generate:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #10b981, stop:1 #059669);
}

QPushButton#btn-generate:disabled {
    background: #334155;
    color: #94a3b8;
}

QPushButton#btn-save {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #2563eb, stop:1 #1d4ed8);
    border: none;
    color: #ffffff;
}

QPushButton#btn-save:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #3b82f6, stop:1 #2563eb);
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
    background-color: #059669;
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
    background-color: #10b981;
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
    border-color: #10b981;
}

QCheckBox::indicator:checked {
    background-color: #059669;
    border-color: #059669;
}
"""


# -----------------------------------------------------------------------------
# QThread Worker for Background Mitigation Generation
# -----------------------------------------------------------------------------
class MitigationGeneratorWorker(QThread):
    progress = Signal(int, int)  # current, total
    item_processed = Signal(str, str, str)  # file_path, item_id, generated_mitigation
    log_signal = Signal(str)
    error_signal = Signal(str)
    finished = Signal(int)  # count of successfully processed items

    def __init__(self, items_to_process: List[Dict[str, Any]], ai_config: AIConfig):
        super().__init__()
        self.items = items_to_process
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

        total = len(self.items)
        success_count = 0
        self.log_signal.emit(f"Starting mitigation generation using '{self.config.provider_type}' ({self.config.model_name or 'Default Model'}) backend.")

        for idx, item in enumerate(self.items):
            if not self._is_running:
                self.log_signal.emit("Process cancelled by user.")
                break

            file_path = item.get("file_path")
            item_id = item.get("item_id", "Unknown")
            item_type = item.get("type", "Unknown")
            title = item.get("title", "")
            description = item.get("description", "").strip()

            if not description:
                self.log_signal.emit(f"Skipping {item_type} {item_id[:8]} - Empty description.")
                self.progress.emit(idx + 1, total)
                continue

            self.log_signal.emit(f"Generating mitigation for {item_type} {item_id[:8]}...")
            
            prompt = (
                "You are an expert Cyber Security Architect.\n"
                f"Given the following {item_type.lower()}:\n"
                f"Title: {title}\n"
                f"Description: {description}\n\n"
                "Task: Generate a concise, practical, and highly descriptive mitigation strategy (maximum 2-3 sentences) to address this issue.\n"
                "Strict Rules:\n"
                "- Do NOT include any introductory or concluding text (e.g. do not say 'Here is the mitigation:' or 'Mitigation:').\n"
                "- Do NOT wrap the output in quotes.\n"
                "- Provide actionable technical guidance rather than generic advice.\n"
                "- Return ONLY the raw mitigation text."
            )

            try:
                # Execute async call requesting plain text response
                resp_text, _ = loop.run_until_complete(provider.chat_complete(prompt, response_mime_type="text/plain"))
                
                # Cleanup the response
                raw_clean = resp_text.strip()
                
                # Strip markdown code blocks if the model returned them
                if raw_clean.startswith("```"):
                    lines = raw_clean.splitlines()
                    if len(lines) >= 2 and lines[-1].startswith("```"):
                        if lines[0].startswith("```"):
                            raw_clean = "\n".join(lines[1:-1]).strip()
                
                cleaned_mitigation = raw_clean
                
                # If the output is wrapped in JSON, parse and extract the inner value
                if cleaned_mitigation.startswith("{") and cleaned_mitigation.endswith("}"):
                    try:
                        data = json.loads(cleaned_mitigation)
                        if isinstance(data, dict):
                            for k in ["mitigation", "strategy", "text", "generated_mitigation"]:
                                if k in data and isinstance(data[k], str):
                                    cleaned_mitigation = data[k]
                                    break
                            else:
                                for val in data.values():
                                    if isinstance(val, str):
                                        cleaned_mitigation = val
                                        break
                    except Exception:
                        pass
                
                # Final cleanup
                cleaned_mitigation = cleaned_mitigation.strip().strip("'\"")
                if cleaned_mitigation.lower().startswith("mitigation:"):
                    cleaned_mitigation = cleaned_mitigation[11:].strip()
                
                if cleaned_mitigation:
                    self.item_processed.emit(file_path, item_id, cleaned_mitigation)
                    self.log_signal.emit(f"Success! Generated mitigation for {item_id[:8]}.")
                    success_count += 1
                else:
                    self.log_signal.emit(f"Failed for {item_id[:8]} - Received empty response.")
            except Exception as e:
                self.log_signal.emit(f"Error generating mitigation for {item_id[:8]}: {e}")

            # Pacing delay to avoid hitting free-tier API rate limits (e.g., 15 requests per minute)
            if idx < total - 1 and self._is_running:
                loop.run_until_complete(asyncio.sleep(3.0))

            self.progress.emit(idx + 1, total)

        self.finished.emit(success_count)


# -----------------------------------------------------------------------------
# Main GUI Window
# -----------------------------------------------------------------------------
class MitigationGeneratorUtility(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ThreatPilot - Mitigation Generator Utility")
        self.resize(1000, 700)
        self.setStyleSheet(STYLE_SHEET)

        self.project_path = ""
        # Store loaded JSON data: file_path -> dict
        self.files_data: Dict[str, Dict[str, Any]] = {}
        
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
        
        title_lbl = QLabel("Vulnerability & Threat Mitigation Generator")
        title_lbl.setObjectName("title-lbl")
        subtitle_lbl = QLabel("Select a project directory to batch generate actionable mitigations for missing entries using AI.")
        subtitle_lbl.setObjectName("subtitle-lbl")
        
        header_layout.addWidget(title_lbl)
        header_layout.addWidget(subtitle_lbl)
        main_layout.addWidget(header_card)

        # 2. Directory Selection Panel
        dir_panel = QHBoxLayout()
        self.dir_input = QLineEdit()
        self.dir_input.setPlaceholderText("Select project root directory...")
        self.btn_browse = QPushButton("Browse Directory...")
        self.btn_browse.setObjectName("btn-browse")
        self.btn_browse.clicked.connect(self._on_browse_directory)
        
        self.btn_load = QPushButton("Scan Directory")
        self.btn_load.clicked.connect(self._on_scan_directory)
        
        dir_panel.addWidget(self.dir_input)
        dir_panel.addWidget(self.btn_browse)
        dir_panel.addWidget(self.btn_load)
        main_layout.addLayout(dir_panel)

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
        self.only_missing_chk = QCheckBox("Only target missing or empty mitigations")
        self.only_missing_chk.setChecked(True)
        
        filter_panel.addWidget(self.only_missing_chk)
        filter_panel.addStretch()
        main_layout.addLayout(filter_panel)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["", "Type", "ID", "Title", "File", "Mitigation Status"])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents) # check
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents) # Type
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents) # ID
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)          # Title
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)          # File
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)          # Status
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
        
        self.btn_generate = QPushButton("Generate Mitigations")
        self.btn_generate.setObjectName("btn-generate")
        self.btn_generate.clicked.connect(self._on_generate_mitigations)
        self.btn_generate.setEnabled(False)

        self.btn_save = QPushButton("Save Changes")
        self.btn_save.setObjectName("btn-save")
        self.btn_save.clicked.connect(self._on_save_changes)
        self.btn_save.setEnabled(False)

        progress_panel.addWidget(self.progress_bar)
        progress_panel.addWidget(self.btn_generate)
        progress_panel.addWidget(self.btn_save)
        main_layout.addLayout(progress_panel)

        self._log("Mitigation Utility initialized. Ready to scan project directory.")

    def _log(self, text: str):
        self.log_view.append(text)
        # Scroll to bottom
        self.log_view.ensureCursorVisible()

    def _on_browse_directory(self):
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Project Directory",
            ""
        )
        if dir_path:
            self.dir_input.setText(dir_path)

    def _on_scan_directory(self):
        dir_path = self.dir_input.text().strip()
        if not dir_path or not Path(dir_path).exists() or not Path(dir_path).is_dir():
            QMessageBox.critical(self, "Directory Error", "The specified project directory path is invalid.")
            return

        self.files_data.clear()
        
        # Scan for vulnerabilities.json and threats.json
        target_files = []
        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.lower() in ["vulnerabilities.json", "threats.json"]:
                    target_files.append(os.path.join(root, file))

        if not target_files:
            QMessageBox.information(self, "Scan Result", "No vulnerabilities.json or threats.json found in the specified directory.")
            return

        for file_path in target_files:
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    self.files_data[file_path] = json.load(f)
            except Exception as e:
                self._log(f"Error loading {file_path}: {e}")

        self._log(f"Successfully loaded {len(self.files_data)} files.")
        self._populate_table()

    def _populate_table(self):
        self.table.setRowCount(0)
        items_to_display = []

        for file_path, data in self.files_data.items():
            filename = os.path.basename(file_path)
            
            if filename == "vulnerabilities.json":
                vuln_register = data.get("vulnerability_register", {})
                vulnerabilities = vuln_register.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    items_to_display.append({
                        "file_path": file_path,
                        "type": "Vulnerability",
                        "item_id": vuln.get("vulnerability_id", "N/A"),
                        "title": vuln.get("title", ""),
                        "description": vuln.get("description", ""),
                        "mitigation": vuln.get("mitigation", ""),
                        "ref": vuln
                    })
            elif filename == "threats.json":
                threat_register = data.get("threat_register", {})
                threats = threat_register.get("threats", [])
                for threat in threats:
                    items_to_display.append({
                        "file_path": file_path,
                        "type": "Threat",
                        "item_id": threat.get("threat_id", "N/A"),
                        "title": threat.get("title", ""),
                        "description": threat.get("description", ""),
                        "mitigation": threat.get("mitigation", ""),
                        "ref": threat
                    })

        if not items_to_display:
            self._log("No entries found in the scanned files.")
            self.btn_generate.setEnabled(False)
            return

        only_missing = self.only_missing_chk.isChecked()
        row_idx = 0
        
        self.table.setRowCount(len(items_to_display))
        
        for item in items_to_display:
            mitigation = item["mitigation"].strip()
            is_missing = not mitigation or mitigation.lower() in ["n/a", "tbd", "placeholder"]
            
            # Check logic
            should_check = is_missing if only_missing else True

            # Checkbox Item
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk_item.setCheckState(Qt.CheckState.Checked if should_check else Qt.CheckState.Unchecked)
            self.table.setItem(row_idx, 0, chk_item)

            # Type Item
            type_item = QTableWidgetItem(item["type"])
            type_item.setFlags(type_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_idx, 1, type_item)

            # ID Item
            id_str = item["item_id"][:8] if item["type"] == "Vulnerability" else item["item_id"]
            id_item = QTableWidgetItem(id_str)
            
            # Store item metadata for processing
            id_item.setData(Qt.ItemDataRole.UserRole, {
                "file_path": item["file_path"],
                "type": item["type"],
                "item_id": item["item_id"],
                "title": item["title"],
                "description": item["description"]
            })
            id_item.setFlags(id_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_idx, 2, id_item)

            # Title Item
            title_item = QTableWidgetItem(item["title"] if item["title"] else "[No Title]")
            title_item.setFlags(title_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_idx, 3, title_item)

            # File Item
            file_item = QTableWidgetItem(os.path.basename(item["file_path"]))
            file_item.setFlags(file_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_idx, 4, file_item)

            # Status Item
            status_text = mitigation if mitigation else "[Missing Mitigation]"
            status_item = QTableWidgetItem(status_text)
            status_item.setFlags(status_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_idx, 5, status_item)
            
            row_idx += 1

        self.table.setRowCount(row_idx)
        self.btn_generate.setEnabled(True)
        self.btn_save.setEnabled(False)
        self._log(f"Table populated with {row_idx} entries.")

    def _on_generate_mitigations(self):
        if not self.ai_config:
            QMessageBox.critical(self, "AI Config Error", "No active AI Config found. Utility cannot generate mitigations.")
            return

        to_process = []
        for idx in range(self.table.rowCount()):
            chk_item = self.table.item(idx, 0)
            if chk_item and chk_item.checkState() == Qt.CheckState.Checked:
                id_item = self.table.item(idx, 2)
                item_data = id_item.data(Qt.ItemDataRole.UserRole)
                to_process.append(item_data)

        if not to_process:
            QMessageBox.warning(self, "Selection", "No items selected for generation.")
            return

        self.btn_generate.setEnabled(False)
        self.btn_save.setEnabled(False)
        self.btn_browse.setEnabled(False)
        self.btn_load.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setMaximum(len(to_process))

        self.worker = MitigationGeneratorWorker(to_process, self.ai_config)
        self.worker.progress.connect(self._on_worker_progress)
        self.worker.item_processed.connect(self._on_item_mitigation_generated)
        self.worker.log_signal.connect(self._log)
        self.worker.error_signal.connect(self._on_worker_error)
        self.worker.finished.connect(self._on_worker_finished)
        self.worker.start()

    def _on_worker_progress(self, current: int, total: int):
        self.progress_bar.setValue(current)

    def _on_item_mitigation_generated(self, file_path: str, item_id: str, generated_mitigation: str):
        # 1. Update the original dictionary in self.files_data
        data = self.files_data.get(file_path)
        if data:
            filename = os.path.basename(file_path)
            if filename == "vulnerabilities.json":
                items = data.get("vulnerability_register", {}).get("vulnerabilities", [])
                for item in items:
                    if item.get("vulnerability_id") == item_id:
                        item["mitigation"] = generated_mitigation
                        break
            elif filename == "threats.json":
                items = data.get("threat_register", {}).get("threats", [])
                for item in items:
                    if item.get("threat_id") == item_id:
                        item["mitigation"] = generated_mitigation
                        break

        # 2. Update the UI table item
        for idx in range(self.table.rowCount()):
            id_item = self.table.item(idx, 2)
            item_data = id_item.data(Qt.ItemDataRole.UserRole)
            
            # Account for truncated IDs in vulnerability view
            actual_id = item_id[:8] if item_data["type"] == "Vulnerability" else item_id
            
            if item_data and item_data.get("file_path") == file_path and (item_data.get("item_id") == item_id or id_item.text() == actual_id):
                # Update UI Table row
                status_item = self.table.item(idx, 5)
                status_item.setText(generated_mitigation)
                status_item.setForeground(Qt.GlobalColor.green)
                break

    def _on_worker_error(self, error_msg: str):
        QMessageBox.critical(self, "AI Generation Error", error_msg)
        self._enable_controls_after_worker()

    def _on_worker_finished(self, success_count: int):
        self._log(f"Process complete. Successfully generated mitigations for {success_count} entries.")
        self._enable_controls_after_worker()
        if success_count > 0:
            self.btn_save.setEnabled(True)

    def _enable_controls_after_worker(self):
        self.btn_generate.setEnabled(True)
        self.btn_browse.setEnabled(True)
        self.btn_load.setEnabled(True)

    def _on_save_changes(self):
        if not self.files_data:
            QMessageBox.critical(self, "Save Error", "No loaded database found to write changes back to.")
            return

        success_count = 0
        error_messages = []

        for file_path, data in self.files_data.items():
            path_obj = Path(file_path)
            
            # Atomic Write Pattern
            temp_fd, temp_path = tempfile.mkstemp(dir=path_obj.parent, prefix=path_obj.name, suffix=".tmp")
            try:
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as fh:
                    json.dump(data, fh, indent=2, ensure_ascii=False)
                    fh.flush()
                    os.fsync(fh.fileno())
                
                # Atomic replacement
                os.replace(temp_path, file_path)
                success_count += 1
                self._log(f"Successfully saved: {path_obj.name}")
                
            except Exception as e:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                error_messages.append(f"Failed to save {path_obj.name}: {e}")

        if error_messages:
            QMessageBox.critical(self, "Save Errors", "\n".join(error_messages))
        elif success_count > 0:
            QMessageBox.information(self, "Save Successful", f"Successfully updated {success_count} files!")
            self.btn_save.setEnabled(False)
            
            # Reset visual colors on the table
            for idx in range(self.table.rowCount()):
                self.table.item(idx, 5).setForeground(Qt.GlobalColor.white)


# -----------------------------------------------------------------------------
# Main Startup Entrypoint
# -----------------------------------------------------------------------------
def main():
    app = QApplication(sys.argv)
    window = MitigationGeneratorUtility()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
