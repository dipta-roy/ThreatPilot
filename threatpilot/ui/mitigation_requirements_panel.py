"""Mitigation Requirements Panel for ThreatPilot.

Provides a tabular overview of the consolidated, AI-reviewed security requirements.
"""

from __future__ import annotations
from typing import Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QMessageBox
)
from PySide6.QtGui import QDesktopServices
from PySide6.QtCore import QUrl
from threatpilot.core.project_manager import Project
from threatpilot.core.domain_models import MitigationRequirement
from threatpilot.ui.workers import JiraSyncWorker


class MitigationRequirementsPanel(QWidget):
    """A tabular mitigation requirements view."""

    analyze_requested = Signal()
    reasoning_requested = Signal(object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._project: Optional[Project] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        self.setObjectName("mitigation_requirements_container")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)

        header_layout = QHBoxLayout()
        header_font = QFont("Segoe UI", 11, QFont.Weight.Bold)
        label = QLabel("Consolidated Mitigation & Security Requirements")
        label.setFont(header_font)
        label.setObjectName("mitigations_title")
        header_layout.addWidget(label)

        header_layout.addStretch()

        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Filter requirements...")
        self._filter_input.setMinimumWidth(180)
        self._filter_input.setMaximumWidth(300)
        self._filter_input.textChanged.connect(self._on_filter_changed)
        header_layout.addWidget(self._filter_input)

        self._btn_analyze = QPushButton("Analyze Mitigations")
        self._btn_analyze.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_analyze.clicked.connect(self.analyze_requested.emit)
        self._btn_analyze.setEnabled(False)
        header_layout.addWidget(self._btn_analyze)

        self._btn_sync_all = QPushButton("Sync All to Jira")
        self._btn_sync_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_sync_all.clicked.connect(self._sync_all_to_jira)
        self._btn_sync_all.setEnabled(False)
        header_layout.addWidget(self._btn_sync_all)

        layout.addLayout(header_layout)

        # 8 Columns: REQ-ID, Title, Affected Components, Mitigation, Short Description, Test Case, XAI Reasoning, Jira
        self._table = QTableWidget(0, 8)
        self._table.setHorizontalHeaderLabels([
            "REQ-ID",
            "Title",
            "Affected Components",
            "Mitigation",
            "Short Description",
            "Test Case / Validation",
            "XAI Reasoning",
            "Jira"
        ])

        self._table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setDefaultSectionSize(150)
        
        # Set section sizes
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents) # REQ-ID
        self._table.setColumnWidth(1, 160) # Title
        self._table.setColumnWidth(2, 160) # Affected Components
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch) # Mitigation
        self._table.setColumnWidth(4, 220) # Short Description
        self._table.setColumnWidth(5, 220) # Test Case
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive) # XAI Reasoning Button
        self._table.setColumnWidth(6, 160)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Interactive) # Jira Button
        self._table.setColumnWidth(7, 100)

        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setDefaultSectionSize(45)
        self._table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)

        layout.addWidget(self._table)

    def set_project(self, project: Optional[Project]) -> None:
        """Load data from the project into the mitigation requirements table."""
        self._project = project
        self._btn_analyze.setEnabled(project is not None)
        self._btn_sync_all.setEnabled(project is not None)
        self.refresh()

    def refresh(self) -> None:
        """Repopulate the table based on the project's current mitigation requirements."""
        self._table.setRowCount(0)
        if not self._project:
            return

        requirements = getattr(self._project, "mitigation_requirements", [])
        filter_text = self._filter_input.text().lower().strip()

        row_index = 0
        for index, req in enumerate(requirements):
            # Check filtering
            req_id = req.req_id or ""
            title = req.title or ""
            components = req.affected_components or ""
            mitigation = req.mitigation or ""
            desc = req.short_description or ""
            test_case = req.test_case or ""
            reasoning = getattr(req, "reasoning", "") or ""

            if filter_text:
                matches = (
                    filter_text in req_id.lower() or
                    filter_text in title.lower() or
                    filter_text in components.lower() or
                    filter_text in mitigation.lower() or
                    filter_text in desc.lower() or
                    filter_text in test_case.lower() or
                    filter_text in reasoning.lower()
                )
                if not matches:
                    continue

            self._table.insertRow(row_index)

            # Set items
            # REQ-ID
            id_item = QTableWidgetItem(req_id)
            id_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            # Use blue color for requirement ID like Excel sheet styling
            id_item.setForeground(Qt.GlobalColor.darkBlue)
            font = id_item.font()
            font.setBold(True)
            id_item.setFont(font)
            self._table.setItem(row_index, 0, id_item)

            # Title
            self._table.setItem(row_index, 1, QTableWidgetItem(title))

            # Affected Components
            comp_item = QTableWidgetItem(components)
            comp_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row_index, 2, comp_item)

            # Mitigation
            self._table.setItem(row_index, 3, QTableWidgetItem(mitigation))

            # Short Description
            self._table.setItem(row_index, 4, QTableWidgetItem(desc))

            # Test Case / Validation
            self._table.setItem(row_index, 5, QTableWidgetItem(test_case))

            # XAI Reasoning Button widget container (for centering and reducing size)
            container = QWidget()
            btn_layout = QHBoxLayout(container)
            btn_layout.setContentsMargins(0, 0, 0, 0)
            btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

            has_reasoning = bool(reasoning.strip())
            btn_text = "Show XAI Reasoning" if has_reasoning else "Generate XAI Reasoning"
            btn_xai = QPushButton(btn_text)
            btn_xai.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_xai.setFixedHeight(24)
            
            if has_reasoning:
                btn_xai.setStyleSheet("QPushButton { font-size: 10px; font-weight: bold; color: #059669; padding: 2px 10px; }")
            else:
                btn_xai.setStyleSheet("QPushButton { font-size: 10px; color: #0284c7; padding: 2px 10px; }")
                
            btn_xai.clicked.connect(lambda checked=False, r=req: self.reasoning_requested.emit(r))
            btn_layout.addWidget(btn_xai)
            self._table.setCellWidget(row_index, 6, container)

            # Jira Button/Link
            jira_container = QWidget()
            jira_layout = QHBoxLayout(jira_container)
            jira_layout.setContentsMargins(0, 0, 0, 0)
            jira_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            jira_key = getattr(req, "jira_issue_key", "")
            if jira_key:
                btn_jira = QPushButton(jira_key)
                btn_jira.setCursor(Qt.CursorShape.PointingHandCursor)
                btn_jira.setFixedHeight(24)
                btn_jira.setStyleSheet("QPushButton { font-size: 10px; font-weight: bold; color: #1d4ed8; padding: 2px 10px; text-decoration: underline; border: none; background: transparent; }")
                btn_jira.clicked.connect(lambda checked=False, url=getattr(req, "jira_issue_url", ""): QDesktopServices.openUrl(QUrl(url)))
                jira_layout.addWidget(btn_jira)
            else:
                btn_jira = QPushButton("Sync")
                btn_jira.setCursor(Qt.CursorShape.PointingHandCursor)
                btn_jira.setFixedHeight(24)
                btn_jira.setStyleSheet("QPushButton { font-size: 10px; color: #4b5563; padding: 2px 10px; }")
                btn_jira.clicked.connect(lambda checked=False, r=req: self._sync_single_to_jira(r))
                jira_layout.addWidget(btn_jira)
                
            self._table.setCellWidget(row_index, 7, jira_container)

            # Enable word wrapping for each cell (excluding the button)
            for col in range(6):
                item = self._table.item(row_index, col)
                if item:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    if col > 0:
                        item.setToolTip(item.text())

            row_index += 1

    def _on_filter_changed(self, text: str) -> None:
        """Handle live filtering when the user types in the filter field."""
        self.refresh()
        
    def _sync_all_to_jira(self):
        if not self._project: return
        reqs = getattr(self._project, "mitigation_requirements", [])
        unsynced = [r for r in reqs if not getattr(r, "jira_issue_key", "")]
        if not unsynced:
            QMessageBox.information(self, "Jira Sync", "All mitigations are already synced to Jira.")
            return
            
        self._btn_sync_all.setEnabled(False)
        self._btn_sync_all.setText("Syncing...")
        
        self._jira_worker = JiraSyncWorker(unsynced, self)
        self._jira_worker.item_synced.connect(self._on_item_synced)
        self._jira_worker.completed.connect(self._on_sync_completed)
        self._jira_worker.failed.connect(self._on_sync_failed)
        self._jira_worker.start()

    def _sync_single_to_jira(self, req):
        self._btn_sync_all.setEnabled(False)
        self._btn_sync_all.setText("Syncing...")
        
        self._jira_worker = JiraSyncWorker([req], self)
        self._jira_worker.item_synced.connect(self._on_item_synced)
        self._jira_worker.completed.connect(self._on_sync_completed)
        self._jira_worker.failed.connect(self._on_sync_failed)
        self._jira_worker.start()
        
    def _on_item_synced(self, req):
        self.refresh()
        
    def _on_sync_completed(self, success, fail):
        self._btn_sync_all.setEnabled(True)
        self._btn_sync_all.setText("Sync All to Jira")
        if fail > 0:
            QMessageBox.warning(self, "Jira Sync", f"Synced {success} issues. Failed to sync {fail} issues.")
        else:
            QMessageBox.information(self, "Jira Sync", f"Successfully synced {success} issues to Jira.")
            
    def _on_sync_failed(self, error):
        self._btn_sync_all.setEnabled(True)
        self._btn_sync_all.setText("Sync All to Jira")
        QMessageBox.critical(self, "Jira Sync Error", error)
