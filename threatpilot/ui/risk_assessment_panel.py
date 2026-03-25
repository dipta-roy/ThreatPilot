"""Risk Assessment Panel for ThreatPilot.

Provides a comprehensive table view that joins threats with component 
classifications and security metrics.
"""

from __future__ import annotations

from typing import Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QHeaderView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
    QLabel,
    QPushButton,
    QLineEdit,
)

from threatpilot.core.project_manager import Project
from threatpilot.core.threat_model import Threat
from threatpilot.risk.cvss_calculator import get_cvss_severity


class RiskAssessmentPanel(QWidget):
    """A tabular risk assessment view."""

    threat_edited = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._project: Optional[Project] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        header_layout = QHBoxLayout()
        header_font = QFont("Segoe UI", 11, QFont.Weight.Bold)
        label = QLabel("Comprehensive Risk & Vulnerability Assessment Matrix")
        label.setFont(header_font)
        label.setStyleSheet("color: #58a6ff; margin-bottom: 5px;")
        header_layout.addWidget(label)
        
        header_layout.addStretch()
        
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Filter matrix...")
        self._filter_input.setFixedWidth(250)
        self._filter_input.textChanged.connect(self._on_filter_changed)
        header_layout.addWidget(self._filter_input)
        
        layout.addLayout(header_layout)

        self._table = QTableWidget(0, 12)
        self._table.setHorizontalHeaderLabels([
            "Risk ID",
            "Element / Component Name",
            "Asset / Component Name",
            "Threats",
            "Vulnerabilities",
            "Description",
            "Impact",
            "CVSS Vector (3.1)",
            "Likelihood",
            "Severity",
            "Mitigation Strategy",
            "Actions"
        ])
        
        # Enable smooth scrolling
        self._table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setDefaultSectionSize(150)
        
        # Specific stretching logic
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(5, 300) # Description wider
        header.setSectionResizeMode(10, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(11, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(11, 120)
        
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        # Double-click interactions for fast editing
        self._table.itemDoubleClicked.connect(lambda item: self._on_row_double_clicked(item.row()))
        self._table.verticalHeader().sectionDoubleClicked.connect(self._on_row_double_clicked)
        
        layout.addWidget(self._table)

    def _on_row_double_clicked(self, row: int) -> None:
        """Handle double-click on a row or its header to trigger editing."""
        if not self._project or not self._project.threat_register:
            return
        
        threats = self._project.threat_register.threats
        if 0 <= row < len(threats):
            self._edit_threat(threats[row])


    def set_project(self, project: Optional[Project]) -> None:
        """Load data from the project into the assessment table."""
        self._project = project
        self.refresh()

    def refresh(self) -> None:
        """Clear and rebuild the table with the latest joined data."""
        self._table.setRowCount(0)
        if not self._project or not self._project.threat_register:
            return

        threats = self._project.threat_register.threats
        self._table.setRowCount(len(threats))

        for row, t in enumerate(threats):
            # 1. Risk ID (Serial Number)
            id_item = QTableWidgetItem(str(row + 1))
            id_item.setToolTip("Double click to edit")
            self._table.setItem(row, 0, id_item)
            
            # 2 & 3. Component Names (Element & Asset)
            elem = t.affected_element or t.affected_components or "N/A"
            asset = t.affected_asset or t.affected_components or "N/A"
            self._table.setItem(row, 1, QTableWidgetItem(elem))
            self._table.setItem(row, 2, QTableWidgetItem(asset))
            
            # 4. Threats (Only Title)
            self._table.setItem(row, 3, QTableWidgetItem(t.title))
            
            # 5. Vulnerabilities
            self._table.setItem(row, 4, QTableWidgetItem(t.vulnerabilities or "N/A"))
            
            # 6. Description
            self._table.setItem(row, 5, QTableWidgetItem(t.description))
            
            # 7. Impact
            self._table.setItem(row, 6, QTableWidgetItem(t.impact))
            
            # 8. CVSS Vector
            self._table.setItem(row, 7, QTableWidgetItem(t.cvss_vector or "N/A"))
            
            # 9. Likelihood
            self._table.setItem(row, 8, QTableWidgetItem(f"{t.likelihood}/5"))
            
            # 10. Severity (With Cell Background Coloring)
            severity = get_cvss_severity(t.cvss_score)
            sev_item = QTableWidgetItem(f"{severity} ({t.cvss_score})")
            self._table.setItem(row, 9, sev_item)
            
            # Apply specific cell backgrounds
            s_upper = severity.upper()
            if s_upper == "CRITICAL":
                sev_item.setBackground(QColor("#7b1e1e"))  # Dark reddish brown
                sev_item.setForeground(QColor("white"))
            elif s_upper == "HIGH":
                sev_item.setBackground(QColor("#cc0000"))  # Red
                sev_item.setForeground(QColor("white"))
            elif s_upper == "MEDIUM":
                sev_item.setBackground(QColor("#ffbb33"))  # Amber
                sev_item.setForeground(QColor("black"))
            elif s_upper == "LOW":
                sev_item.setBackground(QColor("#33b5e5"))  # Light Blue
                sev_item.setForeground(QColor("black"))

            # 11. Mitigation Strategy
            self._table.setItem(row, 10, QTableWidgetItem(t.mitigation))
            
            # 12. Actions (Edit Button)
            edit_btn = QPushButton("Edit")
            edit_btn.setFixedSize(90, 32)
            edit_btn.setStyleSheet("background-color: #238636; color: white; border-radius: 4px; font-weight: bold;")
            edit_btn.clicked.connect(lambda checked=False, threat=t: self._edit_threat(threat))
            self._table.setCellWidget(row, 11, edit_btn)
            
            # Set tooltip for the row header so users know they can double-click it.
            self._table.setVerticalHeaderItem(row, QTableWidgetItem(str(row + 1)))
            self._table.verticalHeaderItem(row).setToolTip("Double click to edit")
            
        self._table.resizeRowsToContents()


    def _edit_threat(self, threat: Threat) -> None:
        """Open the edit dialog for the selected threat."""
        from threatpilot.ui.threat_edit_dialog import ThreatEditDialog
        from PySide6.QtWidgets import QDialog
        
        if self._project:
            component_names = [c.name for c in self._project.components]
            component_names.extend([f.name for f in self._project.flows])

        dialog = ThreatEditDialog(threat, component_names=component_names, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self.threat_edited.emit()

    def _on_filter_changed(self, text: str) -> None:
        """Filter the table rows based on the text."""
        text = text.lower()
        for row in range(self._table.rowCount()):
            match = False
            for col in range(self._table.columnCount()):
                item = self._table.item(row, col)
                if item and text in item.text().lower():
                    match = True
                    break
            self._table.setRowHidden(row, not match)
