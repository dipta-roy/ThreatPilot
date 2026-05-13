"""Risk Assessment Panel for ThreatPilot.

Provides a comprehensive table view that joins threats with component 
classifications and security metrics.
"""

from __future__ import annotations
from typing import Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from threatpilot.core.project_manager import Project
from threatpilot.core.threat_model import Threat, STRIDECategory
from threatpilot.risk.cvss_calculator import get_cvss_severity
from threatpilot.ui.threat_edit_dialog import ThreatEditDialog

class RiskAssessmentPanel(QWidget):
    """A tabular risk assessment view."""

    threat_edited = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._project: Optional[Project] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        self.setObjectName("assessment_container")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        header_layout = QHBoxLayout()
        header_font = QFont("Segoe UI", 11, QFont.Weight.Bold)
        label = QLabel("Comprehensive Risk & Vulnerability Assessment Matrix")
        label.setFont(header_font)
        label.setObjectName("assessment_title")
        header_layout.addWidget(label)
        
        header_layout.addStretch()
        
        self._filter_input = QLineEdit()
        self._filter_input.setPlaceholderText("Filter matrix...")
        self._filter_input.setFixedWidth(250)
        self._filter_input.textChanged.connect(self._on_filter_changed)
        header_layout.addWidget(self._filter_input)
        
        self._btn_add_threat = QPushButton("Add New Risk")
        self._btn_add_threat.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_add_threat.clicked.connect(self._on_add_threat)
        self._btn_add_threat.setEnabled(False)
        header_layout.addWidget(self._btn_add_threat)
        
        layout.addLayout(header_layout)

        self._table = QTableWidget(0, 12)
        self._table.setHorizontalHeaderLabels([
            "SL #",
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
        
        self._table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setDefaultSectionSize(150)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(5, 300)
        header.setSectionResizeMode(10, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(11, QHeaderView.ResizeMode.Fixed)
        self._table.setColumnWidth(11, 185)
        self._table.setAlternatingRowColors(True)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
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
        self._btn_add_threat.setEnabled(project is not None)
        self.refresh()

    def set_theme(self, is_dark: bool) -> None:
        """Update the panel's internal state for theme changes."""
        self._is_dark_theme = is_dark
        self.refresh()

    def refresh(self, scroll_to_row: int = -1) -> None:
        """Clear and rebuild the table with the latest joined data.

        Args:
            scroll_to_row: If >= 0, scroll to and select this row after
                rebuilding. When -1 (default), the previous scroll
                position is preserved instead.
        """
        # ── Consume any pending scroll target set by _edit_threat ──
        if scroll_to_row < 0:
            pending = getattr(self, "_pending_scroll_row", -1)
            if pending >= 0:
                scroll_to_row = pending
            self._pending_scroll_row = -1

        # ── Preserve scroll position & selection before clearing ──
        v_scroll = self._table.verticalScrollBar().value()
        h_scroll = self._table.horizontalScrollBar().value()
        prev_row = self._table.currentRow()

        self._table.setRowCount(0)
        if not self._project or not self._project.threat_register:
            return

        is_dark = getattr(self, "_is_dark_theme", True)
        threats = self._project.threat_register.threats
        self._table.setRowCount(len(threats))

        for row, t in enumerate(threats):
            id_item = QTableWidgetItem(str(row + 1))
            id_item.setToolTip("Double click to edit")
            self._table.setItem(row, 0, id_item)
            
            # Determine display names. Prioritize manual user overrides in the specific fields.
            elem = t.affected_element_type or ""
            asset = t.affected_asset_type or ""
            
            # If fields are empty or contain generic AI types, attempt to resolve from narrative
            generic_types = ["data flow", "informational", "physical", "process", "data store", "external entity", "n/a", ""]
            if elem.lower() in generic_types or asset.lower() in generic_types:
                res_elem = ""
                res_asset = ""
                if t.affected_components:
                    haystack = (f"{t.affected_components} {t.title} {t.description}").lower()
                    for cname in [n.strip() for n in t.affected_components.split(",")]:
                        # 1. Exact flow name match
                        flow_match = next((f for f in self._project.flows if f.name == cname), None)
                        if flow_match:
                            src = next((c for c in self._project.components if c.component_id == flow_match.source_id), None)
                            dst = next((c for c in self._project.components if c.component_id == flow_match.target_id), None)
                            res_elem = src.name if src else ""
                            res_asset = dst.name if dst else ""
                            break
                        # 2. Exact component name match
                        comp_match = next((c for c in self._project.components if c.name == cname), None)
                        if comp_match:
                            res_elem = comp_match.name
                            res_asset = comp_match.name
                            break
                    # 3. Fuzzy flow match
                    if not res_elem:
                        for f in self._project.flows:
                            src = next((c for c in self._project.components if c.component_id == f.source_id), None)
                            dst = next((c for c in self._project.components if c.component_id == f.target_id), None)
                            if src and dst and src.name.lower() in haystack and dst.name.lower() in haystack:
                                res_elem = src.name
                                res_asset = dst.name
                                break
                    # 4. Fuzzy component match
                    if not res_elem:
                        for c in self._project.components:
                            if c.name.lower() in haystack:
                                res_elem = c.name
                                res_asset = c.name
                                break
                
                # Only overwrite if resolution found something better
                elem = elem if elem.lower() not in generic_types else (res_elem or elem or t.affected_components or "N/A")
                asset = asset if asset.lower() not in generic_types else (res_asset or asset or t.affected_components or "N/A")
            self._table.setItem(row, 1, QTableWidgetItem(elem))
            self._table.setItem(row, 2, QTableWidgetItem(asset))
            self._table.setItem(row, 3, QTableWidgetItem(t.title))
            v_texts = []
            v_ids = getattr(t, "vulnerability_ids", [])
            for vid in v_ids:
                v_obj = self._project.vulnerability_register.get_vulnerability(vid)
                if v_obj:
                    v_texts.append(v_obj.description)
            vuln_summary = "; ".join(v_texts) if v_texts else "N/A"
            self._table.setItem(row, 4, QTableWidgetItem(vuln_summary))
            self._table.setItem(row, 5, QTableWidgetItem(t.description))
            self._table.setItem(row, 6, QTableWidgetItem(t.impact))
            self._table.setItem(row, 7, QTableWidgetItem(t.cvss_vector or "N/A"))
            self._table.setItem(row, 8, QTableWidgetItem(f"{t.likelihood}/5"))
            severity = get_cvss_severity(t.cvss_score)
            sev_text = f"{severity} ({t.cvss_score})"
            sev_item = QTableWidgetItem(sev_text)
            self._table.setItem(row, 9, sev_item)
            lbl = QLabel(sev_text)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            lbl.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            
            s_upper = severity.upper()
            if is_dark:
                if s_upper == "CRITICAL":
                    lbl.setStyleSheet("background-color: #7b1e1e; color: white; border-radius: 4px; padding: 3px;")
                elif s_upper == "HIGH":
                    lbl.setStyleSheet("background-color: #cc0000; color: white; border-radius: 4px; padding: 3px;")
                elif s_upper == "MEDIUM":
                    lbl.setStyleSheet("background-color: #e3b341; color: white; border-radius: 4px; padding: 3px;")
                elif s_upper == "LOW":
                    lbl.setStyleSheet("background-color: #1f6feb; color: white; border-radius: 4px; padding: 3px;")
                else:
                    lbl.setStyleSheet("background-color: #30363d; color: white; border-radius: 4px; padding: 3px;")
            else:
                if s_upper == "CRITICAL":
                    lbl.setStyleSheet("background-color: #cf222e; color: white; border-radius: 4px; padding: 3px;")
                elif s_upper == "HIGH":
                    lbl.setStyleSheet("background-color: #af4e00; color: white; border-radius: 4px; padding: 3px;")
                elif s_upper == "MEDIUM":
                    lbl.setStyleSheet("background-color: #9a6700; color: white; border-radius: 4px; padding: 3px;")
                elif s_upper == "LOW":
                    lbl.setStyleSheet("background-color: #0969da; color: white; border-radius: 4px; padding: 3px;")
                else:
                    lbl.setStyleSheet("background-color: #f6f8fa; color: #57606a; border-radius: 4px; padding: 3px;")

            container = QWidget()
            layout = QHBoxLayout(container)
            layout.setContentsMargins(4, 2, 4, 2)
            layout.addWidget(lbl)
            container.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            self._table.setCellWidget(row, 9, container)
            self._table.setItem(row, 10, QTableWidgetItem(t.mitigation))
            actions_container = QWidget()
            actions_layout = QHBoxLayout(actions_container)
            actions_layout.setContentsMargins(4, 2, 4, 2)
            actions_layout.setSpacing(6)
            edit_btn = QPushButton("Edit")
            edit_btn.setFixedSize(70, 28)
            edit_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            edit_btn.clicked.connect(lambda checked=False, threat=t: self._edit_threat(threat))
            actions_layout.addWidget(edit_btn)
            del_btn = QPushButton("Delete")
            del_btn.setFixedSize(90, 28)
            del_btn.setCursor(Qt.CursorShape.PointingHandCursor)
            if is_dark:
                del_btn.setStyleSheet("""
                    QPushButton { color: #ff6b6b; background-color: #2a1515; border: 1px solid #7b1e1e; border-radius: 4px; font-weight: bold; }
                    QPushButton:hover { background-color: #7b1e1e; color: white; }
                """)
            else:
                del_btn.setStyleSheet("""
                    QPushButton { color: #cf222e; background-color: #ffebe9; border: 1px solid #d73a49; border-radius: 4px; font-weight: bold; }
                    QPushButton:hover { background-color: #d73a49; color: white; }
                """)
                
            del_btn.clicked.connect(lambda checked=False, tid=t.threat_id: self._delete_threat(tid))
            actions_layout.addWidget(del_btn)
            self._table.setCellWidget(row, 11, actions_container)
            self._table.setVerticalHeaderItem(row, QTableWidgetItem(str(row + 1)))
            self._table.verticalHeaderItem(row).setToolTip("Double click to edit")
            
        self._table.resizeRowsToContents()

        # ── Restore scroll position & selection after rebuild ──
        if scroll_to_row >= 0 and scroll_to_row < self._table.rowCount():
            self._table.selectRow(scroll_to_row)
            self._table.scrollToItem(
                self._table.item(scroll_to_row, 0),
                QTableWidget.ScrollHint.PositionAtCenter,
            )
        else:
            # Clamp previous row to the new row count
            if prev_row >= 0 and prev_row < self._table.rowCount():
                self._table.selectRow(prev_row)
            self._table.verticalScrollBar().setValue(v_scroll)
            self._table.horizontalScrollBar().setValue(h_scroll)


    def _edit_threat(self, threat: Threat) -> None:
        """Open the edit dialog for the selected threat."""
        if self._project:
            component_names = sorted(list(set(
                [c.name for c in self._project.components]
            )))

        dialog = ThreatEditDialog(threat, component_names=component_names, project=self._project, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Determine the row index of the edited threat so we can
            # scroll back to it after the save-triggered refresh.
            edited_row = -1
            if self._project and self._project.threat_register:
                try:
                    edited_row = self._project.threat_register.threats.index(threat)
                except ValueError:
                    edited_row = -1
            self._pending_scroll_row = edited_row
            self.threat_edited.emit()

    def _on_add_threat(self) -> None:
        """Create a new manual threat and open the edit dialog."""
        if not self._project or not self._project.threat_register:
            return
            
        new_threat = Threat(title="New Identified Risk", category=STRIDECategory.TAMPERING)
        self._project.threat_register.add_threat(new_threat, skip_duplicates=False)
        self.refresh()
        self._edit_threat(new_threat)
        self.threat_edited.emit()

    def _delete_threat(self, threat_id: str) -> None:
        """Delete the specified threat after confirmation."""
        reply = QMessageBox.question(
            self,
            "Delete Threat",
            "Are you sure you want to delete this threat? This action cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            if self._project and self._project.threat_register:
                self._project.threat_register.remove_threat(threat_id)
                self.refresh()
                self.threat_edited.emit()

    def _on_filter_changed(self, text: str) -> None:
        """Filter the table rows based on the text."""
        text = text.lower()
        visible_row_count = 1
        for row in range(self._table.rowCount()):
            match = False
            for col in range(self._table.columnCount()):
                item = self._table.item(row, col)
                if item and text in item.text().lower():
                    match = True
                    break
            
            self._table.setRowHidden(row, not match)
            if match:
                self._table.item(row, 0).setText(str(visible_row_count))
                visible_row_count += 1