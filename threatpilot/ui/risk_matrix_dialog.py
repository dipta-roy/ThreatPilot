"""Risk Matrix Dialog for ThreatPilot.

Provides a 5x5 visual heat map of identified threats based on Likelihood 
and Impact (derived from CVSS). Supports clicking cells to drill down.
"""

from __future__ import annotations

from typing import List, Dict
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QLabel,
    QHBoxLayout,
    QFrame,
    QAbstractItemView,
    QPushButton,
    QDialogButtonBox,
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QFont

from threatpilot.core.threat_model import Threat, ThreatRegister


class RiskMatrixDialog(QDialog):
    """Visual heat map for risk prioritization."""

    def __init__(self, threats: List[Threat], component_names: List[str] = None, is_dark: bool = True, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Strategic Risk Matrix")
        self.resize(900, 650)
        self._threats = threats
        self._component_names = component_names or []
        self._is_dark_theme = is_dark
        self._setup_ui()
        self._populate_matrix()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Header
        header = QLabel("Visual Risk Heat Map")
        header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        header.setStyleSheet("color: #58a6ff;")
        layout.addWidget(header)

        desc = QLabel("Threats are plotted by Likelihood (AI identified) vs. Impact (CVSS-derived).")
        desc.setStyleSheet("color: #8b949e;")
        layout.addWidget(desc)

        # Main horizontal split
        main_h = QHBoxLayout()
        
        # 1. Left: The Heatmap
        self._matrix = QTableWidget(5, 5)
        self._matrix.setObjectName("risk_heatmap")
        self._matrix.setMinimumSize(450, 450)
        self._matrix.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._matrix.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        # Use a custom delegate that paints item.background(), bypassing QSS
        from PySide6.QtWidgets import QStyledItemDelegate, QStyleOptionViewItem
        from PySide6.QtCore import QModelIndex
        
        class HeatmapDelegate(QStyledItemDelegate):
            def paint(self, painter, option, index):
                bg = index.data(Qt.ItemDataRole.BackgroundRole)
                if bg:
                    painter.fillRect(option.rect, bg)
                # Draw text
                painter.save()
                fg = index.data(Qt.ItemDataRole.ForegroundRole)
                if fg:
                    painter.setPen(fg.color())
                font = index.data(Qt.ItemDataRole.FontRole)
                if font:
                    painter.setFont(font)
                painter.drawText(option.rect, Qt.AlignmentFlag.AlignCenter, index.data() or "")
                painter.restore()
        
        self._matrix.setItemDelegate(HeatmapDelegate(self._matrix))
        
        # Headers
        self._matrix.setVerticalHeaderLabels(["Certain (5)", "Likely (4)", "Possible (3)", "Unlikely (2)", "Rare (1)"])
        self._matrix.setHorizontalHeaderLabels(["Low (1)", "Minor (2)", "Mid (3)", "Major (4)", "Crit (5)"])
        
        # Styling headers
        vh = self._matrix.verticalHeader()
        hh = self._matrix.horizontalHeader()
        vh.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        main_h.addWidget(self._matrix, 3)

        # 2. Right: Drill-down List (theme-aware)
        self._side_panel = QFrame()
        self._side_panel.setFrameShape(QFrame.Shape.StyledPanel)
        if self._is_dark_theme:
            self._side_panel.setStyleSheet("background-color: #161b22; border-radius: 8px;")
            title_color = "#f0f6fc"
            table_color = "#f0f6fc"
        else:
            self._side_panel.setStyleSheet("background-color: #f6f8fa; border-radius: 8px; border: 1px solid #d0d7de;")
            title_color = "#24292f"
            table_color = "#24292f"
        side_layout = QVBoxLayout(self._side_panel)
        
        self._cell_title = QLabel("Select a cell to view threats")
        self._cell_title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._cell_title.setStyleSheet(f"color: {title_color}; padding-top: 5px;")
        side_layout.addWidget(self._cell_title)
        
        self._threat_table = QTableWidget(0, 2)
        self._threat_table.setHorizontalHeaderLabels(["Threat Title", "Action"])
        self._threat_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._threat_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._threat_table.setColumnWidth(1, 80)
        self._threat_table.setStyleSheet(f"background: transparent; border: none; color: {table_color};")
        self._threat_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._threat_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._threat_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._threat_table.verticalHeader().setVisible(False)
        self._threat_table.itemDoubleClicked.connect(self._on_threat_double_clicked)
        side_layout.addWidget(self._threat_table)
        
        main_h.addWidget(self._side_panel, 2)
        
        layout.addLayout(main_h)

        # Close button
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

        self._matrix.cellClicked.connect(self._on_cell_clicked)

    def _on_threat_double_clicked(self, item: QTableWidgetItem) -> None:
        """Handle double-click on a threat in the side panel list."""
        row = item.row()
        likelihood = 5 - self._matrix.currentRow()
        impact = self._matrix.currentColumn() + 1
        threats = self._data.get((self._matrix.currentRow(), self._matrix.currentColumn()), [])
        
        if 0 <= row < len(threats):
            self._edit_threat(threats[row])


    def _get_impact_score(self, cvss: float) -> int:
        """Map 0-10 CVSS to 1-5 Impact scale."""
        if cvss >= 9.0: return 5
        if cvss >= 7.0: return 4
        if cvss >= 4.0: return 3
        if cvss >= 2.0: return 2
        return 1

    def _get_cell_color(self, row: int, col: int) -> QColor:
        likelihood = 5 - row
        impact = col + 1
        risk_score = likelihood * impact
        
        if self._is_dark_theme:
            if risk_score >= 15: return QColor("#8b0000") # Critical Deep Red
            if risk_score >= 10: return QColor("#d73a49") # Major Red
            if risk_score >= 6:  return QColor("#d29922") # Warning Orange/Yellow
            if risk_score >= 3:  return QColor("#30363d") # Mid
            return QColor("#238636") # Low Green
        else:
            # Light Mode High-Contrast Colors
            if risk_score >= 15: return QColor("#cf222e") # Bright Red
            if risk_score >= 10: return QColor("#ffcccc") # Lighter Red
            if risk_score >= 6:  return QColor("#fff8c5") # Soft Yellow
            if risk_score >= 3:  return QColor("#ddf4ff") # Light Blue/Mid
            return QColor("#dafbe1") # Pale Green

    def _populate_matrix(self) -> None:
        """Group threats into matrix cells and update counts."""
        self._data: Dict[tuple[int, int], List[Threat]] = {}
        
        for t in self._threats:
            impact = self._get_impact_score(t.cvss_score)
            likelihood = t.likelihood
            
            # Map to table indices
            # Likelihood 5 -> row 0, Likelihood 1 -> row 4
            # Impact 1 -> col 0, Impact 5 -> col 4
            row = 5 - likelihood
            col = impact - 1
            
            key = (row, col)
            if key not in self._data: self._data[key] = []
            self._data[key].append(t)

        # Clear and draw cells
        for r in range(5):
            for c in range(5):
                threats_in_cell = self._data.get((r, c), [])
                count = len(threats_in_cell)
                
                item = QTableWidgetItem(str(count) if count > 0 else "")
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                
                # Sizing and bolding
                font = QFont()
                font.setBold(True)
                item.setFont(font)
                
                # Apply heat color
                bg = self._get_cell_color(r, c)
                item.setBackground(bg)
                
                if self._is_dark_theme:
                    if count > 0:
                        item.setForeground(QColor("white"))
                    else:
                        item.setForeground(QColor("#484f58")) # subtle zero
                else:
                    if count > 0:
                        # For very dark cells in light theme (Critical/Certain), use white text
                        if r + c <= 2: # Top left-ish are higher risk (Likelihood rank 5, Impact rank 5 is 0,4)
                            # Actually top right is higher.
                            # Row 0 is Likelihood 5. Col 4 is Impact 5.
                            # Row 4 is Likelihood 1. Col 0 is Impact 1.
                            pass
                        
                        # Simplest: dark text for everything in light theme except maybe most critical
                        item.setForeground(QColor("#1a7f37") if (r >= 4 and c <= 0) else QColor("#1a1a1a"))
                        if r == 0 and c == 4: # Critical
                            item.setForeground(QColor("white"))
                    else:
                        item.setForeground(QColor("#cccccc")) # subtle zero light
                
                self._matrix.setItem(r, c, item)

    def _on_cell_clicked(self, row: int, col: int) -> None:
        """Update side panel list with threats in the selected risk category."""
        likelihood = 5 - row
        impact = col + 1
        threats = self._data.get((row, col), [])
        
        self._cell_title.setText(f"Likelihood: {likelihood} | Impact: {impact} ({len(threats)} Threats)")
        self._threat_table.setRowCount(0)
        
        for t in threats:
            row_idx = self._threat_table.rowCount()
            self._threat_table.insertRow(row_idx)
            
            title_item = QTableWidgetItem(f"[{t.category.value[:3]}] {t.title}")
            title_item.setToolTip(t.title)
            self._threat_table.setItem(row_idx, 0, title_item)
            
            edit_btn = QPushButton("Edit")
            edit_btn.setFixedSize(60, 32)
            edit_btn.setStyleSheet("background-color: #238636; color: white; border-radius: 4px; font-weight: bold;")
            edit_btn.clicked.connect(lambda checked=False, threat=t: self._edit_threat(threat))
            self._threat_table.setCellWidget(row_idx, 1, edit_btn)

    def _edit_threat(self, threat: Threat) -> None:
        """Open the edit dialog for the selected threat."""
        from threatpilot.ui.threat_edit_dialog import ThreatEditDialog
        dialog = ThreatEditDialog(threat, component_names=self._component_names, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Re-populate to reflect changes (e.g. if likelihood/impact changed)
            self._populate_matrix()
            # Find the new cell if likelihood/impact changed
            impact = self._get_impact_score(threat.cvss_score)
            new_row = 5 - threat.likelihood
            new_col = impact - 1
            self._on_cell_clicked(new_row, new_col)
            # Select the cell visually
            self._matrix.setCurrentCell(new_row, new_col)
