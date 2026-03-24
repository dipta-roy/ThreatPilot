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
    QListWidget,
    QDialogButtonBox,
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QColor, QFont

from threatpilot.core.threat_model import Threat, ThreatRegister


class RiskMatrixDialog(QDialog):
    """Visual heat map for risk prioritization."""

    def __init__(self, threats: List[Threat], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Strategic Risk Matrix")
        self.resize(900, 650)
        self._threats = threats
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
        self._matrix.setMinimumSize(450, 450)
        self._matrix.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._matrix.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        
        # Headers
        self._matrix.setVerticalHeaderLabels(["Certain (5)", "Likely (4)", "Possible (3)", "Unlikely (2)", "Rare (1)"])
        self._matrix.setHorizontalHeaderLabels(["Low (1)", "Minor (2)", "Mid (3)", "Major (4)", "Crit (5)"])
        
        # Styling headers
        vh = self._matrix.verticalHeader()
        hh = self._matrix.horizontalHeader()
        vh.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        main_h.addWidget(self._matrix, 3)

        # 2. Right: Drill-down List
        self._side_panel = QFrame()
        self._side_panel.setFrameShape(QFrame.Shape.StyledPanel)
        self._side_panel.setStyleSheet("background-color: #161b22; border-radius: 8px;")
        side_layout = QVBoxLayout(self._side_panel)
        
        self._cell_title = QLabel("Select a cell to view threats")
        self._cell_title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._cell_title.setStyleSheet("color: #f0f6fc; padding-top: 5px;")
        side_layout.addWidget(self._cell_title)
        
        self._threat_list = QListWidget()
        self._threat_list.setStyleSheet("background: transparent; border: none;")
        side_layout.addWidget(self._threat_list)
        
        main_h.addWidget(self._side_panel, 2)
        
        layout.addLayout(main_h)

        # Close button
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

        self._matrix.cellClicked.connect(self._on_cell_clicked)

    def _get_impact_score(self, cvss: float) -> int:
        """Map 0-10 CVSS to 1-5 Impact scale."""
        if cvss >= 9.0: return 5
        if cvss >= 7.0: return 4
        if cvss >= 4.0: return 3
        if cvss >= 2.0: return 2
        return 1

    def _get_cell_color(self, row: int, col: int) -> QColor:
        """Heatmap logic: top-right is red (5,5), bottom-left is green (1,1).
        
        Table rows: 0 (Likelihood 5) to 4 (Likelihood 1)
        Table cols: 0 (Impact 1) to 4 (Impact 5)
        """
        likelihood = 5 - row
        impact = col + 1
        risk_score = likelihood * impact
        
        if risk_score >= 15: return QColor("#8b0000") # Critical Deep Red
        if risk_score >= 10: return QColor("#d73a49") # Major Red
        if risk_score >= 6:  return QColor("#d29922") # Warning Orange/Yellow
        if risk_score >= 3:  return QColor("#30363d") # Mid
        return QColor("#238636") # Low Green

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
                if count > 0:
                    item.setForeground(QColor("white"))
                else:
                    item.setForeground(QColor("#484f58")) # subtle zero
                
                self._matrix.setItem(r, c, item)

    def _on_cell_clicked(self, row: int, col: int) -> None:
        """Update side panel list with threats in the selected risk category."""
        likelihood = 5 - row
        impact = col + 1
        threats = self._data.get((row, col), [])
        
        self._cell_title.setText(f"Likelihood: {likelihood} | Impact: {impact} ({len(threats)} Threats)")
        self._threat_list.clear()
        
        for t in threats:
            self._threat_list.addItem(f"[{t.category}] {t.title}")
