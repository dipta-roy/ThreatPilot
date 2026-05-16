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
from PySide6.QtCore import Qt, QSize, QModelIndex
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import QStyledItemDelegate, QStyleOptionViewItem
from threatpilot.core.threat_model import Threat, ThreatRegister


class RiskMatrixDialog(QDialog):
    """Visual heat map for risk prioritization."""

    def __init__(self, threats: List[Threat], component_names: List[str] = None, is_dark: bool = True, project: Project | None = None, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Strategic Risk Matrix")
        self.resize(900, 650)
        self.setSizeGripEnabled(True)
        self._threats = threats
        self._project = project
        self._component_names = component_names or []
        self._is_dark_theme = is_dark
        self._setup_ui()
        self._populate_matrix()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        header = QLabel("Visual Risk Heat Map")
        header.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        header.setObjectName("matrix_header")
        layout.addWidget(header)

        desc = QLabel("Threats are plotted by Likelihood (AI identified) vs. Impact (CVSS-derived).")
        desc.setObjectName("matrix_desc")
        layout.addWidget(desc)
        main_h = QHBoxLayout()
        self._matrix = QTableWidget(5, 5)
        self._matrix.setObjectName("risk_heatmap")
        self._matrix.setMinimumSize(450, 450)
        self._matrix.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._matrix.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        class HeatmapDelegate(QStyledItemDelegate):
            def paint(self, painter, option, index):
                bg = index.data(Qt.ItemDataRole.BackgroundRole)
                if bg:
                    painter.fillRect(option.rect, bg)
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
        self._matrix.setVerticalHeaderLabels(["Certain (5)", "Likely (4)", "Possible (3)", "Unlikely (2)", "Rare (1)"])
        self._matrix.setHorizontalHeaderLabels(["Low (1)", "Minor (2)", "Mid (3)", "Major (4)", "Crit (5)"])
        vh = self._matrix.verticalHeader()
        hh = self._matrix.horizontalHeader()
        vh.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        main_h.addWidget(self._matrix, 3)
        self._side_panel = QFrame()
        self._side_panel.setFrameShape(QFrame.Shape.StyledPanel)
        self._side_panel.setObjectName("matrix_side_panel")
        side_layout = QVBoxLayout(self._side_panel)
        
        self._cell_title = QLabel("Select a cell to view threats")
        self._cell_title.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self._cell_title.setStyleSheet("padding-top: 5px;")
        side_layout.addWidget(self._cell_title)
        
        self._threat_table = QTableWidget(0, 2)
        self._threat_table.setHorizontalHeaderLabels(["Threat Title", "Action"])
        self._threat_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._threat_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self._threat_table.setColumnWidth(1, 80)
        self._threat_table.setStyleSheet("background: transparent; border: none;")
        self._threat_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._threat_table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self._threat_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self._threat_table.verticalHeader().setVisible(False)
        self._threat_table.itemDoubleClicked.connect(self._on_threat_double_clicked)
        side_layout.addWidget(self._threat_table)
        main_h.addWidget(self._side_panel, 2)
        layout.addLayout(main_h)
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


    def _get_cell_colors(self, row: int, col: int) -> tuple[QColor, QColor]:
        """Get (background, foreground) QColor for a matrix cell."""
        from threatpilot.risk.utils import calculate_risk_rating, get_risk_color
        
        likelihood = 5 - row
        impact = col + 1
        risk_score = calculate_risk_rating(likelihood, impact)
        bg_hex, fg_hex = get_risk_color(risk_score)
        
        return QColor(bg_hex), QColor(fg_hex)

    def _populate_matrix(self) -> None:
        """Group threats into matrix cells and update counts."""
        from threatpilot.risk.utils import score_to_impact_score
        self._data: Dict[tuple[int, int], List[Threat]] = {}
        
        for t in self._threats:
            impact = score_to_impact_score(t.cvss_score)
            likelihood = t.likelihood
            row = 5 - likelihood
            col = impact - 1
            key = (row, col)
            if key not in self._data: self._data[key] = []
            self._data[key].append(t)

        for r in range(5):
            for c in range(5):
                threats_in_cell = self._data.get((r, c), [])
                count = len(threats_in_cell)
                item = QTableWidgetItem(str(count) if count > 0 else "")
                item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                font = QFont()
                font.setBold(True)
                item.setFont(font)
                
                bg_color, fg_color = self._get_cell_colors(r, c)
                item.setBackground(bg_color)
                
                if count > 0:
                    item.setForeground(fg_color)
                else:
                    # Subtle color for empty cells
                    item.setForeground(QColor("#484f58") if self._is_dark_theme else QColor("#cccccc"))
                
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
            edit_btn.setProperty("class", "btn-edit")
            edit_btn.clicked.connect(lambda checked=False, threat=t: self._edit_threat(threat))
            self._threat_table.setCellWidget(row_idx, 1, edit_btn)

    def _edit_threat(self, threat: Threat) -> None:
        """Open the edit dialog for the selected threat."""
        from threatpilot.ui.threat_edit_dialog import ThreatEditDialog
        dialog = ThreatEditDialog(threat, component_names=self._component_names, project=self._project, parent=self)
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._populate_matrix()
            impact = self._get_impact_score(threat.cvss_score)
            new_row = 5 - threat.likelihood
            new_col = impact - 1
            self._on_cell_clicked(new_row, new_col)
            self._matrix.setCurrentCell(new_row, new_col)