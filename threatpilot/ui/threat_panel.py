"""Threat panel module for ThreatPilot.

Provides a ``QTableWidget`` based panel to display and manage identified threats.
Supports filtering by STRIDE / LINDDUN category and text search.
"""

from __future__ import annotations
from typing import Dict, List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)
from threatpilot.core.threat_model import STRIDECategory, Threat, ThreatRegister
from threatpilot.risk.utils import get_risk_label

# ---------------------------------------------------------------------------
# Category sets
# ---------------------------------------------------------------------------
STRIDE_CATEGORIES = {
    STRIDECategory.SPOOFING, STRIDECategory.TAMPERING,
    STRIDECategory.REPUDIATION, STRIDECategory.INFORMATION_DISCLOSURE,
    STRIDECategory.DENIAL_OF_SERVICE, STRIDECategory.ELEVATION_OF_PRIVILEGE,
}
LINDDUN_CATEGORIES = {
    STRIDECategory.LINKABILITY, STRIDECategory.IDENTIFIABILITY,
    STRIDECategory.NON_REPUDIATION_PRIVACY, STRIDECategory.DETECTABILITY,
    STRIDECategory.DISCLOSURE_OF_INFORMATION, STRIDECategory.UNAWARENESS,
    STRIDECategory.NON_COMPLIANCE,
}


class ThreatPanel(QWidget):
    """Provides a flat table view for managing STRIDE or LINDDUN threats."""

    threat_selected: Signal = Signal(object)
    threat_added: Signal = Signal(object)
    threat_removed: Signal = Signal(str)
    run_analysis_requested: Signal = Signal(str, int)
    reasoning_requested: Signal = Signal(object)

    def __init__(self, parent: QWidget | None = None, filter_mode: str = "ALL") -> None:
        super().__init__(parent)
        self._register: Optional[ThreatRegister] = None
        self._filter_mode = filter_mode.upper()
        self._is_dark_theme: bool = False
        self._setup_ui()

    def _setup_ui(self) -> None:
        """Initializes the table layout, search filters, and control actions."""
        self.setObjectName("threat_panel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.setSpacing(10)

        toolbar_layout = QHBoxLayout()

        self._filter_combo = QComboBox()
        self._filter_combo.addItems(["All Frameworks", "STRIDE (Security)", "LINDDUN (Privacy)"])
        mode_map = {"ALL": 0, "STRIDE": 1, "LINDDUN": 2}
        self._filter_combo.setCurrentIndex(mode_map.get(self._filter_mode, 0))
        self._filter_combo.currentTextChanged.connect(self._on_filter_mode_changed)
        self._filter_combo.setMinimumWidth(150)
        self._filter_combo.setMaximumWidth(200)
        toolbar_layout.addWidget(self._filter_combo)

        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Filter threats...")
        self._search_input.setMinimumWidth(180)
        self._search_input.setMaximumWidth(300)
        self._search_input.textChanged.connect(lambda: self.refresh())
        toolbar_layout.addWidget(self._search_input)

        self._cat_filter_combo = QComboBox()
        self._cat_filter_combo.setMinimumWidth(140)
        self._cat_filter_combo.setMaximumWidth(180)
        self._cat_filter_combo.currentTextChanged.connect(lambda: self.refresh())
        toolbar_layout.addWidget(self._cat_filter_combo)

        self._sev_filter_combo = QComboBox()
        self._sev_filter_combo.addItems(["All Severities", "Critical", "High", "Medium", "Low", "Info", "None"])
        self._sev_filter_combo.setMinimumWidth(110)
        self._sev_filter_combo.setMaximumWidth(150)
        self._sev_filter_combo.currentTextChanged.connect(lambda: self.refresh())
        toolbar_layout.addWidget(self._sev_filter_combo)

        self._update_category_filter_options()

        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.VLine)
        sep1.setFrameShadow(QFrame.Shadow.Sunken)
        toolbar_layout.addWidget(sep1)

        btn_text = "Run AI Analysis"
        if self._filter_mode == "STRIDE": btn_text = "Run STRIDE Analysis"
        elif self._filter_mode == "LINDDUN": btn_text = "Run LINDDUN Analysis"

        if self._filter_mode in ("STRIDE", "LINDDUN"):
            iter_label = QLabel("Iterations:")
            iter_label.setProperty("class", "text-muted")
            iter_label.setStyleSheet("font-weight: bold; margin-left: 10px;")
            toolbar_layout.addWidget(iter_label)

            self._iterations_combo = QComboBox()
            self._iterations_combo.setObjectName("combo_iterations")
            self._iterations_combo.addItems([str(i) for i in range(1, 6)])
            self._iterations_combo.setCurrentIndex(0)
            self._iterations_combo.setMinimumWidth(80)
            self._iterations_combo.setMaximumWidth(100)
            toolbar_layout.addWidget(self._iterations_combo)
        else:
            self._iterations_combo = None

        self._btn_run = QPushButton(btn_text)
        self._btn_run.setObjectName("btn_run_threat_analysis")
        self._btn_run.setProperty("class", "btn-primary")
        self._btn_run.clicked.connect(self._on_run_clicked)
        toolbar_layout.addWidget(self._btn_run)

        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.VLine)
        sep2.setFrameShadow(QFrame.Shadow.Sunken)
        toolbar_layout.addWidget(sep2)

        self._btn_add = QPushButton("Add Manual Threat")
        self._btn_add.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_add.clicked.connect(self._on_add_threat)
        toolbar_layout.addWidget(self._btn_add)

        from PySide6.QtWidgets import QCheckBox
        self._select_all = QCheckBox("Select All")
        self._select_all.setObjectName("select_all_checkbox")
        self._select_all.clicked.connect(self._on_select_all)
        toolbar_layout.addWidget(self._select_all)

        self._btn_delete = QPushButton("Delete Selected")
        self._btn_delete.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_delete.clicked.connect(self._on_delete_threat)
        toolbar_layout.addWidget(self._btn_delete)

        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)

        self._btn_add.setEnabled(False)
        self._btn_delete.setEnabled(False)

        self._summary_label = QLabel("")
        self._summary_label.setObjectName("threat_summary_label")
        layout.addWidget(self._summary_label)

        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels(["", "SL #", "Category", "Severity", "Threat Title", "Affected Component", "CVSS Score"])

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 30)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setColumnWidth(2, 160)
        self._table.setColumnWidth(3, 100)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(5, 200)
        self._table.setColumnWidth(6, 100)

        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self._table.cellClicked.connect(self._on_cell_clicked)
        self._table.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self._table)

        self.setEnabled(False)

    def set_theme(self, is_dark: bool) -> None:
        """Updates the panel styling for theme transitions."""
        self._is_dark_theme = is_dark
        self.refresh()

    def set_register(self, register: Optional[ThreatRegister]) -> None:
        """Binds a threat register to the panel and refreshes the view."""
        self._register = register
        has_reg = register is not None
        self.setEnabled(has_reg)
        if has_reg:
            self._btn_add.setEnabled(True)
            self._btn_delete.setEnabled(True)

        self.refresh()

    def clear_filter(self) -> None:
        """Clears the active search filter."""
        self._search_input.clear()
        self.refresh()

    def refresh(self) -> None:
        """Synchronizes the table view with the current register state."""
        if not self._register:
            self._table.setRowCount(0)
            self._summary_label.setText("")
            return

        v_scroll = self._table.verticalScrollBar().value()
        h_scroll = self._table.horizontalScrollBar().value()
        prev_row = self._table.currentRow()

        self._table.blockSignals(True)
        self._table.setRowCount(0)

        visible_threats, category_counts = self._filter_threats()
        self._update_summary(visible_threats, category_counts)
        self._populate_table(visible_threats)

        if 0 <= prev_row < self._table.rowCount():
            self._table.selectRow(prev_row)
        
        self._table.verticalScrollBar().setValue(v_scroll)
        self._table.horizontalScrollBar().setValue(h_scroll)
        self._table.blockSignals(False)

    def _filter_threats(self) -> tuple[list[Threat], dict[str, int]]:
        """Applies active framework, category, severity, and search filters."""
        visible_threats: list[Threat] = []
        category_counts: dict[str, int] = {}
        
        search_text = self._search_input.text().strip().lower()
        selected_cat = self._cat_filter_combo.currentText()
        selected_sev = self._sev_filter_combo.currentText()

        for threat in self._register.threats:
            target_cat = self._resolve_category(threat.category)
            if self._filter_mode == "STRIDE" and target_cat not in STRIDE_CATEGORIES: continue
            if self._filter_mode == "LINDDUN" and target_cat not in LINDDUN_CATEGORIES: continue
            
            if selected_cat != "All Categories":
                cat_name = target_cat.name.upper().replace("_PRIVACY", "").replace("_", " ")
                if selected_cat.upper() != cat_name: continue

            if selected_sev != "All Severities":
                if selected_sev.upper() != get_risk_label(threat.cvss_score).upper(): continue

            if search_text:
                sev_label = get_risk_label(threat.cvss_score).lower()
                vuln_ids = " ".join(getattr(threat, "vulnerability_ids", []))
                matches = (
                    search_text in threat.title.lower() or
                    search_text in threat.description.lower() or
                    search_text in vuln_ids.lower() or
                    search_text in threat.category.value.lower() or
                    search_text in threat.affected_components.lower() or
                    search_text in sev_label
                )
                if not matches: continue

            visible_threats.append(threat)
            cat_label = target_cat.name.upper().replace("_PRIVACY", "")
            category_counts[cat_label] = category_counts.get(cat_label, 0) + 1
            
        return visible_threats, category_counts

    def _update_summary(self, threats: list[Threat], counts: dict[str, int]) -> None:
        """Updates the status label with filtered threat metrics."""
        parts = [f"{name}: {count}" for name, count in sorted(counts.items())]
        total = len(threats)
        summary = f"{total} threat{'s' if total != 1 else ''}"
        if parts: summary += f"  •  {' | '.join(parts)}"
        self._summary_label.setText(summary)

    def _populate_table(self, threats: list[Threat]) -> None:
        """Constructs table rows for the provided threat list."""
        self._table.setRowCount(len(threats))
        is_dark = self._is_dark_theme
        bold_font = QFont(); bold_font.setBold(True)

        for row, threat in enumerate(threats):
            sev_label = get_risk_label(threat.cvss_score)
            target_cat = self._resolve_category(threat.category)
            cat_name = target_cat.name.upper().replace("_PRIVACY", "")

            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk_item.setCheckState(Qt.CheckState.Unchecked)
            self._table.setItem(row, 0, chk_item)

            sl_item = QTableWidgetItem(str(row + 1))
            sl_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            sl_item.setData(Qt.ItemDataRole.UserRole, threat)
            self._table.setItem(row, 1, sl_item)

            cat_lbl = QLabel(cat_name)
            cat_lbl.setFont(bold_font)
            cat_lbl.setProperty("class", "text-accent")
            cat_lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            cat_lbl.setContentsMargins(5, 0, 0, 0)
            
            cat_lbl.style().unpolish(cat_lbl)
            cat_lbl.style().polish(cat_lbl)
            self._table.setCellWidget(row, 2, cat_lbl)

            s_upper = sev_label.upper()
            lbl = QLabel(sev_label)
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            lbl.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            
            if s_upper == "CRITICAL": lbl.setProperty("class", "severity-critical")
            elif s_upper == "HIGH": lbl.setProperty("class", "severity-high")
            elif s_upper == "MEDIUM": lbl.setProperty("class", "severity-medium")
            elif s_upper == "LOW": lbl.setProperty("class", "severity-low")
            else: lbl.setProperty("class", "severity-info")
            
            # Re-apply style to ensure class property is picked up
            lbl.style().unpolish(lbl)
            lbl.style().polish(lbl)

            container = QWidget()
            layout = QHBoxLayout(container)
            layout.setContentsMargins(4, 2, 4, 2)
            layout.addWidget(lbl)
            container.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            self._table.setCellWidget(row, 3, container)

            title_text = f"[Accepted] {threat.title}" if threat.is_accepted_risk else threat.title
            title_item = QTableWidgetItem(title_text)
            if threat.is_accepted_risk: title_item.setForeground(QColor(Qt.GlobalColor.gray))
            self._table.setItem(row, 4, title_item)

            self._table.setItem(row, 5, QTableWidgetItem(threat.affected_components or "N/A"))
            score_item = QTableWidgetItem(f"{threat.cvss_score:.1f}")
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 6, score_item)

    @staticmethod
    def _resolve_category(category) -> STRIDECategory:
        """Resolves raw category input to a valid STRIDECategory enum."""
        if isinstance(category, STRIDECategory): return category
        if isinstance(category, str):
            for member in STRIDECategory:
                if category.lower() == member.value.lower(): return member
        return STRIDECategory.TAMPERING


    def _on_filter_mode_changed(self, text: str) -> None:
        """Handles framework filter transitions and updates UI components."""
        if "STRIDE" in text: self._filter_mode = "STRIDE"
        elif "LINDDUN" in text: self._filter_mode = "LINDDUN"
        else: self._filter_mode = "ALL"
            
        if hasattr(self, "_btn_run"):
            btn_text = "Run AI Analysis"
            if self._filter_mode == "STRIDE": btn_text = "Run STRIDE Analysis"
            elif self._filter_mode == "LINDDUN": btn_text = "Run LINDDUN Analysis"
            self._btn_run.setText(btn_text)
            
        self._update_category_filter_options()
        self.refresh()

    def _update_category_filter_options(self) -> None:
        """Populates category-specific filtering options based on the active framework."""
        self._cat_filter_combo.blockSignals(True)
        self._cat_filter_combo.clear()
        options = ["All Categories"]
        if self._filter_mode == "STRIDE":
            options.extend([c.name.title().replace("_", " ") for c in sorted(list(STRIDE_CATEGORIES), key=lambda x: x.name)])
        elif self._filter_mode == "LINDDUN":
            options.extend([c.name.replace("_PRIVACY", "").title().replace("_", " ") for c in sorted(list(LINDDUN_CATEGORIES), key=lambda x: x.name)])
        self._cat_filter_combo.addItems(options)
        self._cat_filter_combo.setCurrentIndex(0)
        self._cat_filter_combo.blockSignals(False)

    def _on_run_clicked(self) -> None:
        """Dispatches an analysis request with current iteration parameters."""
        iters = int(self._iterations_combo.currentText()) if self._iterations_combo else 1
        self.run_analysis_requested.emit(self._filter_mode, iters)

    def _on_add_threat(self) -> None:
        """Inserts a new manual threat entry into the register."""
        if self._register is None: return
        new_t = Threat(title="New Identified Risk", category=STRIDECategory.TAMPERING)
        self._register.add_threat(new_t, skip_duplicates=False)
        self.refresh()
        self.threat_added.emit(new_t)
        self.threat_selected.emit(new_t)

    def _on_select_all(self, checked: bool) -> None:
        """Toggles check state for all visible threats."""
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self._table.blockSignals(True)
        for r in range(self._table.rowCount()):
            item = self._table.item(r, 0)
            if item: item.setCheckState(state)
        self._table.blockSignals(False)

    def _on_delete_threat(self) -> None:
        """Removes selected or active threats from the register after confirmation."""
        if self._register is None: return
        to_del = [self._table.item(r, 1).data(Qt.ItemDataRole.UserRole) for r in range(self._table.rowCount()) if self._table.item(r, 0).checkState() == Qt.CheckState.Checked]
        if not to_del and self._table.currentRow() >= 0:
            to_del = [self._table.item(self._table.currentRow(), 1).data(Qt.ItemDataRole.UserRole)]
        
        if not to_del: return
        from PySide6.QtWidgets import QMessageBox
        if QMessageBox.question(self, "Delete Threats", f"Delete {len(to_del)} selected threat(s)?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            for t in to_del:
                self._register.remove_threat(t.threat_id)
            if to_del:
                self.threat_removed.emit(to_del[-1].threat_id)
            self.refresh()
            self._select_all.setCheckState(Qt.CheckState.Unchecked)

    def _on_cell_clicked(self, row: int, column: int) -> None:
        """Handles explicit clicks on any cell to ensure the threat is selected."""
        self._update_selection_from_row(row)

    def _on_selection_changed(self) -> None:
        """Handles selection changes (clicks or keyboard) to update the Attributes panel."""
        row = self._table.currentRow()
        if row >= 0:
            self._update_selection_from_row(row)

    def _update_selection_from_row(self, row: int) -> None:
        """Extracts the threat from the specified row and emits the selection signal."""
        sl_item = self._table.item(row, 1)
        if sl_item:
            threat = sl_item.data(Qt.ItemDataRole.UserRole)
            if isinstance(threat, Threat):
                self.threat_selected.emit(threat)
