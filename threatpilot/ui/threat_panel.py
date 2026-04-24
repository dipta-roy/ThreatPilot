"""Threat panel module for ThreatPilot.

Provides a ``QTreeWidget`` based panel to display and manage identified threats.
Groups threats by STRIDE category and supports selection/editing.
"""

from __future__ import annotations
from typing import Dict, List, Optional
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLineEdit,
    QPushButton,
    QTreeWidget,
     QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from threatpilot.core.threat_model import STRIDECategory, Threat, ThreatRegister

class ThreatPanel(QWidget):
    """Panel for viewing and managing identified threats.

    Displays threats in a hierarchical view grouped by STRIDE category.

    Signals:
        threat_selected: Emitted when a threat item is clicked. Carries the
            ``Threat`` object.
        run_analysis_requested: Emitted when the "Run Analysis" button is clicked.
    """

    threat_selected: Signal = Signal(object)
    threat_added: Signal = Signal(object)
    threat_removed: Signal = Signal(str)
    run_analysis_requested: Signal = Signal(str)

    def __init__(self, parent: QWidget | None = None, filter_mode: str = "ALL") -> None:
        super().__init__(parent)
        self._register: Optional[ThreatRegister] = None
        self._category_items: Dict[STRIDECategory, QTreeWidgetItem] = {}
        self._filter_mode = filter_mode.upper()

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Initialise tree widget and control buttons."""
        self.setObjectName("threat_panel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.setSpacing(10)
        toolbar_layout = QHBoxLayout()
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Filter threats...")
        self._search_input.setFixedWidth(250)
        self._search_input.textChanged.connect(lambda: self.refresh())
        toolbar_layout.addWidget(self._search_input)

        self._btn_add = QPushButton("Add Manual Threat")
        self._btn_add.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_add.clicked.connect(self._on_add_threat)
        toolbar_layout.addWidget(self._btn_add)

        self._btn_delete = QPushButton("Delete Selected")
        self._btn_delete.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_delete.clicked.connect(self._on_delete_threat)
        toolbar_layout.addWidget(self._btn_delete)
        
        btn_text = "Run AI Analysis"
        if self._filter_mode == "STRIDE":
            btn_text = "Run STRIDE Analysis"
        elif self._filter_mode == "LINDDUN":
            btn_text = "Run LINDDUN Analysis"
            
        self._btn_run = QPushButton(btn_text)
        self._btn_run.setObjectName("btn_run_threat_analysis")
        self._btn_run.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_run.setStyleSheet("background-color: #238636; color: white; font-weight: bold;")
        self._btn_run.clicked.connect(lambda: self.run_analysis_requested.emit(self._filter_mode))
        toolbar_layout.addWidget(self._btn_run)
        
        toolbar_layout.addStretch()
        layout.addLayout(toolbar_layout)

        self._btn_add.setEnabled(False)
        self._btn_delete.setEnabled(False)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["REF ID", "SEVERITY", "VULNERABILITY TITLE"])
        self._tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._tree.header().resizeSection(0, 100)
        self._tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        self._tree.header().resizeSection(1, 110)
        self._tree.header().setStretchLastSection(True)
        self._tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._tree.setAlternatingRowColors(True)
        self._tree.setIndentation(15)
        self._tree.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._tree.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._tree.itemClicked.connect(self._on_item_clicked)
        layout.addWidget(self._tree)
        self.setEnabled(False)

    def set_theme(self, is_dark: bool) -> None:
        """Update the panel's internal state for theme changes."""
        self._is_dark_theme = is_dark
        self.refresh()

    def set_register(self, register: Optional[ThreatRegister]) -> None:
        """Load the threat list from the register into the tree."""
        self._register = register
        
        has_reg = register is not None
        self.setEnabled(has_reg)
        
        if has_reg:
            self._btn_add.setEnabled(True)
            self._btn_delete.setEnabled(True)
        
        self.refresh()

    def clear_filter(self) -> None:
        """Reset search filters and show all results."""
        self._search_input.clear()
        self.refresh()

    def refresh(self) -> None:
        """Clear and rebuild the tree from the current register."""
        self._tree.clear()
        self._category_items.clear()

        if self._register is None:
            return

        header_font = self._tree.font()
        header_font.setBold(True)
        is_dark = getattr(self, "_is_dark_theme", True)
        
        STRIDE_ONLY = {
            STRIDECategory.SPOOFING, STRIDECategory.TAMPERING, 
            STRIDECategory.REPUDIATION, STRIDECategory.INFORMATION_DISCLOSURE, 
            STRIDECategory.DENIAL_OF_SERVICE, STRIDECategory.ELEVATION_OF_PRIVILEGE
        }
        LINDDUN_ONLY = {
            STRIDECategory.LINKABILITY, STRIDECategory.IDENTIFIABILITY, 
            STRIDECategory.NON_REPUDIATION_PRIVACY, STRIDECategory.DETECTABILITY, 
            STRIDECategory.DISCLOSURE_OF_INFORMATION, STRIDECategory.UNAWARENESS, 
            STRIDECategory.NON_COMPLIANCE
        }

        for cat in STRIDECategory:
            if self._filter_mode == "STRIDE" and cat not in STRIDE_ONLY:
                continue
            if self._filter_mode == "LINDDUN" and cat not in LINDDUN_ONLY:
                continue
                
            base_name = cat.name.upper().replace("_PRIVACY", "")
            cat_item = QTreeWidgetItem(self._tree, [f"[0] {base_name}", "", ""])
            cat_item.setFlags(cat_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            cat_item.setFirstColumnSpanned(True)
            cat_item.setFont(0, header_font)
            
            if is_dark:
                for col in range(3):
                    cat_item.setBackground(col, QColor("#21262d"))
                cat_item.setForeground(0, QColor("#58a6ff"))
            else:
                for col in range(3):
                    cat_item.setBackground(col, QColor("#f6f8fa"))
                cat_item.setForeground(0, QColor("#0969da"))
                
            cat_item.setExpanded(True)
            self._category_items[cat] = cat_item

        search_text = self._search_input.text().strip().lower()

        for threat in self._register.threats:
            if search_text:
                sev_label = self._get_severity_label(threat.cvss_score).lower()
                matches_search = (
                    search_text in threat.title.lower() or
                    search_text in threat.description.lower() or
                    search_text in threat.vulnerabilities.lower() or
                    search_text in threat.category.value.lower() or
                    search_text in threat.affected_components.lower() or
                    search_text in sev_label
                )
                if not matches_search:
                    continue

            target_cat = threat.category
            if isinstance(target_cat, str):
                for member in STRIDECategory:
                    if target_cat.lower() == member.value.lower():
                        target_cat = member
                        break
                        
            parent = self._category_items.get(target_cat)
            if parent:
                sev_label = self._get_severity_label(threat.cvss_score)
                threat_item = QTreeWidgetItem(parent, [
                    threat.threat_id[:8],
                    sev_label,
                    threat.title
                ])
                
                is_dark = getattr(self, "_is_dark_theme", True)
                if is_dark:
                    if sev_label == "CRITICAL":
                        threat_item.setBackground(1, QColor("#cc0000"))
                        threat_item.setForeground(1, QColor("white"))
                    elif sev_label == "HIGH":
                        threat_item.setBackground(1, QColor("#f97583"))
                        threat_item.setForeground(1, QColor("white"))
                    elif sev_label == "MEDIUM":
                        threat_item.setBackground(1, QColor("#e3b341"))
                        threat_item.setForeground(1, QColor("white"))
                    elif sev_label == "LOW":
                        threat_item.setBackground(1, QColor("#1f6feb"))
                        threat_item.setForeground(1, QColor("white"))
                else:
                    if sev_label == "CRITICAL":
                        threat_item.setBackground(1, QColor("#ffebe9"))
                        threat_item.setForeground(1, QColor("#cf222e"))
                    elif sev_label == "HIGH":
                        threat_item.setBackground(1, QColor("#fff1e5"))
                        threat_item.setForeground(1, QColor("#af4e00"))
                    elif sev_label == "MEDIUM":
                        threat_item.setBackground(1, QColor("#fff8c5"))
                        threat_item.setForeground(1, QColor("#9a6700"))
                    elif sev_label == "LOW":
                        threat_item.setBackground(1, QColor("#ddf4ff"))
                        threat_item.setForeground(1, QColor("#0969da"))
                threat_item.setData(0, Qt.ItemDataRole.UserRole, threat)

                if threat.is_accepted_risk:
                    threat_item.setForeground(1, Qt.GlobalColor.gray)
                    threat_item.setText(2, f"[Accepted] {threat.title}")

        for cat in STRIDECategory:
            cat_item = self._category_items.get(cat)
            if not cat_item:
                continue

            count = cat_item.childCount()
            if count > 0:
                cat_item.setHidden(False)
                base_name = cat.name.upper().replace("_PRIVACY", "")
                cat_item.setText(0, f"[{count}] {base_name}")
            else:
                cat_item.setHidden(True)

    def _get_severity_label(self, score: float) -> str:
        """Map a numeric CVSS score to a qualitative severity label."""
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score > 0:    return "LOW"
        return "NONE"

    def _on_add_threat(self) -> None:
        """Create a new manual threat and add it to the register."""
        if self._register is None:
            return

        new_threat = Threat(title="New Identified Risk", category=STRIDECategory.TAMPERING)
        self._register.add_threat(new_threat, skip_duplicates=False)
        self.refresh()
        
        self.threat_added.emit(new_threat)
        self.threat_selected.emit(new_threat)

    def _on_delete_threat(self) -> None:
        """Remove the currently selected threat from the register."""
        item = self._tree.currentItem()
        if not item:
            return

        threat = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(threat, Threat) and self._register:
            self._register.remove_threat(threat.threat_id)
            self.refresh()
            self.threat_removed.emit(threat.threat_id)

    def _on_item_clicked(self, item: QTreeWidgetItem, column: int) -> None:
        """Handle selection of a threat item and emit signal."""
        threat = item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(threat, Threat):
            self.threat_selected.emit(threat)
