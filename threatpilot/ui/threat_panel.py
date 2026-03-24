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

    threat_selected: Signal = Signal(object)  # Threat
    threat_added: Signal = Signal(object)     # Threat
    threat_removed: Signal = Signal(str)      # Threat ID
    run_analysis_requested: Signal = Signal()

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._register: Optional[ThreatRegister] = None
        self._category_items: Dict[STRIDECategory, QTreeWidgetItem] = {}

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Initialise tree widget and control buttons."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Toolbar / Actions area
        self._btn_run = QPushButton("Run Global AI Analysis")
        self._btn_run.setObjectName("btn_run_analysis")
        self._btn_run.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_run.clicked.connect(self.run_analysis_requested.emit)
        layout.addWidget(self._btn_run)

        btn_row = QHBoxLayout()
        self._btn_add = QPushButton("Add Manual Threat")
        self._btn_add.clicked.connect(self._on_add_threat)
        btn_row.addWidget(self._btn_add)

        self._btn_delete = QPushButton("Delete Selected")
        self._btn_delete.clicked.connect(self._on_delete_threat)
        btn_row.addWidget(self._btn_delete)
        layout.addLayout(btn_row)

        # Start disabled (no project)
        self._btn_run.setEnabled(False)
        self._btn_add.setEnabled(False)
        self._btn_delete.setEnabled(False)

        # Filter bar
        filter_layout = QHBoxLayout()
        self._search_input = QLineEdit()
        self._search_input.setPlaceholderText("Filter threats...")
        self._search_input.textChanged.connect(lambda: self.refresh())
        filter_layout.addWidget(self._search_input)
        layout.addLayout(filter_layout)

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
        
        # Selection handling
        self._tree.itemClicked.connect(self._on_item_clicked)
        
        layout.addWidget(self._tree)
        
        self.setEnabled(False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_register(self, register: Optional[ThreatRegister]) -> None:
        """Load the threat list from the register into the tree."""
        self._register = register
        
        has_reg = register is not None
        self.setEnabled(has_reg)
        
        if has_reg:
            self._btn_run.setEnabled(True)
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

        # Prepare STRIDE category headers
        for cat in STRIDECategory:
            cat_item = QTreeWidgetItem(self._tree, [cat.name, cat.value])
            cat_item.setFlags(cat_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            cat_item.setExpanded(True)
            self._category_items[cat] = cat_item

        # Add threats to headers
        search_text = self._search_input.text().strip().lower()

        for threat in self._register.threats:
            # Filtering logic
            if search_text:
                sev_label = self._get_severity_label(threat.cvss_score).lower()
                matches_search = (
                    search_text in threat.title.lower() or
                    search_text in threat.description.lower() or
                    search_text in threat.category.value.lower() or
                    search_text in threat.affected_components.lower() or
                    search_text in sev_label
                )
                if not matches_search:
                    continue

            parent = self._category_items.get(threat.category)
            if parent:
                sev_label = self._get_severity_label(threat.cvss_score)
                threat_item = QTreeWidgetItem(parent, [
                    threat.threat_id[:8],  # short ID
                    sev_label,
                    threat.title
                ])
                
                # Color code severity
                if sev_label == "CRITICAL":
                    threat_item.setForeground(1, QColor("#ff4444"))
                elif sev_label == "HIGH":
                    threat_item.setForeground(1, QColor("#ff8800"))
                elif sev_label == "MEDIUM":
                    threat_item.setForeground(1, QColor("#ffbb33"))
                elif sev_label == "LOW":
                    threat_item.setForeground(1, QColor("#00c851"))
                # Store reference in user data
                threat_item.setData(0, Qt.ItemDataRole.UserRole, threat)

                # Visual state for accepted risks
                if threat.is_accepted_risk:
                    threat_item.setForeground(1, Qt.GlobalColor.gray)
                    threat_item.setText(1, f"[Accepted] {threat.title}")

        # Hide empty categories
        for cat_item in self._category_items.values():
            cat_item.setHidden(cat_item.childCount() == 0)

    def _get_severity_label(self, score: float) -> str:
        """Map a numeric CVSS score to a qualitative severity label."""
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score > 0:    return "LOW"
        return "NONE"

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_add_threat(self) -> None:
        """Create a new manual threat and add it to the register."""
        if self._register is None:
            return

        new_threat = Threat(category=STRIDECategory.TAMPERING)
        self._register.add_threat(new_threat)
        self.refresh()
        
        # Select the new threat
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
