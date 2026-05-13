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
    """Panel for viewing and managing identified threats.

    Displays threats in a flat table view with columns for category, severity,
    title, affected component, and CVSS score.

    Signals:
        threat_selected: Emitted when a threat row is clicked. Carries the
            ``Threat`` object.
        run_analysis_requested: Emitted when the "Run Analysis" button is clicked.
    """

    threat_selected: Signal = Signal(object)
    threat_added: Signal = Signal(object)
    threat_removed: Signal = Signal(str)
    run_analysis_requested: Signal = Signal(str)
    reasoning_requested: Signal = Signal(object)

    def __init__(self, parent: QWidget | None = None, filter_mode: str = "ALL") -> None:
        super().__init__(parent)
        self._register: Optional[ThreatRegister] = None
        self._filter_mode = filter_mode.upper()
        self._is_dark_theme: bool = False
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------
    def _setup_ui(self) -> None:
        """Initialise table widget and control buttons."""
        self.setObjectName("threat_panel")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 12, 8, 8)
        layout.setSpacing(10)

        # --- Toolbar ---
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

        # --- Summary label ---
        self._summary_label = QLabel("")
        self._summary_label.setObjectName("threat_summary_label")
        layout.addWidget(self._summary_label)

        # --- Table ---
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels([
            "SL #",
            "Category",
            "Severity",
            "Threat Title",
            "Affected Component",
            "CVSS Score",
        ])

        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self._table.setColumnWidth(1, 160)
        self._table.setColumnWidth(2, 100)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self._table.setColumnWidth(4, 200)
        self._table.setColumnWidth(5, 100)

        self._table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self._table.itemClicked.connect(self._on_item_clicked)
        layout.addWidget(self._table)

        self.setEnabled(False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def set_theme(self, is_dark: bool) -> None:
        """Update the panel's internal state for theme changes."""
        self._is_dark_theme = is_dark
        self.refresh()

    def set_register(self, register: Optional[ThreatRegister]) -> None:
        """Load the threat list from the register into the table."""
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
        """Clear and rebuild the table from the current register."""
        # ── Preserve scroll & selection ──
        v_scroll = self._table.verticalScrollBar().value()
        h_scroll = self._table.horizontalScrollBar().value()
        prev_row = self._table.currentRow()

        self._table.setRowCount(0)

        if self._register is None:
            self._summary_label.setText("")
            return

        is_dark = self._is_dark_theme
        search_text = self._search_input.text().strip().lower()

        # Determine which threats to show
        visible_threats: list[Threat] = []
        category_counts: Dict[str, int] = {}

        for threat in self._register.threats:
            # Filter by framework mode
            target_cat = self._resolve_category(threat.category)
            if self._filter_mode == "STRIDE" and target_cat not in STRIDE_CATEGORIES:
                continue
            if self._filter_mode == "LINDDUN" and target_cat not in LINDDUN_CATEGORIES:
                continue

            # Filter by search text
            if search_text:
                sev_label = self._get_severity_label(threat.cvss_score).lower()
                vuln_search_text = " ".join(getattr(threat, "vulnerability_ids", []))

                matches_search = (
                    search_text in threat.title.lower()
                    or search_text in threat.description.lower()
                    or search_text in vuln_search_text.lower()
                    or search_text in threat.category.value.lower()
                    or search_text in threat.affected_components.lower()
                    or search_text in sev_label
                )
                if not matches_search:
                    continue

            visible_threats.append(threat)
            cat_name = target_cat.name.upper().replace("_PRIVACY", "")
            category_counts[cat_name] = category_counts.get(cat_name, 0) + 1

        # Build summary
        parts = [f"{name}: {count}" for name, count in sorted(category_counts.items())]
        total = len(visible_threats)
        summary = f"{total} threat{'s' if total != 1 else ''}"
        if parts:
            summary += f"  •  {' | '.join(parts)}"
        self._summary_label.setText(summary)

        # Populate table
        self._table.setRowCount(len(visible_threats))
        bold_font = QFont()
        bold_font.setBold(True)

        for row, threat in enumerate(visible_threats):
            target_cat = self._resolve_category(threat.category)
            sev_label = self._get_severity_label(threat.cvss_score)
            cat_name = target_cat.name.upper().replace("_PRIVACY", "")

            # SL #
            sl_item = QTableWidgetItem(str(row + 1))
            sl_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            sl_item.setData(Qt.ItemDataRole.UserRole, threat)
            self._table.setItem(row, 0, sl_item)

            # Category
            cat_item = QTableWidgetItem(cat_name)
            cat_item.setFont(bold_font)
            if is_dark:
                cat_item.setForeground(QColor("#58a6ff"))
            else:
                cat_item.setForeground(QColor("#0969da"))
            self._table.setItem(row, 1, cat_item)

            # Severity (coloured table item)
            sev_item = QTableWidgetItem(sev_label)
            sev_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            sev_item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            bg, fg = self._severity_colors(sev_label, is_dark)
            sev_item.setBackground(bg)
            sev_item.setForeground(fg)
            self._table.setItem(row, 2, sev_item)

            # Title
            title_text = threat.title
            if threat.is_accepted_risk:
                title_text = f"[Accepted] {threat.title}"
            title_item = QTableWidgetItem(title_text)
            if threat.is_accepted_risk:
                title_item.setForeground(QColor(Qt.GlobalColor.gray))
            self._table.setItem(row, 3, title_item)

            # Affected Component
            self._table.setItem(row, 4, QTableWidgetItem(threat.affected_components or "N/A"))

            # CVSS Score
            score_item = QTableWidgetItem(f"{threat.cvss_score:.1f}")
            score_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self._table.setItem(row, 5, score_item)



        # ── Restore scroll & selection ──
        if prev_row >= 0 and prev_row < self._table.rowCount():
            self._table.selectRow(prev_row)
        self._table.verticalScrollBar().setValue(v_scroll)
        self._table.horizontalScrollBar().setValue(h_scroll)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_category(category) -> STRIDECategory:
        """Normalise a category value to a ``STRIDECategory`` enum member."""
        if isinstance(category, STRIDECategory):
            return category
        if isinstance(category, str):
            for member in STRIDECategory:
                if category.lower() == member.value.lower():
                    return member
        return STRIDECategory.TAMPERING  # fallback

    @staticmethod
    def _get_severity_label(score: float) -> str:
        """Map a numeric CVSS score to a qualitative severity label."""
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0:
            return "LOW"
        return "NONE"

    @staticmethod
    def _severity_colors(sev_label: str, is_dark: bool) -> tuple:
        """Return (background QColor, foreground QColor) for the severity level."""
        if is_dark:
            colors = {
                "CRITICAL": (QColor("#7b1e1e"), QColor("white")),
                "HIGH": (QColor("#cc0000"), QColor("white")),
                "MEDIUM": (QColor("#e3b341"), QColor("white")),
                "LOW": (QColor("#1f6feb"), QColor("white")),
            }
            default = (QColor("#30363d"), QColor("white"))
        else:
            colors = {
                "CRITICAL": (QColor("#cf222e"), QColor("white")),
                "HIGH": (QColor("#af4e00"), QColor("white")),
                "MEDIUM": (QColor("#9a6700"), QColor("white")),
                "LOW": (QColor("#0969da"), QColor("white")),
            }
            default = (QColor("#f6f8fa"), QColor("#57606a"))
        return colors.get(sev_label, default)

    # ------------------------------------------------------------------
    # Slots
    # ------------------------------------------------------------------
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
        row = self._table.currentRow()
        if row < 0:
            return

        item = self._table.item(row, 0)
        if not item:
            return
        threat = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(threat, Threat) and self._register:
            self._register.remove_threat(threat.threat_id)
            self.refresh()
            self.threat_removed.emit(threat.threat_id)

    def _on_item_clicked(self, item: QTableWidgetItem) -> None:
        """Handle selection of a threat row and emit signal."""
        row = item.row()
        sl_item = self._table.item(row, 0)
        if sl_item:
            threat = sl_item.data(Qt.ItemDataRole.UserRole)
            if isinstance(threat, Threat):
                self.threat_selected.emit(threat)
