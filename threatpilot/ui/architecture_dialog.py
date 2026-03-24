"""Architecture Editor Dialog for ThreatPilot.

Provides a tabular view of all detected components, allowing the user
to edit their names, types, and positions, or delete them before AI analysis.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QDialogButtonBox,
    QPushButton,
    QHBoxLayout,
    QMessageBox,
    QComboBox,
    QWidget,
    QTabWidget,
    QLabel,
    QSpacerItem,
    QSizePolicy,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from threatpilot.core.project_manager import Project
from threatpilot.core.domain_models import Component, Flow

class ArchitectureDialog(QDialog):
    """Dialog for editing detected architectural components."""

    def __init__(self, project: Project, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Architecture Inventory & Flow Control")
        self.resize(1100, 750)
        self._project = project
        self._setup_ui()
        self._load_data()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        self._tabs = QTabWidget()
        layout.addWidget(self._tabs)

        # Components Tab
        self._comp_tab = QWidget()
        comp_layout = QVBoxLayout(self._comp_tab)
        comp_layout.setContentsMargins(15, 15, 15, 15)
        comp_layout.setSpacing(10)
        
        header_font = QFont("Segoe UI", 12, QFont.Weight.Bold)
        comp_header = QLabel("Architectural Entities & Nodes")
        comp_header.setFont(header_font)
        comp_header.setStyleSheet("color: #58a6ff; margin-bottom: 5px;")
        comp_layout.addWidget(comp_header)
        
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(["Entity Name", "Classification / Type", "Canvas Position (X, Y)", "Width (px)", "Height (px)"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.itemChanged.connect(self._on_item_changed)
        comp_layout.addWidget(self._table)
        
        comp_btns = QHBoxLayout()
        self._btn_add = QPushButton(" + Add New Component")
        self._btn_add.setMinimumHeight(35)
        self._btn_add.clicked.connect(self._on_add_component)
        comp_btns.addWidget(self._btn_add)
        
        self._btn_del_comp = QPushButton(" x Remove Selected")
        self._btn_del_comp.setMinimumHeight(35)
        self._btn_del_comp.clicked.connect(self._on_delete_selected)
        comp_btns.addWidget(self._btn_del_comp)
        
        comp_btns.addStretch()
        comp_layout.addLayout(comp_btns)
        
        self._tabs.addTab(self._comp_tab, "Entities & Nodes")

        # Flows Tab
        self._flow_tab = QWidget()
        flow_layout = QVBoxLayout(self._flow_tab)
        flow_layout.setContentsMargins(15, 15, 15, 15)
        flow_layout.setSpacing(10)
        
        flow_header = QLabel("Data Flow Mapping & Protocols")
        flow_header.setFont(header_font)
        flow_header.setStyleSheet("color: #58a6ff; margin-bottom: 5px;")
        flow_layout.addWidget(flow_header)
        
        self._flow_table = QTableWidget(0, 4)
        self._flow_table.setHorizontalHeaderLabels(["Flow Alias", "Source Entity", "Destination Entity", "Protocol / Port"])
        
        header = self._flow_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        self._flow_table.setColumnWidth(1, 220)
        self._flow_table.setColumnWidth(2, 220)
        
        self._flow_table.setAlternatingRowColors(True)
        flow_layout.addWidget(self._flow_table)
        
        flow_btns = QHBoxLayout()
        self._btn_add_flow = QPushButton(" + Create Manual Flow")
        self._btn_add_flow.setMinimumHeight(35)
        self._btn_add_flow.clicked.connect(self._on_add_flow)
        flow_btns.addWidget(self._btn_add_flow)
        
        self._btn_del_flow = QPushButton(" x Delete Flow Connection")
        self._btn_del_flow.setMinimumHeight(35)
        self._btn_del_flow.clicked.connect(self._on_delete_selected_flow)
        flow_btns.addWidget(self._btn_del_flow)
        
        flow_btns.addStretch()
        flow_layout.addLayout(flow_btns)
        
        self._tabs.addTab(self._flow_tab, "Data Flows")

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_data(self) -> None:
        """Populate the tables with project components and flows."""
        self._table.blockSignals(True)
        self._table.setRowCount(0)
        for row, comp in enumerate(self._project.components):
            self._table.insertRow(row)
            name_item = QTableWidgetItem(comp.name)
            name_item.setData(Qt.ItemDataRole.UserRole, comp)
            self._table.setItem(row, 0, name_item)
            
            combo = QComboBox()
            valid_types = ["Service", "Datastore", "Asset", "Trustboundary"]
            combo.addItems(valid_types)
            combo.setCurrentText(comp.type)
            combo.setProperty("row", row)
            combo.currentTextChanged.connect(self._on_type_changed)
            self._table.setCellWidget(row, 1, combo)
            
            self._table.setItem(row, 2, QTableWidgetItem(f"{int(comp.x)}, {int(comp.y)}"))
            self._table.setItem(row, 3, QTableWidgetItem(str(int(comp.width))))
            self._table.setItem(row, 4, QTableWidgetItem(str(int(comp.height))))
        self._table.blockSignals(False)

        # Load Flows
        self._flow_table.blockSignals(True)
        self._flow_table.setRowCount(0)
        comp_names = ["(Unlinked)"] + [c.name for c in self._project.components]
        for row, flow in enumerate(self._project.flows):
            self._flow_table.insertRow(row)
            
            name_item = QTableWidgetItem(flow.name)
            name_item.setData(Qt.ItemDataRole.UserRole, flow)
            self._flow_table.setItem(row, 0, name_item)
            
            # Source
            src_combo = QComboBox()
            src_combo.addItems(comp_names)
            src_name = self._get_comp_name_by_id(flow.source_id)
            src_combo.setCurrentText(src_name or "(Unlinked)")
            src_combo.currentTextChanged.connect(lambda val, f=flow: self._update_flow_source(f, val))
            self._flow_table.setCellWidget(row, 1, src_combo)
            
            # Target
            dst_combo = QComboBox()
            dst_combo.addItems(comp_names)
            dst_name = self._get_comp_name_by_id(flow.target_id)
            dst_combo.setCurrentText(dst_name or "(Unlinked)")
            dst_combo.currentTextChanged.connect(lambda val, f=flow: self._update_flow_target(f, val))
            self._flow_table.setCellWidget(row, 2, dst_combo)
            
            proto_item = QTableWidgetItem(flow.protocol)
            proto_item.setData(Qt.ItemDataRole.UserRole, flow)
            self._flow_table.setItem(row, 3, proto_item)
            
        self._flow_table.itemChanged.connect(self._on_flow_item_changed)
        self._flow_table.blockSignals(False)

    def _get_comp_name_by_id(self, cid: str) -> str:
        for c in self._project.components:
            if c.component_id == cid: return c.name
        return ""

    def _get_comp_id_by_name(self, name: str) -> str:
        for c in self._project.components:
            if c.name == name: return c.component_id
        return ""

    def _update_flow_source(self, flow, name):
        flow.source_id = self._get_comp_id_by_name(name)
        
    def _update_flow_target(self, flow, name):
        flow.target_id = self._get_comp_id_by_name(name)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        row = item.row()
        name_item = self._table.item(row, 0)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp and item.column() == 0:
                comp.name = item.text().strip()

    def _on_type_changed(self, new_type: str) -> None:
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 0)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp: comp.type = new_type

    def _on_delete_selected(self) -> None:
        row = self._table.currentRow()
        if row >= 0:
            name_item = self._table.item(row, 0)
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp in self._project.components:
                self._project.components.remove(comp)
            self._load_data()

    def _on_delete_selected_flow(self) -> None:
        """Remove the selected flow from the project."""
        row = self._flow_table.currentRow()
        if row >= 0:
            name_item = self._flow_table.item(row, 0)
            flow = name_item.data(Qt.ItemDataRole.UserRole)
            if flow in self._project.flows:
                self._project.flows.remove(flow)
            self._load_data()

    def _on_add_component(self) -> None:
        new_comp = Component(name="New Component", x=100, y=100)
        self._project.components.append(new_comp)
        self._load_data()

    def _on_add_flow(self) -> None:
        """Add a blank manual flow to the project."""
        new_flow = Flow(name="Manual Flow", protocol="HTTPS")
        self._project.flows.append(new_flow)
        self._load_data()

    def _on_flow_item_changed(self, item: QTableWidgetItem) -> None:
        """Track edits to flow name (col 0) and protocol (col 3)."""
        row = item.row()
        name_item = self._flow_table.item(row, 0)
        if not name_item: return
        flow = name_item.data(Qt.ItemDataRole.UserRole)
        if not flow: return

        if item.column() == 0:
            flow.name = item.text().strip()
        elif item.column() == 3:
            flow.protocol = item.text().strip()
