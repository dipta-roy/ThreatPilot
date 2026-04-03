"""Architecture Editor Dialogs for ThreatPilot.

Provides two separate dialogs:
- EntitiesDialog: Manage architectural entities & nodes with classifications.
- DataFlowDialog: Manage data flow connections, protocols, and mappings.
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
    QLabel,
    QApplication,
)
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtGui import QFont
from threatpilot.core.project_manager import Project
from threatpilot.core.domain_models import Component, Flow
from threatpilot.ui import undo_commands

class EntitiesDialog(QDialog):
    """Dialog for editing architectural entities and nodes."""

    project_modified = Signal()

    def __init__(self, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Entities and Nodes")
        
        screen = QApplication.primaryScreen().availableGeometry()
        width = int(screen.width() * 0.8)
        height = int(screen.height() * 0.7)
        self.resize(width, height)
        self._project = project
        self._undo_stack = undo_stack
        self._is_internal_edit = False
        if self._undo_stack:
             self._undo_stack.indexChanged.connect(self._on_undo_redo_index_changed)
        self._setup_ui()
        self._load_data()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        header_font = QFont("Segoe UI", 12, QFont.Weight.Bold)
        comp_header = QLabel("Architectural Entities & Nodes")
        comp_header.setFont(header_font)
        comp_header.setStyleSheet("color: #58a6ff; margin-bottom: 5px;")
        layout.addWidget(comp_header)

        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels([
            "Entity Name",
            "Classification",
            "Asset Category",
            "Asset Type / OS",
            "Asset Description",
            "High Value?",
            "Criticality Description"
        ])
        self._table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 200)
        self._table.setColumnWidth(1, 150)
        self._table.setColumnWidth(2, 150)
        self._table.setColumnWidth(3, 150)
        self._table.setColumnWidth(4, 300)
        self._table.setColumnWidth(5, 100)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._table)
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
        layout.addLayout(comp_btns)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_data(self) -> None:
        self._table.blockSignals(True)
        self._table.setRowCount(0)
        for row, comp in enumerate(self._project.components):
            self._table.insertRow(row)
            name_item = QTableWidgetItem(comp.name)
            name_item.setData(Qt.ItemDataRole.UserRole, comp)
            self._table.setItem(row, 0, name_item)
            elem_combo = QComboBox()
            elem_types = ["Entity", "Process", "DataStore", "DataFlow"]
            elem_combo.addItems(elem_types)
            elem_combo.setCurrentText(comp.element_classification)
            elem_combo.setProperty("row", row)
            elem_combo.currentTextChanged.connect(self._on_element_classification_changed)
            self._table.setCellWidget(row, 1, elem_combo)
            asset_combo = QComboBox()
            asset_types = ["Physical", "Informational"]
            asset_combo.addItems(asset_types)
            asset_combo.setCurrentText(comp.asset_classification)
            asset_combo.setProperty("row", row)
            asset_combo.currentTextChanged.connect(self._on_asset_classification_changed)
            self._table.setCellWidget(row, 2, asset_combo)
            type_item = QTableWidgetItem(comp.type)
            self._table.setItem(row, 3, type_item)
            desc_item = QTableWidgetItem(comp.description)
            self._table.setItem(row, 4, desc_item)
            hva_item = QTableWidgetItem()
            hva_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            hva_item.setCheckState(Qt.CheckState.Checked if comp.is_high_value_asset else Qt.CheckState.Unchecked)
            self._table.setItem(row, 5, hva_item)
            crit_item = QTableWidgetItem(comp.criticality_description)
            self._table.setItem(row, 6, crit_item)
        self._table.blockSignals(False)

    def _on_undo_redo_index_changed(self, index: int) -> None:
        """Reload the table when an undo/redo takes place."""
        if not self._is_internal_edit:
            QTimer.singleShot(0, self._load_data)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        row = item.row()
        name_item = self._table.item(row, 0)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp:
                field = ""
                if item.column() == 0: field = "name"
                elif item.column() == 3: field = "type"
                elif item.column() == 4: field = "description"
                elif item.column() == 5: field = "is_high_value_asset"
                elif item.column() == 6: field = "criticality_description"
                
                if field:
                    new_val = item.text().strip()
                    if field == "is_high_value_asset":
                        new_val = (item.checkState() == Qt.CheckState.Checked)

                    old_val = getattr(comp, field)
                    if new_val != old_val:
                        if self._undo_stack:
                            self._is_internal_edit = True
                            cmd = undo_commands.PropertyUpdateCommand(comp, field, old_val, new_val)
                            self._undo_stack.push(cmd)
                            self._is_internal_edit = False
                        else:
                            setattr(comp, field, new_val)
                        
                        self.project_modified.emit()

    def _on_element_classification_changed(self, new_val: str) -> None:
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 0)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp: 
                old_val = comp.element_classification
                if new_val != old_val:
                    if self._undo_stack:
                        self._is_internal_edit = True
                        cmd = undo_commands.PropertyUpdateCommand(comp, "element_classification", old_val, new_val)
                        self._undo_stack.push(cmd)
                        self._is_internal_edit = False
                    else:
                        comp.element_classification = new_val
                    self.project_modified.emit()

    def _on_asset_classification_changed(self, new_val: str) -> None:
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 0)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp: 
                old_val = comp.asset_classification
                if new_val != old_val:
                    if self._undo_stack:
                        self._is_internal_edit = True
                        cmd = undo_commands.PropertyUpdateCommand(comp, "asset_classification", old_val, new_val)
                        self._undo_stack.push(cmd)
                        self._is_internal_edit = False
                    else:
                        comp.asset_classification = new_val
                    self.project_modified.emit()

    def _on_delete_selected(self) -> None:
        row = self._table.currentRow()
        if row >= 0:
            name_item = self._table.item(row, 0)
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp:
                if self._undo_stack:
                    cmd = undo_commands.DeleteComponentCommand(self._project, comp)
                    self._undo_stack.push(cmd)
                else:
                    if comp in self._project.components:
                        self._project.components.remove(comp)
                self.project_modified.emit()
                self._load_data()

    def _on_add_component(self) -> None:
        new_comp = Component(name="New Component", x=100, y=100)
        if self._undo_stack:
            cmd = undo_commands.AddComponentCommand(self._project, new_comp)
            self._undo_stack.push(cmd)
        else:
            self._project.components.append(new_comp)
        self.project_modified.emit()
        self._load_data()


class DataFlowDialog(QDialog):
    """Dialog for editing data flow connections and protocols."""

    project_modified = Signal()

    def __init__(self, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Data Flow Mapping")
        self.resize(1000, 600)
        self._project = project
        self._undo_stack = undo_stack
        self._is_internal_edit = False
        
        if self._undo_stack:
             self._undo_stack.indexChanged.connect(self._on_undo_redo_index_changed)

        self._setup_ui()
        self._load_data()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        header_font = QFont("Segoe UI", 12, QFont.Weight.Bold)
        flow_header = QLabel("Data Flow Mapping & Protocols")
        flow_header.setFont(header_font)
        flow_header.setStyleSheet("color: #58a6ff; margin-bottom: 5px;")
        layout.addWidget(flow_header)
        self._flow_table = QTableWidget(0, 4)
        self._flow_table.setHorizontalHeaderLabels(["Flow Alias", "Source Entity", "Destination Entity", "Protocol / Port"])
        self._flow_table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._flow_table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._flow_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        header = self._flow_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._flow_table.setColumnWidth(1, 280)
        self._flow_table.setColumnWidth(2, 280)
        self._flow_table.setColumnWidth(3, 160)
        self._flow_table.setAlternatingRowColors(True)
        self._flow_table.verticalHeader().setDefaultSectionSize(38)
        layout.addWidget(self._flow_table)
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
        layout.addLayout(flow_btns)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_data(self) -> None:
        self._flow_table.blockSignals(True)
        self._flow_table.setRowCount(0)
        comp_names = ["(Unlinked)"] + [c.name for c in self._project.components]
        for row, flow in enumerate(self._project.flows):
            self._flow_table.insertRow(row)
            name_item = QTableWidgetItem(flow.name)
            name_item.setData(Qt.ItemDataRole.UserRole, flow)
            self._flow_table.setItem(row, 0, name_item)
            src_combo = QComboBox()
            src_combo.addItems(comp_names)
            src_name = self._get_comp_name_by_id(flow.source_id)
            src_combo.setCurrentText(src_name or "(Unlinked)")
            src_combo.currentTextChanged.connect(lambda val, f=flow: self._update_flow_source(f, val))
            self._flow_table.setCellWidget(row, 1, src_combo)
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
        old_val = flow.source_id
        new_val = self._get_comp_id_by_name(name)
        if new_val != old_val:
            if self._undo_stack:
                self._is_internal_edit = True
                cmd = undo_commands.PropertyUpdateCommand(flow, "source_id", old_val, new_val)
                self._undo_stack.push(cmd)
                self._is_internal_edit = False
            else:
                flow.source_id = new_val
            self.project_modified.emit()

    def _update_flow_target(self, flow, name):
        old_val = flow.target_id
        new_val = self._get_comp_id_by_name(name)
        if new_val != old_val:
            if self._undo_stack:
                self._is_internal_edit = True
                cmd = undo_commands.PropertyUpdateCommand(flow, "target_id", old_val, new_val)
                self._undo_stack.push(cmd)
                self._is_internal_edit = False
            else:
                flow.target_id = new_val
            self.project_modified.emit()

    def _on_delete_selected_flow(self) -> None:
        row = self._flow_table.currentRow()
        if row >= 0:
            name_item = self._flow_table.item(row, 0)
            flow = name_item.data(Qt.ItemDataRole.UserRole)
            if flow:
                if self._undo_stack:
                    cmd = undo_commands.DeleteFlowCommand(self._project, flow)
                    self._undo_stack.push(cmd)
                else:
                    if flow in self._project.flows:
                        self._project.flows.remove(flow)
                self.project_modified.emit()
                self._load_data()

    def _on_add_flow(self) -> None:
        new_flow = Flow(name="Manual Flow", protocol="HTTPS")
        if self._undo_stack:
            cmd = undo_commands.AddFlowCommand(self._project, new_flow)
            self._undo_stack.push(cmd)
        else:
            self._project.flows.append(new_flow)
        self.project_modified.emit()
        self._load_data()

    def _on_undo_redo_index_changed(self, index: int) -> None:
        """Reload the table when an undo/redo takes place."""
        if not self._is_internal_edit:
            QTimer.singleShot(0, self._load_data)

    def _on_flow_item_changed(self, item: QTableWidgetItem) -> None:
        row = item.row()
        name_item = self._flow_table.item(row, 0)
        if not name_item: return
        flow = name_item.data(Qt.ItemDataRole.UserRole)
        if not flow: return

        field = ""
        if item.column() == 0: field = "name"
        elif item.column() == 3: field = "protocol"

        if field:
            new_val = item.text().strip()
            old_val = getattr(flow, field)
            if new_val != old_val:
                if self._undo_stack:
                    self._is_internal_edit = True
                    cmd = undo_commands.PropertyUpdateCommand(flow, field, old_val, new_val)
                    self._undo_stack.push(cmd)
                    self._is_internal_edit = False
                else:
                    setattr(flow, field, new_val)
                self.project_modified.emit()

ArchitectureDialog = EntitiesDialog