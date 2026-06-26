"""Architecture Editor Dialogs for ThreatPilot.

Provides separate dialogs for managing architectural elements, assets, and data flows.
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
from PySide6.QtGui import QFont, QColor, QUndoCommand
from threatpilot.core.project_manager import Project
from threatpilot.core.domain_models import Component, Flow, TrustBoundary, ElementType, AssetType
from threatpilot.ui import undo_commands

class BaseProjectTableDialog(QDialog):
    """Base class for project-related table dialogs to reduce code duplication.
    
    Handles window setup, undo stack integration, scroll persistence,
    and common UI patterns like 'Select All' and bulk deletion.
    """
    project_modified = Signal()

    def __init__(self, title: str, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self._project = project
        self._undo_stack = undo_stack
        self._is_internal_edit = False
        
        self._setup_window_size()
        
        if self._undo_stack:
             self._undo_stack.indexChanged.connect(self._on_undo_redo_index_changed)

    def _setup_window_size(self, width_factor=0.6, height_factor=0.6) -> None:
        screen = QApplication.primaryScreen().availableGeometry()
        width = int(screen.width() * width_factor)
        height = int(screen.height() * height_factor)
        self.resize(width, height)
        self.setSizeGripEnabled(True)

    def _on_undo_redo_index_changed(self, index: int) -> None:
        if not self._is_internal_edit:
            QTimer.singleShot(0, self._load_data)

    def _load_data_generic(self, items: list, column_mappers: dict):
        """Generic table loader.
        
        column_mappers: {col_idx: (attr_name, editable, is_checkbox)}
        """
        self._table.blockSignals(True)
        self._table.setRowCount(len(items))
        
        for row, obj in enumerate(items):
            # Selection Checkbox (Column 0)
            chk_item = QTableWidgetItem("")
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            chk_item.setCheckState(Qt.CheckState.Unchecked)
            self._table.setItem(row, 0, chk_item)
            
            for col, (attr, editable, is_bool) in column_mappers.items():
                val = getattr(obj, attr)
                if is_bool:
                    chk = QTableWidgetItem("")
                    chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
                    chk.setCheckState(Qt.CheckState.Checked if val else Qt.CheckState.Unchecked)
                    self._table.setItem(row, col, chk)
                else:
                    item = QTableWidgetItem(str(val) if val is not None else "")
                    if not editable:
                        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    item.setData(Qt.ItemDataRole.UserRole, obj)
                    self._table.setItem(row, col, item)
        self._table.blockSignals(False)

    def _on_item_changed_generic(self, item: QTableWidgetItem, field_map: dict):
        """Generic item change handler for undo support."""
        if self._is_internal_edit: return
        
        row = item.row()
        col = item.column()
        if col not in field_map: return
        
        field, is_bool = field_map[col]
        obj = self._table.item(row, 1 if col != 1 else 1).data(Qt.ItemDataRole.UserRole)
        if not obj: return
        
        new_val = (item.checkState() == Qt.CheckState.Checked) if is_bool else item.text()
        old_val = getattr(obj, field)
        
        if new_val != old_val:
            self._update_property(obj, field, new_val, old_val)

    def _update_property(self, obj, field, new_val, old_val=None):
        """Helper to update a property with undo support."""
        if old_val is None:
            old_val = getattr(obj, field)
            
        if new_val != old_val:
            if self._undo_stack:
                self._is_internal_edit = True
                cmd = undo_commands.PropertyUpdateCommand(obj, field, old_val, new_val)
                self._undo_stack.push(cmd)
                self._is_internal_edit = False
            else:
                setattr(obj, field, new_val)
            self.project_modified.emit()

    def _on_select_all(self, checked: bool, table: QTableWidget) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        table.blockSignals(True)
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item:
                item.setCheckState(state)
        table.blockSignals(False)

    def _get_selected_items(self, table: QTableWidget, data_role=Qt.ItemDataRole.UserRole):
        """Retrieve data objects for all rows with a checked first column."""
        items = []
        for row in range(table.rowCount()):
            chk_item = table.item(row, 0)
            if chk_item and chk_item.checkState() == Qt.CheckState.Checked:
                name_item = table.item(row, 1)
                obj = name_item.data(data_role)
                if obj:
                    items.append(obj)
        
        # Fallback to current row if none checked
        if not items:
            row = table.currentRow()
            if row >= 0:
                name_item = table.item(row, 1)
                obj = name_item.data(data_role)
                if obj:
                    items.append(obj)
        return items

class ElementsDialog(BaseProjectTableDialog):
    """Dialog for editing architectural elements (Process, Data Store, etc.)."""

    def __init__(self, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__("System Elements", project, undo_stack, parent)
        self._setup_ui()
        self._load_data()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        header_font = QFont("Segoe UI", 12, QFont.Weight.Bold)
        comp_header = QLabel("System Elements (Process, Data Store, Entity)")
        comp_header.setFont(header_font)
        comp_header.setStyleSheet("color: #58a6ff; margin-bottom: 5px;")
        layout.addWidget(comp_header)

        self._table = QTableWidget(0, 8)
        self._table.setHorizontalHeaderLabels([
            "",
            "Element Name",
            "Element Type",
            "Trust Boundary",
            "Technical Description",
            "Out of Scope?",
            "Justification / Remarks",
            "Identified Risks"
        ])
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 30)
        self._table.setColumnWidth(1, 180)
        self._table.setColumnWidth(2, 120)
        self._table.setColumnWidth(3, 180)
        self._table.setColumnWidth(4, 200)
        self._table.setColumnWidth(5, 90)
        self._table.setColumnWidth(7, 120)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._table)
        
        comp_btns = QHBoxLayout()
        from PySide6.QtWidgets import QCheckBox
        self._select_all_cb = QCheckBox("Select All")
        self._select_all_cb.clicked.connect(lambda chk: self._on_select_all(chk, self._table))
        comp_btns.addWidget(self._select_all_cb)
        
        self._btn_add = QPushButton(" + Add New Element")
        self._btn_add.setMinimumHeight(35)
        self._btn_add.clicked.connect(self._on_add_element)
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
        v_scroll = self._table.verticalScrollBar().value()
        h_scroll = self._table.horizontalScrollBar().value()
        
        for comp in self._project.components:
            count = sum(1 for t in self._project.threat_register.threats if comp.name.strip().lower() in t.affected_components.lower())
            comp._identified_risks_count = str(count) if count > 0 else ""
            
        column_mappers = {
            1: ("name", True, False),
            4: ("description", True, False),
            5: ("is_out_of_scope", True, True),
            6: ("out_of_scope_justification", True, False),
            7: ("_identified_risks_count", False, False)
        }
        self._load_data_generic(self._project.components, column_mappers)
        
        # Add custom combo boxes for Type and Boundary
        self._table.blockSignals(True)
        for row, comp in enumerate(self._project.components):
            elem_combo = QComboBox()
            elem_combo.addItems(sorted([e.value for e in ElementType]))
            elem_combo.setCurrentText(comp.element_type.value)
            elem_combo.setProperty("row", row)
            elem_combo.currentTextChanged.connect(self._on_element_type_changed)
            self._table.setCellWidget(row, 2, elem_combo)
            
            tb_combo = QComboBox()
            tb_names = ["None (External)"] + sorted([b.name for b in self._project.boundaries])
            tb_combo.addItems(tb_names)
            curr_tb_name = next((b.name for b in self._project.boundaries if b.boundary_id == comp.trust_boundary_id), "None (External)")
            tb_combo.setCurrentText(curr_tb_name)
            tb_combo.setProperty("row", row)
            tb_combo.currentTextChanged.connect(self._on_trust_boundary_changed)
            self._table.setCellWidget(row, 3, tb_combo)
        self._table.blockSignals(False)
        
        self._table.verticalScrollBar().setValue(v_scroll)
        self._table.horizontalScrollBar().setValue(h_scroll)
        if hasattr(self, "_select_all_cb") and self._select_all_cb:
            self._select_all_cb.setCheckState(Qt.CheckState.Unchecked)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        field_map = {1: ("name", False), 4: ("description", False), 5: ("is_out_of_scope", True), 6: ("out_of_scope_justification", False)}
        self._on_item_changed_generic(item, field_map)

    def _on_element_type_changed(self, new_val: str) -> None:
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 1)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp: 
                new_enum_val = next((et for et in ElementType if et.value == new_val), ElementType.PROCESS)
                self._update_property(comp, "element_type", new_enum_val)

    def _on_trust_boundary_changed(self, new_val: str) -> None:
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 1)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp: 
                new_tb_id = None
                if new_val != "None (External)":
                    tb = next((b for b in self._project.boundaries if b.name == new_val), None)
                    if tb: new_tb_id = tb.boundary_id
                self._update_property(comp, "trust_boundary_id", new_tb_id)

    def _on_delete_selected(self) -> None:
        to_delete = self._get_selected_items(self._table)
        if not to_delete:
            return

        if self._undo_stack:
            from threatpilot.ui.undo_commands import DeleteComponentCommand
            self._undo_stack.beginMacro(f"Bulk Delete {len(to_delete)} Elements")
            for comp in to_delete:
                cmd = DeleteComponentCommand(self._project, comp)
                self._undo_stack.push(cmd)
            self._undo_stack.endMacro()
        else:
            for comp in to_delete:
                if comp in self._project.components:
                    self._project.components.remove(comp)
        
        self.project_modified.emit()
        self._load_data()

    def _on_add_element(self) -> None:
        from threatpilot.core.domain_models import Asset, AssetType
        new_comp = Component(name="New Element", x=100, y=100)
        new_asset = Asset(name="New Element", type=AssetType.PHYSICAL, description="Manually added element")
        
        if self._undo_stack:
            from threatpilot.ui.undo_commands import AddComponentCommand, AddAssetCommand
            self._undo_stack.beginMacro("Add Element & Mirror to Assets")
            self._undo_stack.push(AddComponentCommand(self._project, new_comp))
            self._undo_stack.push(AddAssetCommand(self._project, new_asset))
            self._undo_stack.endMacro()
        else:
            self._project.components.append(new_comp)
            self._project.assets.append(new_asset)
            
        self.project_modified.emit()
        self._load_data()


class AssetsDialog(BaseProjectTableDialog):
    """Dialog for editing standalone assets (Physical, Informational)."""

    def __init__(self, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__("System Asset", project, undo_stack, parent)
        self._setup_window_size(0.7, 0.6)
        self._setup_ui()
        self._load_data()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        header_font = QFont("Segoe UI", 12, QFont.Weight.Bold)
        asset_header = QLabel("Security Assets (Data, Credentials, Hardware)")
        asset_header.setFont(header_font)
        asset_header.setStyleSheet("color: #e3b341; margin-bottom: 5px;")
        layout.addWidget(asset_header)

        self._table = QTableWidget(0, 8)
        self._table.setHorizontalHeaderLabels([
            "",
            "Asset Name",
            "Asset Type",
            "Criticality",
            "Out of Scope?",
            "Justification",
            "Description",
            "Identified Risks"
        ])
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 30) # Checkbox column
        self._table.setColumnWidth(1, 200)
        self._table.setColumnWidth(2, 140)
        self._table.setColumnWidth(3, 120)
        self._table.setColumnWidth(4, 100)
        self._table.setColumnWidth(5, 250)
        self._table.setColumnWidth(7, 120)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._table)
        
        asset_btns = QHBoxLayout()
        from PySide6.QtWidgets import QCheckBox
        self._select_all_assets = QCheckBox("Select All")
        self._select_all_assets.clicked.connect(lambda chk: self._on_select_all(chk, self._table))
        asset_btns.addWidget(self._select_all_assets)
        
        self._btn_add_asset = QPushButton(" + Add New Asset")
        self._btn_add_asset.setMinimumHeight(35)
        self._btn_add_asset.clicked.connect(self._on_add_asset)
        asset_btns.addWidget(self._btn_add_asset)
        
        self._btn_del_asset = QPushButton(" x Remove Selected")
        self._btn_del_asset.setMinimumHeight(35)
        self._btn_del_asset.clicked.connect(self._on_delete_selected)
        asset_btns.addWidget(self._btn_del_asset)
        asset_btns.addStretch()
        layout.addLayout(asset_btns)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_data(self) -> None:
        v_scroll = self._table.verticalScrollBar().value()
        h_scroll = self._table.horizontalScrollBar().value()
        
        for asset in self._project.assets:
            count = sum(1 for t in self._project.threat_register.threats if asset.name.strip().lower() in t.affected_components.lower())
            asset._identified_risks_count = str(count) if count > 0 else ""
            
        column_mappers = {
            1: ("name", True, False),
            3: ("criticality", True, False),
            4: ("is_out_of_scope", True, True),
            5: ("out_of_scope_justification", True, False),
            6: ("description", True, False),
            7: ("_identified_risks_count", False, False)
        }
        self._load_data_generic(self._project.assets, column_mappers)
        
        self._table.blockSignals(True)
        for row, asset in enumerate(self._project.assets):
            asset_combo = QComboBox()
            asset_combo.addItems(["Physical", "Informational"])
            asset_combo.setCurrentText(asset.type.value)
            asset_combo.setProperty("row", row)
            asset_combo.currentTextChanged.connect(self._on_asset_type_changed)
            self._table.setCellWidget(row, 2, asset_combo)
        self._table.blockSignals(False)
        
        self._table.verticalScrollBar().setValue(v_scroll)
        self._table.horizontalScrollBar().setValue(h_scroll)
        if hasattr(self, "_select_all_assets") and self._select_all_assets:
            self._select_all_assets.setCheckState(Qt.CheckState.Unchecked)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        field_map = {1: ("name", False), 3: ("criticality", False), 4: ("is_out_of_scope", True), 5: ("out_of_scope_justification", False), 6: ("description", False)}
        self._on_item_changed_generic(item, field_map)

    def _on_asset_type_changed(self, new_val: str) -> None:
        from threatpilot.core.domain_models import AssetType
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 1)
        if name_item:
            asset = name_item.data(Qt.ItemDataRole.UserRole)
            if asset: 
                new_enum_val = AssetType.PHYSICAL if new_val == "Physical" else AssetType.INFORMATIONAL
                self._update_property(asset, "type", new_enum_val)

    def _on_add_asset(self) -> None:
        from threatpilot.core.domain_models import Asset, AssetType
        new_asset = Asset(name="New Asset", type=AssetType.INFORMATIONAL)
        if self._undo_stack:
            cmd = undo_commands.AddAssetCommand(self._project, new_asset)
            self._undo_stack.push(cmd)
        else:
            self._project.assets.append(new_asset)
        self.project_modified.emit()
        self._load_data()

    def _on_delete_selected(self) -> None:
        to_delete = self._get_selected_items(self._table)
        if not to_delete:
            return

        if self._undo_stack:
            from threatpilot.ui.undo_commands import DeleteAssetCommand
            self._undo_stack.beginMacro(f"Bulk Delete {len(to_delete)} Assets")
            for asset in to_delete:
                cmd = DeleteAssetCommand(self._project, asset)
                self._undo_stack.push(cmd)
            self._undo_stack.endMacro()
        else:
            for asset in to_delete:
                if asset in self._project.assets:
                    self._project.assets.remove(asset)
        
        self.project_modified.emit()
        self._load_data()


class DataFlowDialog(BaseProjectTableDialog):
    """Dialog for editing data flow connections and protocols."""

    def __init__(self, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__("Data Flow Mapping", project, undo_stack, parent)
        self._setup_window_size(0.8, 0.6)
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
        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels(["", "Flow Alias", "Source Element", "Destination Element", "Protocol / Port", "Bidirectional?", "Identified Risks"])
        self._table.setColumnWidth(0, 30)
        self._table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(1, 250)
        self._table.setColumnWidth(2, 250)
        self._table.setColumnWidth(3, 250)
        self._table.setColumnWidth(4, 140)
        self._table.setColumnWidth(6, 120)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.itemChanged.connect(self._on_flow_item_changed)
        layout.addWidget(self._table)
        
        flow_btns = QHBoxLayout()
        from PySide6.QtWidgets import QCheckBox
        self._select_all_flows = QCheckBox("Select All")
        self._select_all_flows.clicked.connect(lambda chk: self._on_select_all(chk, self._table))
        flow_btns.addWidget(self._select_all_flows)
        
        self._btn_add_flow = QPushButton(" + Create Manual Flow")
        self._btn_add_flow.setMinimumHeight(35)
        self._btn_add_flow.clicked.connect(self._on_add_flow)
        flow_btns.addWidget(self._btn_add_flow)
        self._btn_del_flow = QPushButton(" x Delete Selected")
        self._btn_del_flow.setMinimumHeight(35)
        self._btn_del_flow.clicked.connect(self._on_delete_selected)
        flow_btns.addWidget(self._btn_del_flow)
        flow_btns.addStretch()
        layout.addLayout(flow_btns)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_data(self) -> None:
        v_scroll = self._table.verticalScrollBar().value()
        h_scroll = self._table.horizontalScrollBar().value()
        
        for flow in self._project.flows:
            count = sum(1 for t in self._project.threat_register.threats if flow.name.strip().lower() in t.affected_components.lower())
            flow._identified_risks_count = str(count) if count > 0 else ""
            
        column_mappers = {
            1: ("name", True, False),
            4: ("protocol", True, False),
            5: ("is_bidirectional", True, True),
            6: ("_identified_risks_count", False, False)
        }
        self._load_data_generic(self._project.flows, column_mappers)
        
        self._table.blockSignals(True)
        comp_names = ["(Unlinked)"] + sorted([c.name for c in self._project.components])
        for row, flow in enumerate(self._project.flows):
            src_combo = QComboBox()
            src_combo.addItems(comp_names)
            src_name = self._get_comp_name_by_id(flow.source_id)
            src_combo.setCurrentText(src_name or "(Unlinked)")
            src_combo.currentTextChanged.connect(lambda val, f=flow: self._update_flow_source(f, val))
            self._table.setCellWidget(row, 2, src_combo)
            
            dst_combo = QComboBox()
            dst_combo.addItems(comp_names)
            dst_name = self._get_comp_name_by_id(flow.target_id)
            dst_combo.setCurrentText(dst_name or "(Unlinked)")
            dst_combo.currentTextChanged.connect(lambda val, f=flow: self._update_flow_target(f, val))
            self._table.setCellWidget(row, 3, dst_combo)
        self._table.blockSignals(False)
        
        self._table.verticalScrollBar().setValue(v_scroll)
        self._table.horizontalScrollBar().setValue(h_scroll)
        if hasattr(self, "_select_all_flows") and self._select_all_flows:
            self._select_all_flows.setCheckState(Qt.CheckState.Unchecked)

        # Restore scroll position
        self._table.verticalScrollBar().setValue(v_scroll)
        self._table.horizontalScrollBar().setValue(h_scroll)

        if hasattr(self, "_select_all_flows") and self._select_all_flows:
            self._select_all_flows.setCheckState(Qt.CheckState.Unchecked)

    def _get_comp_name_by_id(self, cid: str) -> str:
        for c in self._project.components:
            if c.component_id == cid: return c.name
        return ""

    def _get_comp_id_by_name(self, name: str) -> str:
        for c in self._project.components:
            if c.name == name: return c.component_id
        return ""

    def _update_flow_source(self, flow, name):
        new_val = self._get_comp_id_by_name(name)
        self._update_property(flow, "source_id", new_val)

    def _update_flow_target(self, flow, name):
        new_val = self._get_comp_id_by_name(name)
        self._update_property(flow, "target_id", new_val)

    def _on_delete_selected(self) -> None:
        to_delete = self._get_selected_items(self._table)
        if not to_delete:
            return

        if self._undo_stack:
            from threatpilot.ui.undo_commands import DeleteFlowCommand
            self._undo_stack.beginMacro(f"Bulk Delete {len(to_delete)} Flows")
            for flow in to_delete:
                cmd = DeleteFlowCommand(self._project, flow)
                self._undo_stack.push(cmd)
            self._undo_stack.endMacro()
        else:
            for flow in to_delete:
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

    def _on_flow_item_changed(self, item: QTableWidgetItem) -> None:
        field_map = {1: ("name", False), 4: ("protocol", False), 5: ("is_bidirectional", True)}
        self._on_item_changed_generic(item, field_map)



class TrustBoundaryDialog(BaseProjectTableDialog):
    """Dialog for managing trust boundaries (Zones, VPCs, Cloud, etc.) with nesting support."""

    def __init__(self, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__("System Trust Boundaries", project, undo_stack, parent)
        self._setup_window_size(0.7, 0.5)
        self._setup_ui()
        self._load_data()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)

        header_font = QFont("Segoe UI", 12, QFont.Weight.Bold)
        tb_header = QLabel("Trust Boundaries & Security Zones (Nesting Supported)")
        tb_header.setFont(header_font)
        tb_header.setStyleSheet("color: #7ee787; margin-bottom: 5px;")
        layout.addWidget(tb_header)

        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels([
            "",
            "Boundary Name",
            "Boundary Type",
            "Parent Boundary",
            "Description",
            "Identified Risks"
        ])
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 30) # Checkbox column
        self._table.setColumnWidth(1, 180)
        self._table.setColumnWidth(2, 120)
        self._table.setColumnWidth(3, 200)
        self._table.setColumnWidth(5, 120)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._table)
        
        btns = QHBoxLayout()
        from PySide6.QtWidgets import QCheckBox
        self._select_all_cb = QCheckBox("Select All")
        self._select_all_cb.clicked.connect(lambda chk: self._on_select_all(chk, self._table))
        btns.addWidget(self._select_all_cb)
        
        self._btn_add = QPushButton(" + Create Trust Boundary")
        self._btn_add.setMinimumHeight(35)
        self._btn_add.clicked.connect(self._on_add_boundary)
        btns.addWidget(self._btn_add)
        
        self._btn_del = QPushButton(" x Delete Selected")
        self._btn_del.setMinimumHeight(35)
        self._btn_del.clicked.connect(self._on_delete_selected)
        btns.addWidget(self._btn_del)
        btns.addStretch()
        layout.addLayout(btns)
        
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_data(self) -> None:
        v_scroll = self._table.verticalScrollBar().value()
        h_scroll = self._table.horizontalScrollBar().value()
        
        for tb in self._project.boundaries:
            count = sum(1 for t in self._project.threat_register.threats if tb.name.strip().lower() in t.affected_components.lower())
            tb._identified_risks_count = str(count) if count > 0 else ""
            
        column_mappers = {
            1: ("name", True, False),
            2: ("type", True, False),
            4: ("description", True, False),
            5: ("_identified_risks_count", False, False)
        }
        self._load_data_generic(self._project.boundaries, column_mappers)
        
        self._table.blockSignals(True)
        for row, tb in enumerate(self._project.boundaries):
            parent_combo = QComboBox()
            options = ["None"] + sorted([b.name for b in self._project.boundaries if b.boundary_id != tb.boundary_id])
            parent_combo.addItems(options)
            
            parent_name = next((b.name for b in self._project.boundaries if b.boundary_id == tb.parent_boundary_id), "None")
            
            parent_combo.setCurrentText(parent_name)
            parent_combo.setProperty("row", row)
            parent_combo.currentTextChanged.connect(self._on_parent_changed)
            self._table.setCellWidget(row, 3, parent_combo)
            
        self._table.blockSignals(False)

        # Restore scroll position
        self._table.verticalScrollBar().setValue(v_scroll)
        self._table.horizontalScrollBar().setValue(h_scroll)

        if hasattr(self, "_select_all_cb") and self._select_all_cb:
            self._select_all_cb.setCheckState(Qt.CheckState.Unchecked)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        field_map = {1: ("name", False), 2: ("type", False), 4: ("description", False)}
        self._on_item_changed_generic(item, field_map)

    def _on_parent_changed(self, new_val: str) -> None:
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 1)
        if name_item:
            tb = name_item.data(Qt.ItemDataRole.UserRole)
            if tb:
                new_pid = None
                if new_val != "None":
                    parent = next((b for b in self._project.boundaries if b.name == new_val), None)
                    if parent: new_pid = parent.boundary_id
                self._update_property(tb, "parent_boundary_id", new_pid)

    def _on_add_boundary(self) -> None:
        from threatpilot.core.domain_models import TrustBoundary
        new_tb = TrustBoundary(name="New Trust Boundary", x=50, y=50)
        if self._undo_stack:
            cmd = undo_commands.AddTrustBoundaryCommand(self._project, new_tb)
            self._undo_stack.push(cmd)
        else:
            self._project.boundaries.append(new_tb)
        self.project_modified.emit()
        self._load_data()

    def _on_delete_selected(self) -> None:
        to_delete = self._get_selected_items(self._table)
        if not to_delete:
            return

        if self._undo_stack:
            from threatpilot.ui.undo_commands import DeleteTrustBoundaryCommand
            self._undo_stack.beginMacro(f"Bulk Delete {len(to_delete)} Boundaries")
            for tb in to_delete:
                cmd = DeleteTrustBoundaryCommand(self._project, tb)
                self._undo_stack.push(cmd)
            self._undo_stack.endMacro()
        else:
            for tb in to_delete:
                if tb in self._project.boundaries:
                    self._project.boundaries.remove(tb)
        
        self.project_modified.emit()
        self._load_data()

# Compatibility aliases
ArchitectureDialog = ElementsDialog
EntitiesDialog = ElementsDialog
