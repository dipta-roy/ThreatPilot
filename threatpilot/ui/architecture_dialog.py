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

class ElementsDialog(QDialog):
    """Dialog for editing architectural elements (Process, Data Store, etc.)."""

    project_modified = Signal()

    def __init__(self, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("System Elements")
        
        screen = QApplication.primaryScreen().availableGeometry()
        width = int(screen.width() * 0.6)
        height = int(screen.height() * 0.6)
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
        comp_header = QLabel("System Elements (Process, Data Store, Entity)")
        comp_header.setFont(header_font)
        comp_header.setStyleSheet("color: #58a6ff; margin-bottom: 5px;")
        layout.addWidget(comp_header)

        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels([
            "",
            "Element Name",
            "Element Type",
            "Trust Boundary",
            "Technical Description",
            "Out of Scope?",
            "Justification / Remarks"
        ])
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 30) # Checkbox column
        self._table.setColumnWidth(1, 180)
        self._table.setColumnWidth(2, 120)
        self._table.setColumnWidth(3, 180)
        self._table.setColumnWidth(4, 200)
        self._table.setColumnWidth(5, 90)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._table)
        
        comp_btns = QHBoxLayout()
        from PySide6.QtWidgets import QCheckBox
        self._select_all = QCheckBox("Select All")
        self._select_all.clicked.connect(self._on_select_all)
        comp_btns.addWidget(self._select_all)
        
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
        self._table.blockSignals(True)
        self._table.setRowCount(0)
        for row, comp in enumerate(self._project.components):
            self._table.insertRow(row)
            
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk_item.setCheckState(Qt.CheckState.Unchecked)
            self._table.setItem(row, 0, chk_item)

            name_item = QTableWidgetItem(comp.name)
            name_item.setData(Qt.ItemDataRole.UserRole, comp)
            self._table.setItem(row, 1, name_item)
            
            elem_combo = QComboBox()
            elem_types = [e.value for e in ElementType]
            elem_combo.addItems(elem_types)
            elem_combo.setCurrentText(comp.element_type.value)
            elem_combo.setProperty("row", row)
            elem_combo.currentTextChanged.connect(self._on_element_type_changed)
            self._table.setCellWidget(row, 2, elem_combo)
            
            tb_combo = QComboBox()
            tb_names = ["None (External)"] + [b.name for b in self._project.boundaries]
            tb_combo.addItems(tb_names)
            curr_tb_name = "None (External)"
            if comp.trust_boundary_id:
                tb = next((b for b in self._project.boundaries if b.boundary_id == comp.trust_boundary_id), None)
                if tb: curr_tb_name = tb.name
            tb_combo.setCurrentText(curr_tb_name)
            tb_combo.setProperty("row", row)
            tb_combo.currentTextChanged.connect(self._on_trust_boundary_changed)
            self._table.setCellWidget(row, 3, tb_combo)
            
            desc_item = QTableWidgetItem(comp.description)
            self._table.setItem(row, 4, desc_item)
            
            oos_item = QTableWidgetItem()
            oos_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            oos_item.setCheckState(Qt.CheckState.Checked if comp.is_out_of_scope else Qt.CheckState.Unchecked)
            self._table.setItem(row, 5, oos_item)
            
            just_item = QTableWidgetItem(comp.out_of_scope_justification)
            self._table.setItem(row, 6, just_item)
            
            if comp.is_out_of_scope:
                for col in range(7):
                    it = self._table.item(row, col)
                    if it: it.setBackground(QColor("#2d333b") if QApplication.instance().styleSheet().count("style.qss") else QColor("#f6f8fa"))
                    if it: it.setForeground(QColor("#8b949e"))
            
        self._table.blockSignals(False)
        if hasattr(self, "_select_all") and self._select_all:
            self._select_all.setCheckState(Qt.CheckState.Unchecked)

    def _on_undo_redo_index_changed(self, index: int) -> None:
        if not self._is_internal_edit:
            QTimer.singleShot(0, self._load_data)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        row = item.row()
        name_item = self._table.item(row, 1)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp:
                field = ""
                if item.column() == 1: field = "name"
                elif item.column() == 4: field = "description"
                elif item.column() == 5: field = "is_out_of_scope"
                elif item.column() == 6: field = "out_of_scope_justification"
                
                if field:
                    if field == "is_out_of_scope":
                        new_val = (item.checkState() == Qt.CheckState.Checked)
                        if new_val and not comp.out_of_scope_justification:
                             # Auto-focus or remind to add justification
                             item.setToolTip("Please add justification in the next column")
                    else:
                        new_val = item.text().strip()
                        
                    old_val = getattr(comp, field)
                    if new_val != old_val:
                        if self._undo_stack:
                            self._is_internal_edit = True
                            cmd = undo_commands.PropertyUpdateCommand(comp, field, old_val, new_val)
                            self._undo_stack.push(cmd)
                            self._is_internal_edit = False
                        else:
                            setattr(comp, field, new_val)
                        
                        if field == "is_out_of_scope":
                            self._load_data()
                            
                        self.project_modified.emit()

    def _on_element_type_changed(self, new_val: str) -> None:
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 1)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp: 
                old_val = comp.element_type
                new_enum_val = next((et for et in ElementType if et.value == new_val), ElementType.PROCESS)
                if new_enum_val != old_val:
                    if self._undo_stack:
                        self._is_internal_edit = True
                        cmd = undo_commands.PropertyUpdateCommand(comp, "element_type", old_val, new_enum_val)
                        self._undo_stack.push(cmd)
                        self._is_internal_edit = False
                    else:
                        comp.element_type = new_enum_val
                    self.project_modified.emit()

    def _on_trust_boundary_changed(self, new_val: str) -> None:
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 1)
        if name_item:
            comp = name_item.data(Qt.ItemDataRole.UserRole)
            if comp: 
                old_val = comp.trust_boundary_id
                new_tb_id = None
                if new_val != "None (External)":
                    tb = next((b for b in self._project.boundaries if b.name == new_val), None)
                    if tb: new_tb_id = tb.boundary_id
                
                if new_tb_id != old_val:
                    if self._undo_stack:
                        self._is_internal_edit = True
                        cmd = undo_commands.PropertyUpdateCommand(comp, "trust_boundary_id", old_val, new_tb_id)
                        self._undo_stack.push(cmd)
                        self._is_internal_edit = False
                    else:
                        comp.trust_boundary_id = new_tb_id
                    self.project_modified.emit()

    def _on_select_all(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self._table.blockSignals(True)
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item:
                item.setCheckState(state)
        self._table.blockSignals(False)

    def _on_delete_selected(self) -> None:
        to_delete = []
        for row in range(self._table.rowCount()):
            chk_item = self._table.item(row, 0)
            if chk_item and chk_item.checkState() == Qt.CheckState.Checked:
                name_item = self._table.item(row, 1)
                comp = name_item.data(Qt.ItemDataRole.UserRole)
                if comp:
                    to_delete.append(comp)
        
        # Fallback to current row if none checked
        if not to_delete:
            row = self._table.currentRow()
            if row >= 0:
                name_item = self._table.item(row, 1)
                comp = name_item.data(Qt.ItemDataRole.UserRole)
                if comp:
                    to_delete.append(comp)
        
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


class AssetsDialog(QDialog):
    """Dialog for editing standalone assets (Physical, Informational)."""

    project_modified = Signal()

    def __init__(self, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("System Asset")
        
        screen = QApplication.primaryScreen().availableGeometry()
        width = int(screen.width() * 0.7)
        height = int(screen.height() * 0.6)
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
        asset_header = QLabel("Security Assets (Data, Credentials, Hardware)")
        asset_header.setFont(header_font)
        asset_header.setStyleSheet("color: #e3b341; margin-bottom: 5px;")
        layout.addWidget(asset_header)

        self._table = QTableWidget(0, 7)
        self._table.setHorizontalHeaderLabels([
            "",
            "Asset Name",
            "Asset Type",
            "Criticality",
            "Out of Scope?",
            "Justification",
            "Description"
        ])
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 30) # Checkbox column
        self._table.setColumnWidth(1, 200)
        self._table.setColumnWidth(2, 140)
        self._table.setColumnWidth(3, 120)
        self._table.setColumnWidth(4, 100)
        self._table.setColumnWidth(5, 250)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._table)
        
        asset_btns = QHBoxLayout()
        from PySide6.QtWidgets import QCheckBox
        self._select_all_assets = QCheckBox("Select All")
        self._select_all_assets.clicked.connect(self._on_select_all_assets)
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
        from threatpilot.core.domain_models import Asset, AssetType
        self._table.blockSignals(True)
        self._table.setRowCount(0)
        for row, asset in enumerate(self._project.assets):
            self._table.insertRow(row)
            
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk_item.setCheckState(Qt.CheckState.Unchecked)
            self._table.setItem(row, 0, chk_item)

            name_item = QTableWidgetItem(asset.name)
            name_item.setData(Qt.ItemDataRole.UserRole, asset)
            self._table.setItem(row, 1, name_item)
            
            asset_combo = QComboBox()
            asset_types = ["Physical", "Informational"]
            asset_combo.addItems(asset_types)
            asset_combo.setCurrentText(asset.type.value)
            asset_combo.setProperty("row", row)
            asset_combo.currentTextChanged.connect(self._on_asset_type_changed)
            self._table.setCellWidget(row, 2, asset_combo)
            
            crit_item = QTableWidgetItem(asset.criticality)
            self._table.setItem(row, 3, crit_item)
            
            oos_item = QTableWidgetItem()
            oos_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            oos_item.setCheckState(Qt.CheckState.Checked if asset.is_out_of_scope else Qt.CheckState.Unchecked)
            self._table.setItem(row, 4, oos_item)
            
            just_item = QTableWidgetItem(asset.out_of_scope_justification)
            self._table.setItem(row, 5, just_item)
            
            desc_item = QTableWidgetItem(asset.description)
            self._table.setItem(row, 6, desc_item)
            
            if asset.is_out_of_scope:
                for col in range(7):
                    it = self._table.item(row, col)
                    if it: it.setBackground(QColor("#2d333b") if QApplication.instance().styleSheet().count("style.qss") else QColor("#f6f8fa"))
                    if it: it.setForeground(QColor("#8b949e"))
            
        self._table.blockSignals(False)
        if hasattr(self, "_select_all_assets") and self._select_all_assets:
            self._select_all_assets.setCheckState(Qt.CheckState.Unchecked)

    def _on_undo_redo_index_changed(self, index: int) -> None:
        if not self._is_internal_edit:
            QTimer.singleShot(0, self._load_data)

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        row = item.row()
        name_item = self._table.item(row, 1)
        if name_item:
            asset = name_item.data(Qt.ItemDataRole.UserRole)
            if asset:
                field = ""
                if item.column() == 1: field = "name"
                elif item.column() == 3: field = "criticality"
                elif item.column() == 4: field = "is_out_of_scope"
                elif item.column() == 5: field = "out_of_scope_justification"
                elif item.column() == 6: field = "description"
                
                if field:
                    if field == "is_out_of_scope":
                        new_val = (item.checkState() == Qt.CheckState.Checked)
                    else:
                        new_val = item.text().strip()
                        
                    old_val = getattr(asset, field)
                    if new_val != old_val:
                        if self._undo_stack:
                            self._is_internal_edit = True
                            cmd = undo_commands.PropertyUpdateCommand(asset, field, old_val, new_val)
                            self._undo_stack.push(cmd)
                            self._is_internal_edit = False
                        else:
                            setattr(asset, field, new_val)
                        
                        if field == "is_out_of_scope":
                            self._load_data()
                            
                        self.project_modified.emit()

    def _on_asset_type_changed(self, new_val: str) -> None:
        from threatpilot.core.domain_models import AssetType
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 1)
        if name_item:
            asset = name_item.data(Qt.ItemDataRole.UserRole)
            if asset: 
                old_val = asset.type
                new_enum_val = AssetType.PHYSICAL if new_val == "Physical" else AssetType.INFORMATIONAL
                if new_enum_val != old_val:
                    if self._undo_stack:
                        self._is_internal_edit = True
                        cmd = undo_commands.PropertyUpdateCommand(asset, "type", old_val, new_enum_val)
                        self._undo_stack.push(cmd)
                        self._is_internal_edit = False
                    else:
                        asset.type = new_enum_val
                    self.project_modified.emit()

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

    def _on_select_all_assets(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self._table.blockSignals(True)
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item:
                item.setCheckState(state)
        self._table.blockSignals(False)

    def _on_delete_selected(self) -> None:
        to_delete = []
        for row in range(self._table.rowCount()):
            chk_item = self._table.item(row, 0)
            if chk_item and chk_item.checkState() == Qt.CheckState.Checked:
                name_item = self._table.item(row, 1)
                asset = name_item.data(Qt.ItemDataRole.UserRole)
                if asset:
                    to_delete.append(asset)
        
        # Fallback to selection if none checked
        if not to_delete:
            row = self._table.currentRow()
            if row >= 0:
                name_item = self._table.item(row, 1)
                asset = name_item.data(Qt.ItemDataRole.UserRole)
                if asset:
                    to_delete.append(asset)
        
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
        self._flow_table = QTableWidget(0, 6)
        self._flow_table.setHorizontalHeaderLabels(["", "Flow Alias", "Source Element", "Destination Element", "Protocol / Port", "Bidirectional?"])
        self._flow_table.setColumnWidth(0, 30) # Checkbox column
        self._flow_table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._flow_table.setVerticalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self._flow_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        header = self._flow_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self._flow_table.setColumnWidth(1, 250)
        self._flow_table.setColumnWidth(2, 250)
        self._flow_table.setColumnWidth(3, 140)
        self._flow_table.setColumnWidth(4, 100)
        self._flow_table.setAlternatingRowColors(True)
        self._flow_table.verticalHeader().setDefaultSectionSize(38)
        layout.addWidget(self._flow_table)
        flow_btns = QHBoxLayout()
        from PySide6.QtWidgets import QCheckBox
        self._select_all_flows = QCheckBox("Select All")
        self._select_all_flows.clicked.connect(self._on_select_all_flows)
        flow_btns.addWidget(self._select_all_flows)
        
        self._btn_add_flow = QPushButton(" + Create Manual Flow")
        self._btn_add_flow.setMinimumHeight(35)
        self._btn_add_flow.clicked.connect(self._on_add_flow)
        flow_btns.addWidget(self._btn_add_flow)
        self._btn_del_flow = QPushButton(" x Delete Selected")
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
            
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk_item.setCheckState(Qt.CheckState.Unchecked)
            self._flow_table.setItem(row, 0, chk_item)

            name_item = QTableWidgetItem(flow.name)
            name_item.setData(Qt.ItemDataRole.UserRole, flow)
            self._flow_table.setItem(row, 1, name_item)
            
            src_combo = QComboBox()
            src_combo.addItems(comp_names)
            src_name = self._get_comp_name_by_id(flow.source_id)
            src_combo.setCurrentText(src_name or "(Unlinked)")
            src_combo.currentTextChanged.connect(lambda val, f=flow: self._update_flow_source(f, val))
            self._flow_table.setCellWidget(row, 2, src_combo)
            
            dst_combo = QComboBox()
            dst_combo.addItems(comp_names)
            dst_name = self._get_comp_name_by_id(flow.target_id)
            dst_combo.setCurrentText(dst_name or "(Unlinked)")
            dst_combo.currentTextChanged.connect(lambda val, f=flow: self._update_flow_target(f, val))
            self._flow_table.setCellWidget(row, 3, dst_combo)
            
            proto_item = QTableWidgetItem(flow.protocol)
            proto_item.setData(Qt.ItemDataRole.UserRole, flow)
            self._flow_table.setItem(row, 4, proto_item)
            
            bi_item = QTableWidgetItem()
            bi_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            bi_item.setCheckState(Qt.CheckState.Checked if flow.is_bidirectional else Qt.CheckState.Unchecked)
            self._flow_table.setItem(row, 5, bi_item)

        self._flow_table.itemChanged.connect(self._on_flow_item_changed)
        self._flow_table.blockSignals(False)
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

    def _on_select_all_flows(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self._flow_table.blockSignals(True)
        for row in range(self._flow_table.rowCount()):
            item = self._flow_table.item(row, 0)
            if item:
                item.setCheckState(state)
        self._flow_table.blockSignals(False)

    def _on_delete_selected_flow(self) -> None:
        to_delete = []
        for row in range(self._flow_table.rowCount()):
            chk_item = self._flow_table.item(row, 0)
            if chk_item and chk_item.checkState() == Qt.CheckState.Checked:
                name_item = self._flow_table.item(row, 1)
                flow = name_item.data(Qt.ItemDataRole.UserRole)
                if flow:
                    to_delete.append(flow)
        
        # Fallback to selection
        if not to_delete:
            row = self._flow_table.currentRow()
            if row >= 0:
                name_item = self._flow_table.item(row, 1)
                flow = name_item.data(Qt.ItemDataRole.UserRole)
                if flow:
                    to_delete.append(flow)
        
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

    def _on_undo_redo_index_changed(self, index: int) -> None:
        if not self._is_internal_edit:
            QTimer.singleShot(0, self._load_data)

    def _on_flow_item_changed(self, item: QTableWidgetItem) -> None:
        row = item.row()
        name_item = self._flow_table.item(row, 1)
        if not name_item: return
        flow = name_item.data(Qt.ItemDataRole.UserRole)
        if not flow: return

        field = ""
        if item.column() == 1: field = "name"
        elif item.column() == 4: field = "protocol"
        elif item.column() == 5: field = "is_bidirectional"

        if field:
            if field == "is_bidirectional":
                new_val = (item.checkState() == Qt.CheckState.Checked)
            else:
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



class TrustBoundaryDialog(QDialog):
    """Dialog for managing trust boundaries (Zones, VPCs, Cloud, etc.) with nesting support."""

    project_modified = Signal()

    def __init__(self, project: Project, undo_stack=None, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("System Trust Boundaries")
        self.resize(900, 500)
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
        tb_header = QLabel("Trust Boundaries & Security Zones (Nesting Supported)")
        tb_header.setFont(header_font)
        tb_header.setStyleSheet("color: #7ee787; margin-bottom: 5px;")
        layout.addWidget(tb_header)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels([
            "",
            "Boundary Name",
            "Boundary Type",
            "Parent Boundary",
            "Description"
        ])
        header = self._table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.setColumnWidth(0, 30) # Checkbox column
        self._table.setColumnWidth(1, 180)
        self._table.setColumnWidth(2, 120)
        self._table.setColumnWidth(3, 200)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setDefaultSectionSize(38)
        self._table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self._table)
        
        btns = QHBoxLayout()
        from PySide6.QtWidgets import QCheckBox
        self._select_all_tb = QCheckBox("Select All")
        self._select_all_tb.clicked.connect(self._on_select_all_tb)
        btns.addWidget(self._select_all_tb)
        
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
        self._table.blockSignals(True)
        self._table.setRowCount(0)
        
        for row, tb in enumerate(self._project.boundaries):
            self._table.insertRow(row)
            
            chk_item = QTableWidgetItem()
            chk_item.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
            chk_item.setCheckState(Qt.CheckState.Unchecked)
            self._table.setItem(row, 0, chk_item)

            name_item = QTableWidgetItem(tb.name)
            name_item.setData(Qt.ItemDataRole.UserRole, tb)
            self._table.setItem(row, 1, name_item)
            
            type_item = QTableWidgetItem(tb.type)
            self._table.setItem(row, 2, type_item)
            
            parent_combo = QComboBox()
            options = ["None"] + [b.name for b in self._project.boundaries if b.boundary_id != tb.boundary_id]
            parent_combo.addItems(options)
            
            parent_name = "None"
            if tb.parent_boundary_id:
                parent = next((b for b in self._project.boundaries if b.boundary_id == tb.parent_boundary_id), None)
                if parent: parent_name = parent.name
            
            parent_combo.setCurrentText(parent_name)
            parent_combo.setProperty("row", row)
            parent_combo.currentTextChanged.connect(self._on_parent_changed)
            self._table.setCellWidget(row, 3, parent_combo)
            
            desc_item = QTableWidgetItem(tb.description)
            self._table.setItem(row, 4, desc_item)
            
        self._table.blockSignals(False)
        if hasattr(self, "_select_all_tb") and self._select_all_tb:
            self._select_all_tb.setCheckState(Qt.CheckState.Unchecked)

    def _on_undo_redo_index_changed(self, index: int) -> None:
        if not self._is_internal_edit:
            QTimer.singleShot(0, self._load_data)

    def _on_item_changed(self, item) -> None:
        row = item.row()
        name_item = self._table.item(row, 1)
        if name_item:
            tb = name_item.data(Qt.ItemDataRole.UserRole)
            if tb:
                field = ""
                if item.column() == 1: field = "name"
                elif item.column() == 2: field = "type"
                elif item.column() == 4: field = "description"
                
                if field:
                    new_val = item.text().strip()
                    old_val = getattr(tb, field)
                    if new_val != old_val:
                        if self._undo_stack:
                            self._is_internal_edit = True
                            from threatpilot.ui import undo_commands
                            cmd = undo_commands.PropertyUpdateCommand(tb, field, old_val, new_val)
                            self._undo_stack.push(cmd)
                            self._is_internal_edit = False
                        else:
                            setattr(tb, field, new_val)
                        self.project_modified.emit()
                        if field == "name":
                            self._load_data()

    def _on_parent_changed(self, new_val: str) -> None:
        sender = self.sender()
        row = sender.property("row")
        name_item = self._table.item(row, 1)
        if name_item:
            tb = name_item.data(Qt.ItemDataRole.UserRole)
            if tb:
                old_val = tb.parent_boundary_id
                new_pid = None
                if new_val != "None":
                    parent = next((b for b in self._project.boundaries if b.name == new_val), None)
                    if parent: new_pid = parent.boundary_id
                
                if new_pid != old_val:
                    if self._undo_stack:
                        self._is_internal_edit = True
                        from threatpilot.ui import undo_commands
                        cmd = undo_commands.PropertyUpdateCommand(tb, "parent_boundary_id", old_val, new_pid)
                        self._undo_stack.push(cmd)
                        self._is_internal_edit = False
                    else:
                        tb.parent_boundary_id = new_pid
                    self.project_modified.emit()

    def _on_add_boundary(self) -> None:
        from threatpilot.core.domain_models import TrustBoundary
        from threatpilot.ui import undo_commands
        new_tb = TrustBoundary(name="New Trust Boundary", x=50, y=50)
        if self._undo_stack:
            cmd = undo_commands.AddTrustBoundaryCommand(self._project, new_tb)
            self._undo_stack.push(cmd)
        else:
            self._project.boundaries.append(new_tb)
        self.project_modified.emit()
        self._load_data()

    def _on_select_all_tb(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self._table.blockSignals(True)
        for row in range(self._table.rowCount()):
            item = self._table.item(row, 0)
            if item:
                item.setCheckState(state)
        self._table.blockSignals(False)

    def _on_delete_selected(self) -> None:
        to_delete = []
        for row in range(self._table.rowCount()):
            chk_item = self._table.item(row, 0)
            if chk_item and chk_item.checkState() == Qt.CheckState.Checked:
                name_item = self._table.item(row, 1)
                tb = name_item.data(Qt.ItemDataRole.UserRole)
                if tb:
                    to_delete.append(tb)
        
        # Fallback to selection
        if not to_delete:
            row = self._table.currentRow()
            if row >= 0:
                name_item = self._table.item(row, 1)
                tb = name_item.data(Qt.ItemDataRole.UserRole)
                if tb:
                    to_delete.append(tb)
        
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
