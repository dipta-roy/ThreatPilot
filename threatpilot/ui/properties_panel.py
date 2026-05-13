"""Properties panel for ThreatPilot.

Provides a dynamic ``QWidget`` that displays and edits fields for the
currently selected architectural item (Component, Flow, or Trust Boundary).
"""

from __future__ import annotations
from datetime import datetime
from typing import Any
from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QCompleter,
)
from threatpilot.core.domain_models import Component, Flow, TrustBoundary
from threatpilot.core.threat_model import Threat, STRIDECategory
from threatpilot.ui.cvss_dialog import CVSSCalculatorDialog
from threatpilot.ai.response_parser import convert_reasoning_to_markdown
from threatpilot.utils.logger import sanitize_text

class PropertiesPanel(QWidget):
    """A dynamic property editor panel for project elements.

    Displays a form with fields dependent on the object's type.
    Changes are updated back to the model object immediately as they're
    typed/chosen.

    Signals:
        property_changed: Emitted when any field is edited. Carries the
            modified item object.
    """

    property_changed: Signal = Signal(object)
    reasoning_requested: Signal = Signal(object)

    def __init__(self, parent: QWidget | None = None, undo_stack: QUndoStack | None = None) -> None:
        super().__init__(parent)
        self._current_item: Any | None = None
        self._undo_stack = undo_stack
        self._project = None
        
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(1000)
        self._debounce_timer.timeout.connect(self._on_debounced_timeout)
        self._pending_field: str | None = None
        self._pending_getter = None
        self._is_panel_editing: bool = False

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Initialise the layout with the Properties form."""
        self.setObjectName("properties_container")
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)

        self._header = QLabel("No item selected")
        self._header.setObjectName("property_header")
        self._header.setAlignment(Qt.AlignmentFlag.AlignLeft)
        root_layout.addWidget(self._header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        root_layout.addWidget(scroll)

        self._container = QWidget()
        self._form_layout = QFormLayout(self._container)
        scroll.setWidget(self._container)
        
        self._security_warning = QLabel(
            "⚠️ Security Advisory: All AI-generated mitigations and descriptions should be verified "
            "by a security professional before implementation."
        )
        self._security_warning.setWordWrap(True)
        self._security_warning.setStyleSheet("color: #d73a49; font-style: italic; font-size: 10px; margin: 4px;")
        self._security_warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._security_warning.setVisible(False)
        root_layout.addWidget(self._security_warning)

    def set_theme(self, is_dark: bool) -> None:
        """Update the panel's internal state for theme changes."""
        self._is_dark_theme = is_dark
        if self._current_item:
            self.set_item(self._current_item)

    def set_project(self, project: object) -> None:
        self._project = project

    def set_item(self, item: Any | None) -> None:
        """Load the properties of the given item into the panel.

        Args:
            item: The object whose properties should be edited, or ``None`` to clear.
        """
        self._current_item = item
        self._clear_form()

        if item is None:
            self._header.setText("No selection")
            self._security_warning.setVisible(False)
            return

        from threatpilot.core.threat_model import Threat
        if isinstance(item, Threat):
            self._security_warning.setVisible(True)
        else:
            self._security_warning.setVisible(False)

        if isinstance(item, Component):
            self._header.setText("Component Properties")
            self._add_text_row("Name:", "name", item.name)
            self._add_combo_row("Type:", "type", item.type, ["Service", "Datastore", "Asset", "Trustboundary"])
            
            from threatpilot.core.domain_models import ElementType, AssetType
            self._add_combo_row("Element Type:", "element_type", item.element_type.value, [e.value for e in ElementType])
            self._add_combo_row("Asset Type:", "asset_type", item.asset_type.value, [a.value for a in AssetType])
            
            # Trust Boundary Selection
            tb_options = ["None (External)"]
            tb_map = {"None (External)": None}
            if hasattr(self.parent(), "project") and self.parent().project:
                for b in self.parent().project.boundaries:
                    tb_options.append(b.name)
                    tb_map[b.name] = b.boundary_id
            
            current_tb_name = "None (External)"
            if item.trust_boundary_id and hasattr(self.parent(), "project") and self.parent().project:
                tb = next((b for b in self.parent().project.boundaries if b.boundary_id == item.trust_boundary_id), None)
                if tb: current_tb_name = tb.name
            
            self._add_combo_row("Trust Boundary:", "trust_boundary_id", current_tb_name, tb_options)

            self._add_textarea_row("Description:", "description", item.description)
            self._add_checkbox_row("High Value Asset:", "is_high_value_asset", item.is_high_value_asset)
            self._add_textarea_row("Criticality Desc:", "criticality_description", item.criticality_description)
            self._add_checkbox_row("Out of Scope:", "is_out_of_scope", item.is_out_of_scope)
            self._add_textarea_row("OOS Justification:", "out_of_scope_justification", item.out_of_scope_justification)
            self._add_readonly_row("ID:", item.component_id)

        elif isinstance(item, Flow):
            self._header.setText("Data Flow Properties")
            self._add_text_row("Protocol:", "protocol", item.protocol)
            self._add_textarea_row("Description:", "description", item.description)
            self._add_checkbox_row("Bidirectional:", "is_bidirectional", item.is_bidirectional)
            self._add_checkbox_row("Out of Scope:", "is_out_of_scope", item.is_out_of_scope)
            self._add_textarea_row("OOS Justification:", "out_of_scope_justification", item.out_of_scope_justification)
            self._add_readonly_row("Source ID:", item.source_id)
            self._add_readonly_row("Target ID:", item.target_id)
            self._add_readonly_row("ID:", item.flow_id)

        elif isinstance(item, TrustBoundary):
            self._header.setText("Trust Boundary Properties")
            self._add_text_row("Name:", "name", item.name)
            self._add_text_row("Type:", "type", item.type)
            
            parent_options = ["None"]
            parent_map = {"None": None}
            for b in self._project.boundaries:
                if b.boundary_id != item.boundary_id:
                    parent_options.append(b.name)
                    parent_map[b.name] = b.boundary_id
            
            current_parent_name = "None"
            if item.parent_boundary_id:
                p = next((b for b in self._project.boundaries if b.boundary_id == item.parent_boundary_id), None)
                if p: current_parent_name = p.name
                
            self._add_combo_row("Parent Boundary:", "parent_boundary_id", current_parent_name, parent_options, parent_map)
            self._add_textarea_row("Description:", "description", item.description)
            self._add_readonly_row("ID:", item.boundary_id)

        elif isinstance(item, Threat):
            self._header.setText("Threat Details")
            self._add_text_row("Title:", "title", item.title)
            
            self._add_combo_row("Category:", "category", item.category.value, [c.value for c in STRIDECategory])
            
            self._add_textarea_row("Description:", "description", item.description)
            
            vuln_display = ""
            if self._project and self._project.vulnerability_register:
                v_ids = getattr(item, "vulnerability_ids", [])
                v_texts = []
                for vid in v_ids:
                    v_obj = self._project.vulnerability_register.get_vulnerability(vid)
                    if v_obj:
                        v_texts.append(f"• {v_obj.description}")
                    else:
                        v_texts.append(f"• [Unknown: {vid}]")
                vuln_display = "\n".join(v_texts)
            
            self._add_readonly_textarea_row("Vulnerabilities:", "vulnerability_ids", vuln_display)
            self._add_textarea_row("Impact:", "impact", item.impact)
            self._add_textarea_row("Mitigation:", "mitigation", item.mitigation)
            
            self._add_combo_row("Likelihood Score:", "likelihood", str(item.likelihood), ["1", "2", "3", "4", "5"])
            self._add_text_row("CVSS Score:", "cvss_score", str(item.cvss_score))
            self._add_text_row("CVSS Vector:", "cvss_vector", item.cvss_vector)
            self._add_text_row("MITRE ATT&CK ID:", "mitre_attack_id", item.mitre_attack_id)
            self._add_text_row("MITRE Technique:", "mitre_attack_technique", item.mitre_attack_technique)
            
            self._add_textarea_row("Affected Components:", "affected_components", item.affected_components)
            
            # Get list of all component names for the dropdowns
            component_names = []
            if self._project:
                component_names = sorted(list(set(
                    [c.name for c in self._project.components]
                )))
            
            # ── Resolve element/asset names for display consistency ──
            display_elem = item.affected_element_type or ""
            display_asset = item.affected_asset_type or ""
            
            generic_types = ["data flow", "informational", "physical", "process", "data store", "external entity", "n/a", ""]
            if (display_elem.lower() in generic_types or display_asset.lower() in generic_types) and self._project:
                res_elem = ""
                res_asset = ""
                if item.affected_components:
                    haystack = (f"{item.affected_components} {item.title} {item.description}").lower()
                    for cname in [n.strip() for n in item.affected_components.split(",")]:
                        # 1. Exact flow name match
                        flow_match = next((f for f in self._project.flows if f.name == cname), None)
                        if flow_match:
                            src = next((c for c in self._project.components if c.component_id == flow_match.source_id), None)
                            dst = next((c for c in self._project.components if c.component_id == flow_match.target_id), None)
                            res_elem = src.name if src else ""
                            res_asset = dst.name if dst else ""
                            break
                        # 2. Exact component match
                        comp_match = next((c for c in self._project.components if c.name == cname), None)
                        if comp_match:
                            res_elem = comp_match.name
                            res_asset = comp_match.name
                            break
                    # 3. Fuzzy flow match
                    if not res_elem:
                        for f in self._project.flows:
                            src = next((c for c in self._project.components if c.component_id == f.source_id), None)
                            dst = next((c for c in self._project.components if c.component_id == f.target_id), None)
                            if src and dst and src.name.lower() in haystack and dst.name.lower() in haystack:
                                res_elem = src.name
                                res_asset = dst.name
                                break
                    # 4. Fuzzy component match
                    if not res_elem:
                        for c in self._project.components:
                            if c.name.lower() in haystack:
                                res_elem = c.name
                                res_asset = c.name
                                break
                
                display_elem = display_elem if display_elem.lower() not in generic_types else (res_elem or display_elem)
                display_asset = display_asset if display_asset.lower() not in generic_types else (res_asset or display_asset)

            self._add_editable_combo_row("Affected Element:", "affected_element_type", display_elem, component_names)
            self._add_editable_combo_row("Affected Asset:", "affected_asset_type", display_asset, component_names)
            self._add_checkbox_row("Accepted Risk:", "is_accepted_risk", item.is_accepted_risk)
            self._add_textarea_row("Acceptance Rationale:", "acceptance_justification", item.acceptance_justification)
            
            self._add_readonly_textarea_row("XAI Reasoning:", "reasoning", item.reasoning or "Reasoning not yet generated.")
            
            self._btn_xai = QPushButton("Analyze Reasoning using XAI")
            self._btn_xai.setCursor(Qt.CursorShape.PointingHandCursor)
            self._btn_xai.setStyleSheet("background-color: #238636; color: white; font-weight: bold; padding: 8px; margin: 10px 0;")
            self._btn_xai.clicked.connect(self._on_request_reasoning)
            self._form_layout.addRow("", self._btn_xai)
            
            self._xai_progress = QProgressBar()
            self._xai_progress.setRange(0, 0)
            self._xai_progress.setTextVisible(False)
            self._xai_progress.setFixedHeight(4)
            self._xai_progress.setVisible(False)
            self._form_layout.addRow("", self._xai_progress)
            
            self._add_readonly_row("Threat ID:", item.threat_id)

        else:
            self._header.setText(f"{type(item).__name__} Unknown")

    def set_reasoning_progress(self, busy: bool) -> None:
        """Update the UI state to reflect an active XAI reasoning pass."""
        if hasattr(self, "_btn_xai"):
            self._btn_xai.setEnabled(not busy)
            self._btn_xai.setText("Analyzing Reasoning..." if busy else "Analyze Reasoning using XAI")
        
        if hasattr(self, "_xai_progress"):
            self._xai_progress.setVisible(busy)

    def _clear_form(self) -> None:
        """Remove all rows from the layout."""
        while self._form_layout.rowCount() > 0:
            self._form_layout.removeRow(0)

    def _add_text_row(self, label: str, field: str, value: Any) -> None:
        """Add an editable text row that updates the model on change."""
        edit = QLineEdit(str(value))
        
        if field == "cvss_vector":
            edit.setReadOnly(True)
            edit.setCursor(Qt.CursorShape.PointingHandCursor)
            edit.setToolTip("Click to launch interactive CVSS 3.1 Calculator")
            edit.setObjectName("cvss_vector_edit")
            
            def launch_calc():
                dialog = CVSSCalculatorDialog(edit.text(), self)
                if dialog.exec():
                    score, vector = dialog.get_result()
                    edit.setText(vector)
                    self._on_field_changed("cvss_vector", vector)
                    self._on_field_changed("cvss_score", score)
                    self.set_item(self._current_item)

            edit.mousePressEvent = lambda e: launch_calc()

        edit.editingFinished.connect(lambda: self._on_field_changed(field, edit.text()))
        self._form_layout.addRow(label, edit)

    def _add_textarea_row(self, label: str, field: str, value: str) -> None:
        """Add a multiline text environment row with debounced updates."""
        edit = QTextEdit(str(value))
        edit.setFixedHeight(100)
        
        def _on_text_changed():
            self._pending_field = field
            self._pending_getter = edit.toPlainText
            self._debounce_timer.start()

        edit.textChanged.connect(_on_text_changed)
        self._form_layout.addRow(label, edit)

    def _add_readonly_textarea_row(self, label: str, field: str, value: str) -> None:
        """Add a multiline readonly text row (Markdown supported)."""
        edit = QTextEdit()
        edit.setReadOnly(True)

        if field == "reasoning":
            value = convert_reasoning_to_markdown(value)
            self._reasoning_view = edit

        edit.setMarkdown(value)
        edit.setFixedHeight(150)
        edit.setObjectName(f"readonly_{field}")

        self._form_layout.addRow(label, edit)

    def _add_readonly_row(self, label: str, value: str) -> None:
        """Add a non-editable text row for information/IDs."""
        edit = QLineEdit(str(value))
        edit.setReadOnly(True)
        edit.setObjectName("readonly_edit")
        self._form_layout.addRow(label, edit)

    def _add_checkbox_row(self, label: str, field: str, checked: bool) -> None:
        """Add a checkbox row that updates the model on change."""
        cb = QCheckBox()
        cb.setChecked(checked)
        cb.toggled.connect(lambda state: self._on_field_changed(field, state))
        self._form_layout.addRow(label, cb)

    def _add_combo_row(self, label: str, field: str, value: str, options: list[str]) -> None:
        """Add a dropdown combobox row that updates the model on change."""
        cb = QComboBox()
        cb.addItems(options)
        if value not in options:
            cb.addItem(value)
        cb.setCurrentText(value)
        cb.currentTextChanged.connect(lambda text: self._on_field_changed(field, text))
        self._form_layout.addRow(label, cb)

    def _add_editable_combo_row(self, label: str, field: str, value: str, options: list[str]) -> None:
        """Add an editable dropdown with autocompletion support."""
        cb = QComboBox()
        cb.setEditable(True)
        cb.addItems(options)
        
        # Add current value if not in options
        if value and value not in options:
            cb.addItem(value)
            
        cb.setCurrentText(value)
        
        # Add a completer for better UX
        completer = QCompleter(options)
        completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        cb.setCompleter(completer)
        
        cb.currentTextChanged.connect(lambda text: self._on_field_changed(field, text))
        self._form_layout.addRow(label, cb)

    def _on_request_reasoning(self) -> None:
        """Inform the controller that reasoning analysis should be executed for the current threat."""
        from threatpilot.core.threat_model import Threat
        if isinstance(self._current_item, Threat):
            self._btn_xai.setEnabled(False)
            self._reasoning_view.setPlaceholderText("Analyzing Reasoning with AI... Please wait.")
            self.reasoning_requested.emit(self._current_item)

    def _on_field_changed(self, field: str, value: Any) -> None:
        """Update the model object field and emit change signal with type awareness."""
        if self._current_item is not None:
            try:
                old_val = getattr(self._current_item, field)
            except AttributeError:
                return

            if field in ("cvss_score",):
                try: value = float(value)
                except ValueError: return
            elif field in ("likelihood",):
                try: value = int(value)
                except ValueError: return
            
            if field == "category":
                for cat in STRIDECategory:
                    if cat.value == value:
                        value = cat
                        break

            if field == "cvss_score":
                value = round(float(value), 1)
                old_val = round(float(old_val or 0.0), 1)

            if field == "trust_boundary_id":
                if value == "None (External)":
                    value = None
                elif hasattr(self.parent(), "project") and self.parent().project:
                    tb = next((b for b in self.parent().project.boundaries if b.name == value), None)
                    value = tb.boundary_id if tb else None

            if field == "element_type":
                from threatpilot.core.domain_models import ElementType
                for et in ElementType:
                    if et.value == value:
                        value = et
                        break
            
            if field == "asset_type":
                from threatpilot.core.domain_models import AssetType
                for at in AssetType:
                    if at.value == value:
                        value = at
                        break

            if value != old_val:
                self._is_panel_editing = True
                try:
                    if self._undo_stack:
                        from threatpilot.ui import undo_commands
                        cmd = undo_commands.PropertyUpdateCommand(self._current_item, field, old_val, value)
                        self._undo_stack.push(cmd)
                    else:
                        setattr(self._current_item, field, value)
                    
                    self.property_changed.emit(self._current_item)
                finally:
                    self._is_panel_editing = False

    def _on_debounced_timeout(self) -> None:
        """Commit the pending field update after typing has stopped."""
        if self._pending_field and self._pending_getter:
            value = self._pending_getter()
            self._on_field_changed(self._pending_field, value)
            self._pending_field = None
            self._pending_getter = None
