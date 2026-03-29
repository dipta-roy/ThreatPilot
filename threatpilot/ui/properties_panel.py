"""Properties panel for ThreatPilot.

Provides a dynamic ``QWidget`` that displays and edits fields for the
currently selected architectural item (Component, Flow, or Trust Boundary).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QScrollArea,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from threatpilot.core.domain_models import Component, Flow, TrustBoundary
from threatpilot.core.threat_model import Threat, STRIDECategory
from threatpilot.ui.cvss_dialog import CVSSCalculatorDialog
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

    property_changed: Signal = Signal(object)  # One of Component, Flow, TrustBoundary

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._current_item: Any | None = None

        self._setup_ui()

    def _setup_ui(self) -> None:
        """Initialise the layout with tabs for Properties and AI Logs."""
        self.setObjectName("properties_container")
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)

        self._tabs = QTabWidget()
        self._tabs.setObjectName("properties_tabs")
        root_layout.addWidget(self._tabs)

        # --- Tab 1: Properties ---
        self._prop_widget = QWidget()
        prop_layout = QVBoxLayout(self._prop_widget)
        prop_layout.setContentsMargins(5, 5, 5, 5)

        # Title/Header
        self._header = QLabel("No item selected")
        self._header.setObjectName("property_header")
        self._header.setAlignment(Qt.AlignmentFlag.AlignLeft)
        prop_layout.addWidget(self._header)

        # Scroll Area for the form
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        prop_layout.addWidget(scroll)

        self._container = QWidget()
        self._form_layout = QFormLayout(self._container)
        scroll.setWidget(self._container)
        
        self._tabs.addTab(self._prop_widget, "Element Attributes")

        # Security Warning for generated content
        self._security_warning = QLabel(
            "⚠️ Security Advisory: All AI-generated mitigations and descriptions should be verified "
            "by a security professional before implementation."
        )
        self._security_warning.setWordWrap(True)
        self._security_warning.setStyleSheet("color: #d73a49; font-style: italic; font-size: 10px; margin: 4px;")
        self._security_warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._security_warning.setVisible(False)
        prop_layout.addWidget(self._security_warning)

        # --- Tab 2: AI Activity Logs ---
        self._log_view = QTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setObjectName("log_view")
        self._log_view.setPlaceholderText("AI transaction logs will appear here during detection or analysis...")
        
        self._tabs.addTab(self._log_view, "AI Activity Logs")

    def set_theme(self, is_dark: bool) -> None:
        """Update the panel's internal state for theme changes."""
        self._is_dark_theme = is_dark
        # Refresh the current item to apply any object-name based styles if needed
        # (Though most are handled by QSS or re-rendered on set_item)
        if self._current_item:
            self.set_item(self._current_item)

    def append_log(self, text: str, category: str = "INFO") -> None:
        """Add a timestamped entry to the AI Activity Log tab."""
        time_str = datetime.now().strftime("%H:%M:%S")
        
        is_dark = getattr(self, "_is_dark_theme", True)
        
        # Theme-aware log colors
        if is_dark:
            color = "#58a6ff" if "PROMPT" in category else "#7ee787" if "RESPONSE" in category else "#8b949e"
            time_color = "#484f58"
        else:
            color = "#0969da" if "PROMPT" in category else "#1a7f37" if "RESPONSE" in category else "#57606a"
            time_color = "#8b949e"
        
        sanitized_text = sanitize_text(text)
        log_entry = f"<span style='color: {time_color};'>[{time_str}]</span> <b style='color: {color};'>{category}</b>: {sanitized_text}<br>"
        self._log_view.append(log_entry)
        # Scroll to bottom
        self._log_view.verticalScrollBar().setValue(self._log_view.verticalScrollBar().maximum())

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

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

        # Show warning if the item came from AI or is a Threat
        from threatpilot.core.threat_model import Threat
        if isinstance(item, Threat):
            self._security_warning.setVisible(True)
        else:
            self._security_warning.setVisible(False)

        # Build dynamic form based on type
        if isinstance(item, Component):
            self._header.setText("Component Properties")
            self._add_text_row("Name:", "name", item.name)
            self._add_combo_row("Type:", "type", item.type, ["Service", "Datastore", "Asset", "Trustboundary"])
            self._add_combo_row("Element Class:", "element_classification", item.element_classification, ["Entity", "Process", "DataStore", "DataFlow"])
            self._add_combo_row("Asset Class:", "asset_classification", item.asset_classification, ["Physical", "Informational"])
            self._add_textarea_row("Description:", "description", item.description)
            self._add_checkbox_row("High Value Asset:", "is_high_value_asset", item.is_high_value_asset)
            self._add_textarea_row("Criticality Desc:", "criticality_description", item.criticality_description)
            self._add_readonly_row("ID:", item.component_id)

        elif isinstance(item, Flow):
            self._header.setText("Data Flow Properties")
            self._add_text_row("Protocol:", "protocol", item.protocol)
            self._add_textarea_row("Description:", "description", item.description)
            self._add_readonly_row("Source ID:", item.source_id)
            self._add_readonly_row("Target ID:", item.target_id)
            self._add_readonly_row("ID:", item.flow_id)

        elif isinstance(item, TrustBoundary):
            self._header.setText("Trust Boundary Properties")
            self._add_text_row("Name:", "name", item.name)
            self._add_text_row("Type:", "type", item.type)
            self._add_textarea_row("Description:", "description", item.description)
            self._add_readonly_row("ID:", item.boundary_id)

        elif isinstance(item, Threat):
            self._header.setText("Threat Details")
            self._add_text_row("Title:", "title", item.title)
            
            self._add_combo_row("Category:", "category", item.category.value, [c.value for c in STRIDECategory])
            
            self._add_textarea_row("Description:", "description", item.description)
            self._add_textarea_row("Vulnerabilities:", "vulnerabilities", item.vulnerabilities)
            self._add_textarea_row("Impact:", "impact", item.impact)
            self._add_textarea_row("Mitigation:", "mitigation", item.mitigation)
            
            self._add_combo_row("Likelihood Score:", "likelihood", str(item.likelihood), ["1", "2", "3", "4", "5"])
            self._add_text_row("CVSS Score:", "cvss_score", str(item.cvss_score))
            self._add_text_row("CVSS Vector:", "cvss_vector", item.cvss_vector)
            
            self._add_textarea_row("Affected Components:", "affected_components", item.affected_components)
            self._add_text_row("Affected Element:", "affected_element", item.affected_element)
            self._add_text_row("Affected Asset:", "affected_asset", item.affected_asset)
            self._add_checkbox_row("Accepted Risk:", "is_accepted_risk", item.is_accepted_risk)
            self._add_textarea_row("Acceptance Rationale:", "acceptance_justification", item.acceptance_justification)
            self._add_readonly_row("Threat ID:", item.threat_id)

        else:
            self._header.setText(f"{type(item).__name__} Unknown")

    # ------------------------------------------------------------------
    # Form Helpers
    # ------------------------------------------------------------------

    def _clear_form(self) -> None:
        """Remove all rows from the layout."""
        while self._form_layout.rowCount() > 0:
            self._form_layout.removeRow(0)

    def _add_text_row(self, label: str, field: str, value: Any) -> None:
        """Add an editable text row that updates the model on change."""
        edit = QLineEdit(str(value))
        
        # Interactive CVSS Calculator trigger
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
                    # Manually update the score field too if we can find it
                    self._on_field_changed("cvss_score", score)
                    # Refresh the whole panel to show the new numeric score
                    self.set_item(self._current_item)

            edit.mousePressEvent = lambda e: launch_calc()

        edit.textChanged.connect(lambda text: self._on_field_changed(field, text))
        self._form_layout.addRow(label, edit)

    def _add_textarea_row(self, label: str, field: str, value: str) -> None:
        """Add a multiline text environment row."""
        edit = QTextEdit(str(value))
        edit.setFixedHeight(100)
        edit.textChanged.connect(lambda: self._on_field_changed(field, edit.toPlainText()))
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

    # ------------------------------------------------------------------
    # Event Handlers
    # ------------------------------------------------------------------

    def _on_field_changed(self, field: str, value: Any) -> None:
        """Update the model object field and emit change signal with type awareness."""
        if self._current_item is not None:
            # Handle numeric type conversion for specific fields
            if field in ("cvss_score",):
                try: value = float(value)
                except ValueError: return
            elif field in ("likelihood",):
                try: value = int(value)
                except ValueError: return
            
            # Special case for STRIDE Category enum
            if field == "category":
                for cat in STRIDECategory:
                    if cat.value == value:
                        value = cat
                        break

            setattr(self._current_item, field, value)
            self.property_changed.emit(self._current_item)
