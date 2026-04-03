"""Threat Edit Dialog for ThreatPilot.

Provides a form to manually edit all attributes of a security threat,
including an interactive CVSS v3.1 calculator.
"""

from __future__ import annotations
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QFormLayout,
    QLineEdit,
    QTextEdit,
    QComboBox,
    QSpinBox,
    QDoubleSpinBox,
    QDialogButtonBox,
    QLabel,
    QScrollArea,
    QWidget,
    QGroupBox,
    QCompleter,
)
from PySide6.QtCore import Qt, QStringListModel
from PySide6.QtGui import QFont
from threatpilot.core.threat_model import Threat, STRIDECategory
from threatpilot.risk.cvss_calculator import (
    CVSSMetrics, 
    calculate_cvss_base_score, 
    generate_cvss_vector, 
    parse_cvss_vector
)

class ThreatEditDialog(QDialog):
    """Dialog for editing threat details with integrated CVSS calculator."""

    def __init__(self, threat: Threat, component_names: list[str] = None, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Edit Security Threat")
        self.resize(700, 850)
        self._threat = threat
        self._component_names = component_names or []
        self._setup_ui()
        self._load_data()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        self._main_form = QFormLayout(scroll_content)
        scroll.setWidget(scroll_content)
        layout.addWidget(scroll)
        gen_group = QGroupBox("General Information")
        gen_layout = QFormLayout(gen_group)
        self._title_input = QLineEdit()
        gen_layout.addRow("Title:", self._title_input)

        self._category_combo = QComboBox()
        for cat in STRIDECategory:
            self._category_combo.addItem(cat.value, cat)
        gen_layout.addRow("Category (STRIDE):", self._category_combo)

        self._affected_element_combo = QComboBox()
        self._affected_element_combo.setEditable(True)
        self._affected_asset_combo = QComboBox()
        self._affected_asset_combo.setEditable(True)
        
        if self._component_names:
            sorted_names = sorted(self._component_names)
            self._affected_element_combo.addItems(sorted_names)
            self._affected_asset_combo.addItems(sorted_names)
            
            for combo in [self._affected_element_combo, self._affected_asset_combo]:
                completer = QCompleter(sorted_names)
                completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
                completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
                combo.setCompleter(completer)
            
        gen_layout.addRow("Affected Element:", self._affected_element_combo)
        gen_layout.addRow("Affected Asset:", self._affected_asset_combo)      
        self._main_form.addRow(gen_group)
        details_group = QGroupBox("Threat Details")
        details_layout = QFormLayout(details_group)
        self._description_input = QTextEdit()
        self._description_input.setAcceptRichText(False)
        self._description_input.setMinimumHeight(80)
        details_layout.addRow("Description:", self._description_input)
        self._impact_input = QTextEdit()
        self._impact_input.setAcceptRichText(False)
        self._impact_input.setMinimumHeight(60)
        details_layout.addRow("Impact:", self._impact_input)
        self._likelihood_spin = QSpinBox()
        self._likelihood_spin.setRange(1, 5)
        details_layout.addRow("Likelihood (1-5):", self._likelihood_spin)      
        self._main_form.addRow(details_group)
        cvss_group = QGroupBox("CVSS v3.1 Base Metrics")
        cvss_layout = QFormLayout(cvss_group)
        self._cvss_combos = {}
        metrics_options = {
            "attack_vector": ["Network", "Adjacent", "Local", "Physical"],
            "attack_complexity": ["Low", "High"],
            "privileges_required": ["None", "Low", "High"],
            "user_interaction": ["None", "Required"],
            "scope": ["Unchanged", "Changed"],
            "confidentiality": ["None", "Low", "High"],
            "integrity": ["None", "Low", "High"],
            "availability": ["None", "Low", "High"],
        }

        for attr, options in metrics_options.items():
            combo = QComboBox()
            combo.addItems(options)
            combo.currentTextChanged.connect(self._on_cvss_metric_changed)
            label = attr.replace("_", " ").title()
            cvss_layout.addRow(f"{label}:", combo)
            self._cvss_combos[attr] = combo
        self._cvss_score_display = QLabel("0.0")
        self._cvss_score_display.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        cvss_layout.addRow("Calculated Base Score:", self._cvss_score_display)
        self._cvss_vector_display = QLineEdit()
        self._cvss_vector_display.setReadOnly(True)
        cvss_layout.addRow("Vector String:", self._cvss_vector_display)
        self._main_form.addRow(cvss_group)
        remedy_group = QGroupBox("Technical Analysis & Remediation")
        remedy_layout = QFormLayout(remedy_group)
        self._vulnerabilities_input = QTextEdit()
        self._vulnerabilities_input.setAcceptRichText(False)
        self._vulnerabilities_input.setMinimumHeight(80)
        remedy_layout.addRow("Technical Vulnerabilities:", self._vulnerabilities_input)

        self._mitigation_input = QTextEdit()
        self._mitigation_input.setAcceptRichText(False)
        self._mitigation_input.setMinimumHeight(80)
        remedy_layout.addRow("Recommended Mitigation:", self._mitigation_input)
        self._main_form.addRow(remedy_group)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _load_data(self) -> None:
        self._title_input.setText(self._threat.title)
        
        idx = self._category_combo.findData(self._threat.category)
        if idx >= 0:
            self._category_combo.setCurrentIndex(idx)
            
        self._affected_element_combo.setCurrentText(self._threat.affected_element or self._threat.affected_components)
        self._affected_asset_combo.setCurrentText(self._threat.affected_asset or self._threat.affected_components)
        self._description_input.setPlainText(self._threat.description)
        self._impact_input.setPlainText(self._threat.impact)
        self._likelihood_spin.setValue(self._threat.likelihood)
        self._vulnerabilities_input.setPlainText(self._threat.vulnerabilities)
        self._mitigation_input.setPlainText(self._threat.mitigation)
        if self._threat.cvss_vector:
            metrics = parse_cvss_vector(self._threat.cvss_vector)
            for attr, combo in self._cvss_combos.items():
                val = getattr(metrics, attr)
                combo.setCurrentText(val)
        
        self._update_cvss_results()

    def _on_cvss_metric_changed(self) -> None:
        self._update_cvss_results()

    def _update_cvss_results(self) -> None:
        metrics = CVSSMetrics()
        for attr, combo in self._cvss_combos.items():
            setattr(metrics, attr, combo.currentText())
        
        score = calculate_cvss_base_score(metrics)
        vector = generate_cvss_vector(metrics)
        self._cvss_score_display.setText(str(score))
        self._cvss_vector_display.setText(vector)
        if score >= 9.0: color = "#ff4444"
        elif score >= 7.0: color = "#ff8800"
        elif score >= 4.0: color = "#ffbb33"
        elif score > 0: color = "#00c851"
        else: color = "#888888"
        self._cvss_score_display.setStyleSheet(f"color: {color};")

    def accept(self) -> None:
        self._threat.title = self._title_input.text()
        self._threat.affected_element = self._affected_element_combo.currentText()
        self._threat.affected_asset = self._affected_asset_combo.currentText()
        self._threat.affected_components = self._threat.affected_element
        self._threat.description = self._description_input.toPlainText()
        self._threat.impact = self._impact_input.toPlainText()
        self._threat.likelihood = self._likelihood_spin.value()
        self._threat.cvss_score = float(self._cvss_score_display.text())
        self._threat.cvss_vector = self._cvss_vector_display.text()
        self._threat.vulnerabilities = self._vulnerabilities_input.toPlainText()
        self._threat.mitigation = self._mitigation_input.toPlainText()
        super().accept()