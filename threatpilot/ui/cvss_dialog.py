"""CVSS 3.1 Interactive Calculator Dialog for ThreatPilot."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QFormLayout,
    QComboBox,
    QLabel,
    QDialogButtonBox,
    QGroupBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from threatpilot.utils.cvss_calculator import calculate_cvss_31


class CVSSCalculatorDialog(QDialog):
    """An interactive CVSS 3.1 score calculator."""

    def __init__(self, initial_vector: str, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("CVSS 3.1 Calculator")
        self.resize(550, 600)
        self._vector = initial_vector if initial_vector.startswith("CVSS:3.1/") else "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        self._setup_ui()
        self._parse_vector(self._vector)

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        header = QLabel("Interactive CVSS 3.1 Modeler")
        header.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        header.setStyleSheet("color: #58a6ff;")
        layout.addWidget(header)

        # Exploitability Metrics
        exp_group = QGroupBox("Exploitability Metrics")
        exp_layout = QFormLayout(exp_group)
        
        self._av = QComboBox()
        self._av.addItems(["Network (N)", "Adjacent (A)", "Local (L)", "Physical (P)"])
        exp_layout.addRow("Attack Vector:", self._av)
        
        self._ac = QComboBox()
        self._ac.addItems(["Low (L)", "High (H)"])
        exp_layout.addRow("Attack Complexity:", self._ac)
        
        self._pr = QComboBox()
        self._pr.addItems(["None (N)", "Low (L)", "High (H)"])
        exp_layout.addRow("Privileges Required:", self._pr)
        
        self._ui = QComboBox()
        self._ui.addItems(["None (N)", "Required (R)"])
        exp_layout.addRow("User Interaction:", self._ui)
        
        layout.addWidget(exp_group)

        # Impact Metrics
        imp_group = QGroupBox("Impact Metrics")
        imp_layout = QFormLayout(imp_group)
        
        self._scope = QComboBox()
        self._scope.addItems(["Unchanged (U)", "Changed (C)"])
        imp_layout.addRow("Scope:", self._scope)
        
        self._conf = QComboBox()
        self._conf.addItems(["None (N)", "Low (L)", "High (H)"])
        imp_layout.addRow("Confidentiality:", self._conf)
        
        self._integ = QComboBox()
        self._integ.addItems(["None (N)", "Low (L)", "High (H)"])
        imp_layout.addRow("Integrity:", self._integ)
        
        self._avail = QComboBox()
        self._avail.addItems(["None (N)", "Low (L)", "High (H)"])
        imp_layout.addRow("Availability:", self._avail)
        
        layout.addWidget(imp_group)

        # Real-time Result Area
        self._score_label = QLabel("0.0")
        self._score_label.setFont(QFont("Segoe UI", 24, QFont.Weight.Bold))
        self._score_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._score_label.setStyleSheet("padding: 10px; background: #0d1117; border-radius: 8px; border: 1px solid #30363d;")
        layout.addWidget(self._score_label)

        self._vector_label = QLabel(self._vector)
        self._vector_label.setStyleSheet("color: #8b949e; font-family: 'Consolas', monospace; font-size: 11px;")
        self._vector_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._vector_label)

        # Buttons
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

        # Connections
        for cb in [self._av, self._ac, self._pr, self._ui, self._scope, self._conf, self._integ, self._avail]:
            cb.currentTextChanged.connect(self._recalculate)

    def _parse_vector(self, vector: str) -> None:
        """Apply a vector string to the UI components."""
        try:
            parts = {}
            for part in vector.split("/")[1:]:
                k, v = part.split(":")
                parts[k] = v
            
            # Helper to set combo by character in parentheses
            def set_combo(combo, val):
                for i in range(combo.count()):
                    if f"({val})" in combo.itemText(i):
                        combo.setCurrentIndex(i)
                        break

            set_combo(self._av, parts.get("AV", "N"))
            set_combo(self._ac, parts.get("AC", "L"))
            set_combo(self._pr, parts.get("PR", "N"))
            set_combo(self._ui, parts.get("UI", "N"))
            set_combo(self._scope, parts.get("S", "U"))
            set_combo(self._conf, parts.get("C", "H"))
            set_combo(self._integ, parts.get("I", "H"))
            set_combo(self._avail, parts.get("A", "H"))
            self._recalculate()
        except Exception:
            pass

    def _recalculate(self) -> None:
        """Update the score and vector string based on current UI state."""
        def get_val(combo):
            text = combo.currentText()
            return text[text.find("(")+1 : text.find(")")]

        new_vector = f"CVSS:3.1/AV:{get_val(self._av)}/AC:{get_val(self._ac)}/PR:{get_val(self._pr)}/UI:{get_val(self._ui)}/S:{get_val(self._scope)}/C:{get_val(self._conf)}/I:{get_val(self._integ)}/A:{get_val(self._avail)}"
        
        score, vector = calculate_cvss_31(new_vector)
        self._vector = vector
        self._score = score
        
        # Color score by severity
        color = "#ff4444" if score >= 9.0 else "#ff8800" if score >= 7.0 else "#ffbb33" if score >= 4.0 else "#00c851"
        self._score_label.setText(str(score))
        self._score_label.setStyleSheet(f"color: {color}; padding: 10px; background: #0d1117; border-radius: 8px; border: 1px solid #30363d;")
        self._vector_label.setText(vector)

    def get_result(self) -> tuple[float, str]:
        """Return the resulting score and vector."""
        return self._score, self._vector
