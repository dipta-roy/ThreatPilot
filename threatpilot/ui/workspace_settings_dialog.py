from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QSpinBox, QPushButton, QFormLayout, QDialogButtonBox, QMessageBox
)
from PySide6.QtCore import Qt

class WorkspaceSettingsDialog(QDialog):
    """Dialog for configuring workspace settings like the port."""
    
    def __init__(self, current_port: int, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Workspace Settings")
        self.setMinimumWidth(300)
        
        self.selected_port = current_port
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Info label
        info_lbl = QLabel(
            "Configure the port used for local and shared workspace servers.<br>"
            "<i>Note: A restart of the server is required for changes to take effect.</i>"
        )
        info_lbl.setWordWrap(True)
        layout.addWidget(info_lbl)
        
        # Form layout
        form = QFormLayout()
        
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(self.selected_port)
        self.port_spin.setToolTip("Port number to run the workspace server on.")
        
        form.addRow("Server Port:", self.port_spin)
        
        layout.addLayout(form)
        
        # Dialog buttons
        self.button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        
        layout.addWidget(self.button_box)
        
    def accept(self):
        self.selected_port = self.port_spin.value()
        super().accept()
