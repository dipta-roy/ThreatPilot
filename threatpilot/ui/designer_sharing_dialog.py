from __future__ import annotations
import random
import socket
from PySide6.QtCore import Qt, QUrl
from PySide6.QtGui import QFont, QDesktopServices
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QWidget,
    QLabel,
    QRadioButton,
    QButtonGroup,
    QFrame,
    QMessageBox
)

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

class DesignerSharingDialog(QDialog):
    """Dialog to configure Visual Designer workspace hosting (Shared vs Local-only)."""
    def __init__(self, main_window: QWidget, parent: QWidget | None = None, is_dark: bool = True):
        super().__init__(parent)
        self.main_window = main_window
        self._is_dark = is_dark
        self.setWindowTitle("Host Architecture Workspace")
        self.resize(550, 420)
        self.setMinimumWidth(500)
        
        self.local_ip = get_local_ip()
        self.generated_pin = ""
        self.active_host = "127.0.0.1"
        self.active_shared = False
        
        # Pull current server status if running
        server_thread = getattr(self.main_window, "_designer_server_thread", None)
        if server_thread and server_thread.server:
            self.active_host = server_thread.host
            self.active_shared = getattr(server_thread.server, "sharing_active", False)
            self.generated_pin = getattr(server_thread.server, "pin_code", "")
            
        self.setup_ui()
        self.sync_ui_state()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Header title
        title_label = QLabel("Host Architecture Workspace")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_color = "#58a6ff" if self._is_dark else "#3b82f6"
        title_label.setStyleSheet(f"color: {title_color};")
        layout.addWidget(title_label)
        
        desc_label = QLabel(
            "Configure hosting for the interactive Web Architecture Designer. "
            "You can restrict access to this machine only or share it over the local network with authentication."
        )
        desc_label.setWordWrap(True)
        desc_color = "#8b949e" if self._is_dark else "#6b7280"
        desc_label.setStyleSheet(f"color: {desc_color}; font-size: 11px;")
        layout.addWidget(desc_label)
        
        # Mode options box
        options_frame = QFrame()
        options_frame.setFrameShape(QFrame.StyledPanel)
        options_bg = "#161b22" if self._is_dark else "palette(alternate-base)"
        options_border = "#30363d" if self._is_dark else "palette(midlight)"
        options_frame.setStyleSheet(f".QFrame {{ background-color: {options_bg}; border-radius: 8px; border: 1px solid {options_border}; }}")
        options_layout = QVBoxLayout(options_frame)
        options_layout.setSpacing(10)
        
        self.group = QButtonGroup(self)
        
        self.radio_local = QRadioButton("Local Only (Access from this computer only via 127.0.0.1)")
        self.radio_local.setChecked(not self.active_shared)
        self.group.addButton(self.radio_local)
        options_layout.addWidget(self.radio_local)
        
        self.radio_shared = QRadioButton("Shared (Access from any computer on local network)")
        self.radio_shared.setChecked(self.active_shared)
        self.group.addButton(self.radio_shared)
        options_layout.addWidget(self.radio_shared)
        
        layout.addWidget(options_frame)
        
        # Details/PIN display panel
        self.detail_frame = QFrame()
        self.detail_frame.setFrameShape(QFrame.StyledPanel)
        detail_bg = "#0d1117" if self._is_dark else "palette(base)"
        detail_border = "#30363d" if self._is_dark else "palette(midlight)"
        self.detail_frame.setStyleSheet(f".QFrame {{ background-color: {detail_bg}; border-radius: 8px; border: 1px solid {detail_border}; }}")
        detail_layout = QVBoxLayout(self.detail_frame)
        detail_layout.setSpacing(8)
        
        # PIN code field
        pin_lbl = QLabel("6-Digit Authentication PIN:")
        pin_lbl.setFont(QFont("Arial", 11, QFont.Bold))
        pin_lbl.setAlignment(Qt.AlignCenter)
        detail_layout.addWidget(pin_lbl)
        
        self.pin_val = QLabel("123456")
        pin_font = QFont("Courier New", 32, QFont.Bold)
        pin_font.setLetterSpacing(QFont.AbsoluteSpacing, 8.0)
        self.pin_val.setFont(pin_font)
        self.pin_val.setAlignment(Qt.AlignCenter)
        pin_bg = "#450a0a" if self._is_dark else "#fef2f2"
        pin_color = "#f87171" if self._is_dark else "#ef4444"
        pin_border = "#991b1b" if self._is_dark else "#fca5a5"
        
        self.pin_val.setStyleSheet(f"""
            QLabel {{
                background-color: {pin_bg};
                color: {pin_color};
                border: 2px dashed {pin_border};
                border-radius: 8px;
                padding: 10px;
                margin-left: 20px;
                margin-right: 20px;
            }}
        """)
        detail_layout.addWidget(self.pin_val)
        
        # URL field
        url_lbl = QLabel("Network Access URL:")
        url_lbl.setFont(QFont("Arial", 10, QFont.Bold))
        url_lbl.setAlignment(Qt.AlignCenter)
        url_lbl.setStyleSheet("margin-top: 10px;")
        detail_layout.addWidget(url_lbl)
        
        self.url_val = QLabel(f"http://{self.local_ip}:8080/")
        self.url_val.setFont(QFont("Courier New", 12))
        self.url_val.setAlignment(Qt.AlignCenter)
        self.url_val.setTextInteractionFlags(Qt.TextSelectableByMouse)
        
        url_bg = "#172554" if self._is_dark else "#eff6ff"
        url_color = "#60a5fa" if self._is_dark else "#2563eb"
        url_border = "#1e3a8a" if self._is_dark else "#bfdbfe"
        
        self.url_val.setStyleSheet(f"""
            QLabel {{
                background-color: {url_bg};
                color: {url_color};
                border: 1px solid {url_border};
                border-radius: 6px;
                padding: 8px;
                margin-left: 20px;
                margin-right: 20px;
            }}
        """)
        detail_layout.addWidget(self.url_val)
        
        self.status_lbl = QLabel("Status: Shared workspace is active on local network.")
        self.status_lbl.setAlignment(Qt.AlignCenter)
        self.status_lbl.setStyleSheet("color: #10b981; font-size: 11px; font-weight: bold; margin-top: 5px;")
        detail_layout.addWidget(self.status_lbl)
        
        layout.addWidget(self.detail_frame)
        
        # Action Buttons Layout
        btn_layout = QHBoxLayout()
        
        self.btn_action = QPushButton("Start Sharing")
        self.btn_action.clicked.connect(self._on_action_clicked)
        self.btn_action.setStyleSheet("QPushButton { padding: 6px 12px; font-weight: bold; }")
        btn_layout.addWidget(self.btn_action)
        
        self.btn_launch = QPushButton("Launch Workspace")
        self.btn_launch.clicked.connect(self._on_launch_clicked)
        btn_layout.addWidget(self.btn_launch)
        
        btn_layout.addStretch()
        
        self.btn_close = QPushButton("Close")
        self.btn_close.clicked.connect(self.accept)
        btn_layout.addWidget(self.btn_close)
        
        layout.addLayout(btn_layout)
        
        # Connect toggles
        self.radio_local.toggled.connect(self.sync_ui_state)
        self.radio_shared.toggled.connect(self.sync_ui_state)

    def sync_ui_state(self):
        is_shared = self.radio_shared.isChecked()
        
        if is_shared:
            if not self.generated_pin:
                self.generated_pin = str(random.randint(100000, 999999))
            
            self.pin_val.setText(self.generated_pin)
            self.url_val.setText(f"http://{self.local_ip}:8080/")
            self.detail_frame.setVisible(True)
            self.btn_action.setEnabled(True)
            
            if self.active_shared:
                self.btn_action.setText("Stop Sharing")
                self.status_lbl.setText("Status: Sharing active. Remote users must enter PIN to access.")
                self.status_lbl.setStyleSheet("color: #10b981; font-size: 10px; font-weight: bold;")
            else:
                self.btn_action.setText("Start Sharing")
                self.status_lbl.setText("Status: Configured. Click 'Start Sharing' to bind to all interfaces.")
                self.status_lbl.setStyleSheet("color: #f59e0b; font-size: 10px; font-weight: bold;")
            self.btn_launch.setEnabled(self.active_shared)
        else:
            self.detail_frame.setVisible(False)
            self.btn_action.setText("Apply Changes")
            
            # If active host is currently sharing, we show apply changes to drop to local
            if self.active_shared:
                self.btn_action.setEnabled(True)
            else:
                self.btn_action.setEnabled(False) # already local only
            self.btn_launch.setEnabled(True)

    def _on_action_clicked(self):
        is_shared = self.radio_shared.isChecked()
        
        if is_shared:
            if self.active_shared:
                # Stop sharing -> Drop back to local bound server
                self.main_window.start_designer_server(host="127.0.0.1", shared=False)
                self.active_shared = False
                self.active_host = "127.0.0.1"
                self.generated_pin = ""
                QMessageBox.information(self, "Sharing Stopped", "Visual workspace sharing has been disabled. Server reverted to localhost only.")
            else:
                # Start sharing
                if not self.generated_pin:
                    self.generated_pin = str(random.randint(100000, 999999))
                self.main_window.start_designer_server(host="0.0.0.0", shared=True, pin=self.generated_pin)
                self.active_shared = True
                self.active_host = "0.0.0.0"
                QMessageBox.information(self, "Sharing Enabled", f"Visual workspace is now shared on local network!\n\nAccess URL: http://{self.local_ip}:8080/\nPIN Code: {self.generated_pin}")
        else:
            # Revert from shared to local only
            self.main_window.start_designer_server(host="127.0.0.1", shared=False)
            self.active_shared = False
            self.active_host = "127.0.0.1"
            self.generated_pin = ""
            QMessageBox.information(self, "Configuration Reverted", "Server has been bound to local loopback (127.0.0.1) only.")
            
        self.sync_ui_state()

    def _on_launch_clicked(self):
        url_str = f"http://{self.local_ip if self.active_shared else '127.0.0.1'}:8080/"
        QDesktopServices.openUrl(QUrl(url_str))
        self.accept()
