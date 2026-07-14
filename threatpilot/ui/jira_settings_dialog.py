from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
    QLineEdit, QPushButton, QFormLayout, QDialogButtonBox, QMessageBox
)
from PySide6.QtCore import Qt

from threatpilot.config.jira_config import JiraConfig
from threatpilot.core.jira_service import JiraService


class JiraSettingsDialog(QDialog):
    """Dialog for configuring Jira settings."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Jira Settings")
        self.setMinimumWidth(400)
        
        # Load existing config
        self.config = JiraConfig.load()
        
        self._setup_ui()
        
    def _setup_ui(self):
        layout = QVBoxLayout(self)
        
        # Info label
        info_lbl = QLabel(
            "Configure your Jira credentials to enable syncing mitigations directly to your backlog."
        )
        info_lbl.setWordWrap(True)
        layout.addWidget(info_lbl)
        
        # Form layout
        form = QFormLayout()
        
        self.url_input = QLineEdit(self.config.jira_url)
        self.url_input.setPlaceholderText("https://your-domain.atlassian.net")
        form.addRow("Jira URL:", self.url_input)

        self.email_input = QLineEdit(self.config.jira_email)
        self.email_input.setPlaceholderText("you@example.com")
        form.addRow("Jira Email:", self.email_input)

        self.token_input = QLineEdit(self.config.api_token)
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_input.setPlaceholderText("Jira API Token")
        form.addRow("API Token:", self.token_input)

        self.project_input = QLineEdit(self.config.jira_project_key)
        self.project_input.setPlaceholderText("e.g. SEC")
        form.addRow("Project Key:", self.project_input)

        self.issue_type_input = QLineEdit(self.config.jira_issue_type)
        self.issue_type_input.setPlaceholderText("e.g. Story")
        form.addRow("Issue Type:", self.issue_type_input)
        
        layout.addLayout(form)
        
        # Test connection button
        test_layout = QHBoxLayout()
        self.test_btn = QPushButton("Test Connection")
        self.test_btn.clicked.connect(self._test_connection)
        test_layout.addWidget(self.test_btn)
        test_layout.addStretch()
        layout.addLayout(test_layout)
        
        # Dialog buttons
        self.button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        self.button_box.accepted.connect(self._save_settings)
        self.button_box.rejected.connect(self.reject)
        
        layout.addWidget(self.button_box)

    def _test_connection(self):
        """Tests the Jira connection with the provided credentials."""
        temp_config = JiraConfig(
            jira_url=self.url_input.text().strip(),
            jira_email=self.email_input.text().strip(),
            jira_project_key=self.project_input.text().strip(),
            jira_issue_type=self.issue_type_input.text().strip()
        )
        temp_config.api_token = self.token_input.text().strip()
        
        self.test_btn.setEnabled(False)
        self.test_btn.setText("Testing...")
        
        service = JiraService(temp_config)
        success, message = service.verify_connection()
        
        if success:
            QMessageBox.information(self, "Success", "Successfully connected to Jira!")
        else:
            QMessageBox.critical(self, "Connection Failed", f"Failed to connect:\n\n{message}")
            
        self.test_btn.setEnabled(True)
        self.test_btn.setText("Test Connection")

    def _save_settings(self):
        """Saves the settings and closes the dialog."""
        self.config.jira_url = self.url_input.text().strip()
        self.config.jira_email = self.email_input.text().strip()
        self.config.api_token = self.token_input.text().strip()
        self.config.jira_project_key = self.project_input.text().strip()
        self.config.jira_issue_type = self.issue_type_input.text().strip()
        
        self.config.save()
        super().accept()
