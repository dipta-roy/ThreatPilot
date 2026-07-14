"""Jira configuration module for ThreatPilot.

Contains the ``JiraConfig`` model representing Jira settings.
"""

from __future__ import annotations
import os
from pydantic import BaseModel, ConfigDict, SecretStr
import dotenv

from threatpilot.utils.crypto_utils import encrypt_api_key, decrypt_api_key
from threatpilot.utils.logger import add_secret_to_redaction
from threatpilot.utils.paths import CONFIG_FILE, THREATPILOT_HOME


class JiraConfig(BaseModel):
    """Encapsulates global Jira settings and persistence logic."""
    jira_url: str = ""
    jira_email: str = ""
    jira_api_token: SecretStr = SecretStr("")
    jira_project_key: str = ""
    jira_issue_type: str = "Story"

    model_config = ConfigDict(extra="ignore", protected_namespaces=())

    @property
    def api_token(self) -> str:
        """Retrieves the active API token for Jira."""
        return self.jira_api_token.get_secret_value()

    @api_token.setter
    def api_token(self, value: str) -> None:
        """Sets the API token for Jira."""
        self.jira_api_token = SecretStr(value)

    @classmethod
    def load(cls) -> JiraConfig:
        """Deserializes configuration from environment variables or file with decryption."""
        file_values = dotenv.dotenv_values(str(CONFIG_FILE)) if CONFIG_FILE.exists() else {}
        
        def get_val(k: str, d: str) -> str:
            # Environment variables take precedence over file values
            v = os.environ.get(k) or file_values.get(k, d) or d
            return str(v).strip().strip("'\"").replace("\n", "").replace("\r", "")

        def scrub(k: str) -> str:
            # Prevent corrupted/traceback strings from being loaded as keys
            return "" if not k or k.lower().startswith("traceback") else k

        config = cls(
            jira_url=get_val("JIRA_URL", ""),
            jira_email=get_val("JIRA_EMAIL", ""),
            jira_api_token=SecretStr(scrub(decrypt_api_key(get_val("JIRA_API_TOKEN", "")))),
            jira_project_key=get_val("JIRA_PROJECT_KEY", ""),
            jira_issue_type=get_val("JIRA_ISSUE_TYPE", "Story"),
        )
        add_secret_to_redaction(config.jira_api_token)
        return config

    def save(self) -> None:
        """Serializes the current configuration to the environment file with encryption."""
        THREATPILOT_HOME.mkdir(parents=True, exist_ok=True)
        path = str(CONFIG_FILE)
        fields = {
            "JIRA_URL": self.jira_url,
            "JIRA_EMAIL": self.jira_email,
            "JIRA_PROJECT_KEY": self.jira_project_key,
            "JIRA_ISSUE_TYPE": self.jira_issue_type,
        }
        try:
            for k, v in fields.items(): 
                dotenv.set_key(path, k, v)
            if (key := self.jira_api_token.get_secret_value()):
                if (enc := encrypt_api_key(key)): 
                    dotenv.set_key(path, "JIRA_API_TOKEN", enc)
            else: 
                dotenv.unset_key(path, "JIRA_API_TOKEN")
        except Exception:
            try:
                with open(path, "a", encoding="utf-8") as f:
                    for k, v in fields.items(): 
                        f.write(f"{k}={v}\n")
                    if (key := self.jira_api_token.get_secret_value()):
                        f.write(f"JIRA_API_TOKEN={encrypt_api_key(key)}\n")
            except Exception: 
                pass
