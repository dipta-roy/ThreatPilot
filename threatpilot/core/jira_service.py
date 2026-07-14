"""Jira service module for integrating ThreatPilot mitigations with Jira."""

import base64
import httpx
from typing import Tuple
from threatpilot.config.jira_config import JiraConfig
from threatpilot.core.domain_models import MitigationRequirement


class JiraService:
    """Service to handle Jira API operations."""

    def __init__(self, config: JiraConfig):
        self.config = config

    def _get_auth_headers(self) -> dict:
        """Returns the authentication headers for Jira API."""
        auth_string = f"{self.config.jira_email}:{self.config.api_token}"
        encoded_auth = base64.b64encode(auth_string.encode('utf-8')).decode('utf-8')
        return {
            "Authorization": f"Basic {encoded_auth}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    def verify_connection(self) -> Tuple[bool, str]:
        """Tests the connection to Jira.
        
        Returns:
            Tuple[bool, str]: Success flag and a message (error details if failed).
        """
        if not self.config.jira_url or not self.config.jira_email or not self.config.api_token:
            return False, "Jira URL, Email, or API Token is missing."

        url = f"{self.config.jira_url.rstrip('/')}/rest/api/3/myself"
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.get(url, headers=self._get_auth_headers())
                response.raise_for_status()
                return True, "Connection successful."
        except httpx.HTTPStatusError as e:
            return False, f"HTTP Error: {e.response.status_code} - {e.response.text}"
        except Exception as e:
            return False, f"Connection failed: {str(e)}"

    def create_issue(self, mitigation: MitigationRequirement) -> Tuple[bool, str]:
        """Creates a Jira User Story from a MitigationRequirement.
        
        Returns:
            Tuple[bool, str]: Success flag and either the Jira Issue Key or error message.
        """
        if not self.config.jira_project_key:
            return False, "Jira Project Key is not configured."

        url = f"{self.config.jira_url.rstrip('/')}/rest/api/3/issue"
        
        description_text = f"**Short Description:**\n{mitigation.short_description}\n\n" \
                           f"**Affected Components:**\n{mitigation.affected_components}\n\n" \
                           f"**Mitigation Steps:**\n{mitigation.mitigation}\n\n" \
                           f"**Test Case / Validation:**\n{mitigation.test_case}\n"
                           
        if mitigation.reasoning:
            description_text += f"\n**XAI Reasoning:**\n{mitigation.reasoning}\n"

        # Jira REST API v3 uses Atlassian Document Format (ADF)
        description_adf = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {
                            "text": description_text,
                            "type": "text"
                        }
                    ]
                }
            ]
        }

        payload = {
            "fields": {
                "project": {
                    "key": self.config.jira_project_key
                },
                "summary": mitigation.title or "Security Mitigation",
                "description": description_adf,
                "issuetype": {
                    "name": self.config.jira_issue_type or "Story"
                }
            }
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                response = client.post(url, headers=self._get_auth_headers(), json=payload)
                response.raise_for_status()
                data = response.json()
                issue_key = data.get("key")
                return True, issue_key
        except httpx.HTTPStatusError as e:
            return False, f"HTTP Error: {e.response.status_code} - {e.response.text}"
        except Exception as e:
            return False, f"Failed to create issue: {str(e)}"
