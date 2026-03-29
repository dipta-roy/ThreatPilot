"""Logging utility for ThreatPilot.

Provides a configured root logger with rotating file and console handlers,
including sensitive data redaction for API keys.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import re
from pathlib import Path
from typing import Any

# Default log directory in the user's home folder
LOG_DIR = Path.home() / ".threatpilot" / "logs"
LOG_FILENAME = "threatpilot.log"

# Shared list of secrets to redact, populated at runtime
_SECRETS_TO_REDACT: list[str] = []

# Regex patterns for identifying potential secrets in logs (M.3)
SECRET_PATTERNS = [
    re.compile(r"API_KEY=[\"']?(?P<secret>[a-zA-Z0-9_\-]{16,})[\"']?", re.IGNORECASE),
    re.compile(r"Bearer\s+(?P<secret>[a-zA-Z0-9_\-\.]{16,})", re.IGNORECASE),
    re.compile(r"([?&](?:key|token|auth|secret)=)(?P<secret>[a-zA-Z0-9_\-]{16,})", re.IGNORECASE),
    re.compile(r"(\"(?:api_key|secret|token|password|key)\":\s*\")(?P<secret>[a-zA-Z0-9_\-\.]{8,})(\")", re.IGNORECASE),
    re.compile(r"x-goog-api-key\s*:\s*(?P<secret>[a-zA-Z0-9_\-]{16,})", re.IGNORECASE),
]

class RedactingFormatter(logging.Formatter):
    """Formatter that redacts sensitive information like API keys."""

    def __init__(self, fmt: str | None = None, datefmt: str | None = None):
        super().__init__(fmt, datefmt)
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return sanitize_text(original)

def sanitize_text(text: str) -> str:
    """Mask known secrets and sensitive patterns (M.3: Robust Redaction)."""
    if not text:
        return ""
    
    redacted = str(text)
    
    # 1. Redact known secrets from the global registry
    for secret in _SECRETS_TO_REDACT:
        if secret and len(secret) > 8:
            redacted = redacted.replace(secret, "[REDACTED]")
    
    # 2. Redact pattern-based secrets (M.3: Non-brittle regex substitution)
    def _redact_match(m: re.Match) -> str:
        full = m.group(0)
        # Identify the secret segment via the named "secret" group if available
        try:
            start, end = m.span('secret')
            local_start = start - m.start(0)
            local_end = end - m.start(0)
            return full[:local_start] + "[REDACTED]" + full[local_end:]
        except (IndexError, KeyError):
            # Generic fallback: redact the first capture group
            if m.groups() >= 1:
                start, end = m.span(1)
                local_start = start - m.start(0)
                local_end = end - m.start(0)
                return full[:local_start] + "[REDACTED]" + full[local_end:]
        return "[REDACTED]"

    for pattern in SECRET_PATTERNS:
        redacted = pattern.sub(_redact_match, redacted)
        
    return redacted

def setup_logging(level: int = logging.INFO, project_path: str | Path | None = None) -> None:
    """Initialize the application-level logging infrastructure.

    Args:
        level: Logging level (e.g. logging.DEBUG, logging.INFO).
        project_path: Optional project directory to store the log file in.
    """
    # Determine log path
    log_path = LOG_DIR
    if project_path:
        log_path = Path(project_path) / "logs"
    
    try:
        log_path.mkdir(parents=True, exist_ok=True)
    except OSError:
        # Fallback to current directory if home/project is unwritable
        log_path = Path.cwd() / "logs"
        log_path.mkdir(parents=True, exist_ok=True)

    log_file = log_path / LOG_FILENAME

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers if any (to avoid duplicates on multiple setup calls)
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    # Common format for both console and file
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    
    # Redaction list (can be expanded at runtime)
    # We don't import AIConfig here to avoid circular imports
    secrets_to_redact = []

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(RedactingFormatter(log_format))
    root_logger.addHandler(console_handler)

    # File Handler (Rotating, 5MB per file, keep 3 old logs)
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8"
        )
        file_handler.setFormatter(RedactingFormatter(log_format))
        root_logger.addHandler(file_handler)
    except OSError as e:
        print(f"Failed to initialize file logging: {e}")

    level_name = logging.getLevelName(level)
    logging.info(f"Logging initialized at {level_name}. Log file: {log_file}")

def get_logger(name: str) -> logging.Logger:
    """Helper to get a named logger."""
    return logging.getLogger(name)

def add_secret_to_redaction(secret: Any) -> None:
    """Register a new secret to be redacted from all future logs.
    
    Correctly handles Pydantic SecretStr objects (Finding 5.2).
    """
    if not secret:
        return
        
    # Extract raw value from Pydantic SecretStr if applicable
    raw_secret = secret
    if hasattr(secret, "get_secret_value"):
        raw_secret = secret.get_secret_value()
    
    raw_secret = str(raw_secret)
    
    if len(raw_secret) > 8 and raw_secret not in _SECRETS_TO_REDACT:
        _SECRETS_TO_REDACT.append(raw_secret)


# Expose constants in __all__ later when init is updated
