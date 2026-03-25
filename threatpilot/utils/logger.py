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

# Regex patterns for identifying potential secrets in logs
SECRET_PATTERNS = [
    re.compile(r"API_KEY=[\"']?([a-zA-Z0-9_\-]{16,})[\"']?", re.IGNORECASE),
    re.compile(r"Bearer\s+([a-zA-Z0-9_\-\.]{16,})", re.IGNORECASE),
]

class RedactingFormatter(logging.Formatter):
    """Formatter that redacts sensitive information like API keys."""

    def __init__(self, fmt: str | None = None, datefmt: str | None = None):
        super().__init__(fmt, datefmt)
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        redacted = original
        
        # Redact known secrets
        for secret in _SECRETS_TO_REDACT:
            if secret and len(secret) > 8:
                redacted = str(redacted).replace(secret, "[REDACTED]")
        
        # Apply regex patterns for common secret formats
        for pattern in SECRET_PATTERNS:
            redacted = pattern.sub(lambda m: m.group(0).replace(m.group(1), "[REDACTED]"), redacted)
            
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

    logging.info(f"Logging initialized at {level}. Log file: {log_file}")

def get_logger(name: str) -> logging.Logger:
    """Helper to get a named logger."""
    return logging.getLogger(name)

def add_secret_to_redaction(secret: str) -> None:
    """Register a new secret (like an API key) to be redacted from all future logs.

    Args:
        secret: The sensitive string to redact.
    """
    if secret and len(secret) > 8 and secret not in _SECRETS_TO_REDACT:
        _SECRETS_TO_REDACT.append(secret)


# Expose constants in __all__ later when init is updated
