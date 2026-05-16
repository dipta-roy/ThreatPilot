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

from threatpilot.utils.paths import LOG_DIR, LOG_FILENAME

_SECRETS_TO_REDACT: list[str] = []

SECRET_PATTERNS = [
    re.compile(r"API_KEY=[\"']?(?P<secret>[a-zA-Z0-9_\-]{16,})[\"']?", re.IGNORECASE),
    re.compile(r"Bearer\s+(?P<secret>[a-zA-Z0-9_\-\.]{16,})", re.IGNORECASE),
    re.compile(r"([?&](?:key|token|auth|secret)=)(?P<secret>[a-zA-Z0-9_\-]{16,})", re.IGNORECASE),
    re.compile(r"(\"(?:api_key|secret|token|password|key)\":\s*\")(?P<secret>[a-zA-Z0-9_\-\.]{8,})(\")", re.IGNORECASE),
    re.compile(r"x-goog-api-key\s*:\s*(?P<secret>[a-zA-Z0-9_\-]{16,})", re.IGNORECASE),
]

class RedactingFormatter(logging.Formatter):
    """Intercepts and redacts sensitive patterns from log output."""
    def __init__(self, fmt: str | None = None, datefmt: str | None = None):
        super().__init__(fmt, datefmt)
    def format(self, record: logging.LogRecord) -> str:
        return sanitize_text(super().format(record))

def sanitize_text(text: str) -> str:
    """Masks secrets and known security patterns within the provided text."""
    if not text: return ""
    redacted = str(text)
    for s in _SECRETS_TO_REDACT:
        if s and len(s) > 8: redacted = redacted.replace(s, "[REDACTED]")
    
    def _redact_match(m: re.Match) -> str:
        full = m.group(0)
        try:
            start, end = m.span('secret')
            ls, le = start - m.start(0), end - m.start(0)
            return full[:ls] + "[REDACTED]" + full[le:]
        except (IndexError, KeyError):
            if len(m.groups()) >= 1:
                start, end = m.span(1); ls, le = start - m.start(0), end - m.start(0)
                return full[:ls] + "[REDACTED]" + full[le:]
        return "[REDACTED]"

    for pattern in SECRET_PATTERNS: redacted = pattern.sub(_redact_match, redacted)
    return redacted

def setup_logging(level: int = logging.INFO, project_path: str | Path | None = None) -> None:
    """Initializes the global logging subsystem with file and console outputs."""
    log_path = Path(project_path) / "logs" if project_path else LOG_DIR
    try: log_path.mkdir(parents=True, exist_ok=True)
    except OSError:
        log_path = Path.cwd() / "logs"; log_path.mkdir(parents=True, exist_ok=True)

    log_file = log_path / LOG_FILENAME; root = logging.getLogger(); root.setLevel(level)
    for h in list(root.handlers): root.removeHandler(h)

    log_fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    import sys
    if sys.stdout and sys.stdout.isatty():
        console = logging.StreamHandler()
        console.setFormatter(RedactingFormatter(log_fmt))
        root.addHandler(console)

    try:
        file = logging.handlers.RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3, encoding="utf-8")
        file.setFormatter(RedactingFormatter(log_fmt)); root.addHandler(file)
    except OSError as e: print(f"File logging failed: {e}")
    logging.info(f"Logging initialized at {logging.getLevelName(level)}. File: {log_file}")

def get_logger(name: str) -> logging.Logger:
    """Returns a logger instance for the specified module name."""
    return logging.getLogger(name)

def add_secret_to_redaction(secret: Any) -> None:
    """Registers a string or SecretStr for global redaction in logs."""
    if not secret: return
    raw = secret.get_secret_value() if hasattr(secret, "get_secret_value") else str(secret)
    if len(raw) > 8 and raw not in _SECRETS_TO_REDACT: _SECRETS_TO_REDACT.append(raw)
