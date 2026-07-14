"""Encryption utility for ThreatPilot.

Provides secure storage for sensitive data (like API keys) by:
1. Generating a machine-specific encryption key if none exists.
2. Storing that key in a local file or the OS Credential Manager.
3. Using Fernet (AES-128 in CBC mode) for symmetric encryption/decryption.
"""

import base64
import logging
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from threatpilot.utils.paths import THREATPILOT_HOME, KEYSTORE_FILE

log = logging.getLogger(__name__)

SERVICE_NAME = "ThreatPilot"
KEY_ID = "MasterEncryptionKey"
SALT = b"\x89\x1e(\xca\x0c\x84W\x8e\x9c\xd8\x8f\x8e\xe6\xcf\x80\xb0"

# Global cache to avoid repeated file/keyring access
_MASTER_KEY_CACHE: str | None = None

def _get_keyring():
    """Import and configure keyring backend lazily."""
    try:
        import keyring
        try:
            from keyring.backends.Windows import WinVaultKeyring
            keyring.set_keyring(WinVaultKeyring())
        except (ImportError, Exception):
            pass
        return keyring
    except ImportError:
        return None

def _derive_fernet_key(entropy: str) -> str:
    """Derives a cryptographically secure Fernet-compatible key from entropy bytes."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, iterations=100_000)
    return base64.urlsafe_b64encode(kdf.derive(entropy.encode("utf-8"))).decode("utf-8")

def _keyring_get() -> str | None:
    """Retrieves the master encryption key from the OS-native credential manager."""
    try:
        kr = _get_keyring()
        return kr.get_password(SERVICE_NAME, KEY_ID) if kr else None
    except Exception as exc:
        log.debug("keyring read failed: %s", exc)
        return None

def _keyring_set(value: str) -> bool:
    """Persists the master encryption key into the OS-native credential manager."""
    try:
        kr = _get_keyring()
        if kr:
            kr.set_password(SERVICE_NAME, KEY_ID, value)
            return True
        return False
    except Exception as exc:
        log.debug("keyring write failed: %s", exc)
        return False

def _get_or_create_master_key() -> str:
    """Retrieves or initializes the master encryption key for the local machine."""
    global _MASTER_KEY_CACHE
    if _MASTER_KEY_CACHE:
        return _MASTER_KEY_CACHE

    if (env_key := os.environ.get("THREATPILOT_MASTER_KEY")):
        _MASTER_KEY_CACHE = _derive_fernet_key(env_key)
        return _MASTER_KEY_CACHE

    if (raw_key := _keyring_get()):
        _MASTER_KEY_CACHE = raw_key
        return _MASTER_KEY_CACHE

    fb = KEYSTORE_FILE
    if fb.exists():
        try:
            if (raw_key := fb.read_text(encoding="utf-8").strip()):
                _MASTER_KEY_CACHE = raw_key
                return _MASTER_KEY_CACHE
        except Exception as exc:
            log.debug("Keystore read failed: %s", exc)

    raw_key = _derive_fernet_key(os.urandom(32).hex())
    _keyring_set(raw_key)
    try:
        fb.parent.mkdir(parents=True, exist_ok=True)
        fb.write_text(raw_key, encoding="utf-8")
    except Exception as exc:
        log.warning("Key persistence failed: %s", exc)

    _MASTER_KEY_CACHE = raw_key
    return _MASTER_KEY_CACHE

def encrypt_api_key(api_key: str) -> str:
    """Symmetrically encrypts a plain-text API key for secure local storage."""
    if not api_key: return ""
    try:
        f = Fernet(_get_or_create_master_key().encode("utf-8"))
        return f.encrypt(api_key.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        log.error("Encryption failed: %s", exc); return ""

def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypts a previously encrypted API key back to plain-text."""
    if not encrypted_key: return ""
    try:
        f = Fernet(_get_or_create_master_key().encode("utf-8"))
        return f.decrypt(encrypted_key.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        log.warning("Decryption failed: invalid token. Assuming plain-text key provided.")
        return encrypted_key
    except Exception as exc:
        log.error("Decryption failed: %s", exc)
        return ""
