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

log = logging.getLogger(__name__)

SERVICE_NAME = "ThreatPilot"
KEY_ID = "MasterEncryptionKey"
SALT = b"\x89\x1e(\xca\x0c\x84W\x8e\x9c\xd8\x8f\x8e\xe6\xcf\x80\xb0"

# Global cache to avoid repeated file/keyring access
_MASTER_KEY_CACHE: str | None = None

def _app_data_dir() -> Path:
    """Return a writable directory for app-specific data files (~/.threatpilot)."""
    base_dir = Path.home() / ".threatpilot"
    base_dir.mkdir(parents=True, exist_ok=True)
    return base_dir


def _fallback_key_file() -> Path:
    """Return the path to the local master-key fallback file (~/.threatpilot/.keystore)."""
    return _app_data_dir() / ".keystore"


def _derive_fernet_key(entropy: str) -> str:
    """Derive a Fernet-compatible key from arbitrary entropy bytes."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
    )
    derived = base64.urlsafe_b64encode(kdf.derive(entropy.encode("utf-8")))
    return derived.decode("utf-8")


def _keyring_get() -> str | None:
    """Try to read the master key from the OS credential store."""
    try:
        import keyring
        try:
            # Force discovery/setting of backend for frozen environments
            import keyring.backends.Windows
            from keyring.backends.Windows import WinVaultKeyring
            keyring.set_keyring(WinVaultKeyring())
        except Exception:
            pass
            
        val = keyring.get_password(SERVICE_NAME, KEY_ID)
        return val if val else None
    except Exception as exc:
        log.debug("keyring read failed: %s", exc)
        return None


def _keyring_set(value: str) -> bool:
    """Try to store the master key in the OS credential store."""
    try:
        import keyring
        try:
            import keyring.backends.Windows
            from keyring.backends.Windows import WinVaultKeyring
            keyring.set_keyring(WinVaultKeyring())
        except Exception:
            pass
            
        keyring.set_password(SERVICE_NAME, KEY_ID, value)
        return True
    except Exception as exc:
        log.debug("keyring write failed: %s", exc)
        return False


def _get_or_create_master_key() -> str:
    """Return a Fernet-compatible master key, creating one if needed."""
    global _MASTER_KEY_CACHE
    if _MASTER_KEY_CACHE:
        return _MASTER_KEY_CACHE

    # 1. Manual override
    env_key = os.environ.get("THREATPILOT_MASTER_KEY")
    if env_key:
        _MASTER_KEY_CACHE = _derive_fernet_key(env_key)
        return _MASTER_KEY_CACHE

    # 2. Try keyring
    raw_key = _keyring_get()
    if raw_key:
        _MASTER_KEY_CACHE = raw_key
        return _MASTER_KEY_CACHE

    # 3. Local fallback file
    fb = _fallback_key_file()
    if fb.exists():
        try:
            raw_key = fb.read_text(encoding="utf-8").strip()
            if raw_key:
                _MASTER_KEY_CACHE = raw_key
                return _MASTER_KEY_CACHE
        except Exception as exc:
            log.debug("Failed to read fallback key file: %s", exc)

    # 4. Generate new key
    new_entropy = os.urandom(32).hex()
    raw_key = _derive_fernet_key(new_entropy)

    # Persist
    _keyring_set(raw_key)
    try:
        fb.parent.mkdir(parents=True, exist_ok=True)
        fb.write_text(raw_key, encoding="utf-8")
    except Exception as exc:
        log.warning("Could not persist master key to file: %s", exc)

    _MASTER_KEY_CACHE = raw_key
    return _MASTER_KEY_CACHE


def encrypt_api_key(api_key: str) -> str:
    """Encrypt a plain-text API key and return a Fernet token string."""
    if not api_key:
        return ""
    try:
        master_key = _get_or_create_master_key()
        f = Fernet(master_key.encode("utf-8"))
        return f.encrypt(api_key.encode("utf-8")).decode("utf-8")
    except Exception as exc:
        log.error("encrypt_api_key failed: %s", exc)
        return ""


def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt a Fernet token back to the original plain-text API key."""
    if not encrypted_key:
        return ""
    try:
        master_key = _get_or_create_master_key()
        f = Fernet(master_key.encode("utf-8"))
        return f.decrypt(encrypted_key.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        log.warning("decrypt_api_key: invalid token - key may have changed")
        return ""
    except Exception as exc:
        log.error("decrypt_api_key failed: %s", exc)
        return ""
