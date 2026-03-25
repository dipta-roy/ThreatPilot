"""Encryption utility for ThreatPilot.

Provides secure storage for sensitive data (like API keys) by:
1. Generating a machine-specific encryption key if none exists.
2. Storing that key in the OS Credential Manager (via keyring).
3. Using Fernet (AES-128 in CBC mode) for symmetric encryption/decryption.
"""

import base64
import keyring
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SERVICE_NAME = "ThreatPilot"
KEY_ID = "MasterEncryptionKey"

def _get_or_create_master_key() -> str:
    """Retrieve the master key from keyring, or generate it if missing."""
    key = keyring.get_password(SERVICE_NAME, KEY_ID)
    if not key:
        # Generate a new random Fernet key
        key = Fernet.generate_key().decode('utf-8')
        keyring.set_password(SERVICE_NAME, KEY_ID, key)
    return key

def encrypt_api_key(api_key: str) -> str:
    """Encrypt a plain text API key into a base64 encoded string."""
    if not api_key:
        return ""
    
    master_key = _get_or_create_master_key()
    f = Fernet(master_key.encode('utf-8'))
    encrypted_bytes = f.encrypt(api_key.encode('utf-8'))
    return encrypted_bytes.decode('utf-8')

def decrypt_api_key(encrypted_key: str) -> str:
    """Decrypt an encrypted API key back to plain text."""
    if not encrypted_key:
        return ""
    
    try:
        master_key = _get_or_create_master_key()
        f = Fernet(master_key.encode('utf-8'))
        decrypted_bytes = f.decrypt(encrypted_key.encode('utf-8'))
        return decrypted_bytes.decode('utf-8')
    except Exception:
        # If decryption fails (e.g. key changed or data corrupted), return empty
        return ""
