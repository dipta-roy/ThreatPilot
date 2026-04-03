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
import os

SERVICE_NAME = "ThreatPilot"
KEY_ID = "MasterEncryptionKey"
SALT = b"\x89\x1e(\xca\x0c\x84W\x8e\x9c\xd8\x8f\x8e\xe6\xcf\x80\xb0"

def _get_or_create_master_key() -> str:
    """Retrieve or derive the master key from OS vault (H.2)."""
    source_entropy = os.environ.get("THREATPILOT_MASTER_KEY")
    is_user_provided = bool(source_entropy)
    if is_user_provided:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100000
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(str(source_entropy).encode('utf-8')))
        return derived_key.decode('utf-8')

    raw_key = keyring.get_password(SERVICE_NAME, KEY_ID)
    
    if not raw_key:
        source_entropy = os.urandom(32).hex()

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=100000
        )
        derived_key = base64.urlsafe_b64encode(kdf.derive(str(source_entropy).encode('utf-8')))
        raw_key = derived_key.decode('utf-8')
        
        keyring.set_password(SERVICE_NAME, KEY_ID, raw_key)
        
    return raw_key

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
        return ""
