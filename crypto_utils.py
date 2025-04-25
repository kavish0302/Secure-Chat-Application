import hashlib
import os
import base64
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT = b'secure_salt_value_123'

def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """
    Hash a password using PBKDF2-HMAC-SHA256.
    
    Args:
        password: The password to hash
        salt: Optional salt, if not provided a random one will be generated
        
    Returns:
        tuple of (salt_base64, hash_base64)
    """
    if not salt:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return base64.b64encode(salt).decode(), base64.b64encode(hashed).decode()

def verify_password(password: str, salt_b64: str, hash_b64: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        password: The password to verify
        salt_b64: Base64 encoded salt
        hash_b64: Base64 encoded hash
        
    Returns:
        bool: True if password matches, False otherwise
    """
    salt = base64.b64decode(salt_b64.encode())
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100_000)
    return base64.b64encode(hashed).decode() == hash_b64

def derive_key(password: str) -> bytes:
    """
    Derive an encryption key from a password using PBKDF2.
    
    Args:
        password: The password to derive key from
        
    Returns:
        bytes: The derived key suitable for Fernet encryption
    """
    if not isinstance(password, bytes):
        password_bytes = password.encode()
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes if isinstance(password, bytes) else password.encode()))
    return key

def encrypt_message(key: bytes, message: str) -> str:
    """
    Encrypt a message using Fernet symmetric encryption.
    
    Args:
        key: The encryption key (must be URL-safe base64-encoded)
        message: The message to encrypt
        
    Returns:
        str: The encrypted message as a base64-encoded string
    """
    if not isinstance(message, bytes):
        message_bytes = message.encode()
    
    f = Fernet(key)
    encrypted_message = f.encrypt(message_bytes if isinstance(message, str) else message)
    return encrypted_message.decode()

def decrypt_message(key: bytes, encrypted_message: str) -> str:
    """
    Decrypt a message using Fernet symmetric encryption.
    
    Args:
        key: The encryption key (must be URL-safe base64-encoded)
        encrypted_message: The encrypted message to decrypt
        
    Returns:
        str: The decrypted message
    """
    if not isinstance(encrypted_message, bytes):
        encrypted_message = encrypted_message.encode().decode()
    
    f = Fernet(key)
    try:
        decrypted_message = f.decrypt(encrypted_message)
        return decrypted_message.decode()
    except Exception as e:
        return f"Error decrypting message: {str(e)}"

def generate_key() -> bytes:
    """
    Generate a new random encryption key.
    
    Returns:
        bytes: A new Fernet encryption key
    """
    return Fernet.generate_key()
