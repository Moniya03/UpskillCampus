import os
import base64
import json
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# This file contains all functions related to encryption, decryption, and key derivation.

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from a password and salt using PBKDF2.
    This is a key-stretching algorithm that makes brute-force attacks much harder.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,  # A high number of iterations is recommended
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_data(data: dict, key: bytes) -> bytes:
    """
    Serializes a dictionary to JSON, then encrypts it using the derived key.
    """
    f = Fernet(key)
    json_data = json.dumps(data).encode('utf-8')
    return f.encrypt(json_data)

def decrypt_data(encrypted_data: bytes, key: bytes) -> dict | None:
    """
    Decrypts the data and deserializes it from JSON.
    Returns None if the key is incorrect or the data is tampered with.
    """
    f = Fernet(key)
    try:
        decrypted_json = f.decrypt(encrypted_data)
        return json.loads(decrypted_json.decode('utf-8'))
    except InvalidToken:
        # This exception is caught if the key is wrong (wrong master password)
        return None
