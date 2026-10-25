import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt_file(data: bytes) -> dict:
    """Encrypt file bytes using AES-256-GCM."""

    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    if not data:
        raise ValueError("Cannot encrypt an empty file")

    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    return {
        "key": key,
        "nonce": nonce,
        "ciphertext": ciphertext,
    }


def decrypt_file(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
) -> bytes:
    """Decrypt AES-256-GCM ciphertext and authenticate its integrity."""

    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")

    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")

    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, None)