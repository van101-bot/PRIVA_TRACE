"""
Encrypted software keystore.

IMPORTANT:
This is a development/prototype keystore.

Production private keys should be held inside an HSM
rather than relying on a software-held master key.
"""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptedKeyStore:
    """
    Encrypt and decrypt private-key material.

    The encryption key must be supplied externally.
    Do NOT hard-code it into source code.
    """

    NONCE_SIZE = 12
    KEY_SIZE = 32

    def __init__(self, encryption_key: bytes) -> None:
        if len(encryption_key) != self.KEY_SIZE:
            raise ValueError(
                "encryption_key must be exactly 32 bytes"
            )

        self._encryption_key = encryption_key

    @classmethod
    def generate_key(cls) -> bytes:
        """Generate a 256-bit AES key."""

        return os.urandom(cls.KEY_SIZE)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt private-key material using AES-256-GCM."""

        if not plaintext:
            raise ValueError("plaintext must not be empty")

        nonce = os.urandom(self.NONCE_SIZE)

        aes = AESGCM(self._encryption_key)

        ciphertext = aes.encrypt(
            nonce,
            plaintext,
            None,
        )

        return nonce + ciphertext

    def decrypt(self, encrypted: bytes) -> bytes:
        """Decrypt AES-256-GCM encrypted private-key material."""

        if len(encrypted) <= self.NONCE_SIZE:
            raise ValueError("invalid encrypted data")

        nonce = encrypted[: self.NONCE_SIZE]
        ciphertext = encrypted[self.NONCE_SIZE :]

        aes = AESGCM(self._encryption_key)

        return aes.decrypt(
            nonce,
            ciphertext,
            None,
        )