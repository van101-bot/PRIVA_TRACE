from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True)
class EncryptedDocument:
    nonce: bytes
    ciphertext: bytes


class HybridDocumentEncryption:
    """
    Encrypts application data using an AES-256-GCM key
    derived from the hybrid QKD + ML-KEM exchange.
    """

    KEY_SIZE = 32
    NONCE_SIZE = 12

    @classmethod
    def encrypt(
        cls,
        plaintext: bytes,
        key: bytes,
        *,
        associated_data: bytes | None = None,
    ) -> EncryptedDocument:
        if not plaintext:
            raise ValueError("plaintext must not be empty")

        if len(key) != cls.KEY_SIZE:
            raise ValueError(
                "key must be exactly 32 bytes"
            )

        nonce = os.urandom(cls.NONCE_SIZE)

        aesgcm = AESGCM(key)

        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext,
            associated_data,
        )

        return EncryptedDocument(
            nonce=nonce,
            ciphertext=ciphertext,
        )

    @classmethod
    def decrypt(
        cls,
        encrypted: EncryptedDocument,
        key: bytes,
        *,
        associated_data: bytes | None = None,
    ) -> bytes:
        if len(key) != cls.KEY_SIZE:
            raise ValueError(
                "key must be exactly 32 bytes"
            )

        if len(encrypted.nonce) != cls.NONCE_SIZE:
            raise ValueError(
                "invalid nonce length"
            )

        if not encrypted.ciphertext:
            raise ValueError(
                "ciphertext must not be empty"
            )

        aesgcm = AESGCM(key)

        return aesgcm.decrypt(
            encrypted.nonce,
            encrypted.ciphertext,
            associated_data,
        )