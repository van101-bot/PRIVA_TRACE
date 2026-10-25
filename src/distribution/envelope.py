from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from src.distribution.models import (
    EncryptedDocumentEnvelope,
    WrappedDocumentKey,
)


class DocumentEnvelope:
    """
    AES-256-GCM document encryption and CEK wrapping.

    The document is encrypted exactly once.

    A separate CEK wrapping operation is performed for each
    authorized recipient.
    """

    CEK_SIZE = 32
    NONCE_SIZE = 12

    @classmethod
    def generate_cek(cls) -> bytes:
        return os.urandom(cls.CEK_SIZE)

    @classmethod
    def document_hash(cls, document: bytes) -> str:
        if not document:
            raise ValueError("document must not be empty")

        return hashlib.sha256(document).hexdigest()

    @classmethod
    def encrypt_document(
        cls,
        document: bytes,
        cek: bytes,
        document_id: str,
    ) -> tuple[bytes, bytes, str]:

        if not document:
            raise ValueError("document must not be empty")

        if len(cek) != cls.CEK_SIZE:
            raise ValueError(
                "CEK must be exactly 32 bytes"
            )

        if not document_id:
            raise ValueError(
                "document_id must not be empty"
            )

        nonce = os.urandom(cls.NONCE_SIZE)

        aes = AESGCM(cek)

        associated_data = document_id.encode(
            "utf-8"
        )

        ciphertext = aes.encrypt(
            nonce,
            document,
            associated_data,
        )

        digest = cls.document_hash(document)

        return nonce, ciphertext, digest

    @classmethod
    def decrypt_document(
        cls,
        encrypted_document: bytes,
        nonce: bytes,
        cek: bytes,
        document_id: str,
    ) -> bytes:

        if not encrypted_document:
            raise ValueError(
                "encrypted_document must not be empty"
            )

        if len(nonce) != cls.NONCE_SIZE:
            raise ValueError("invalid nonce length")

        if len(cek) != cls.CEK_SIZE:
            raise ValueError(
                "CEK must be exactly 32 bytes"
            )

        aes = AESGCM(cek)

        return aes.decrypt(
            nonce,
            encrypted_document,
            document_id.encode("utf-8"),
        )

    @classmethod
    def wrap_cek(
        cls,
        cek: bytes,
        kek: bytes,
        recipient_id: str,
    ) -> bytes:

        if len(cek) != cls.CEK_SIZE:
            raise ValueError(
                "CEK must be exactly 32 bytes"
            )

        if len(kek) != cls.CEK_SIZE:
            raise ValueError(
                "KEK must be exactly 32 bytes"
            )

        if not recipient_id:
            raise ValueError(
                "recipient_id must not be empty"
            )

        nonce = os.urandom(cls.NONCE_SIZE)

        aes = AESGCM(kek)

        wrapped = aes.encrypt(
            nonce,
            cek,
            recipient_id.encode("utf-8"),
        )

        return nonce + wrapped

    @classmethod
    def unwrap_cek(
        cls,
        wrapped_cek: bytes,
        kek: bytes,
        recipient_id: str,
    ) -> bytes:

        if len(kek) != cls.CEK_SIZE:
            raise ValueError(
                "KEK must be exactly 32 bytes"
            )

        if len(wrapped_cek) <= cls.NONCE_SIZE:
            raise ValueError(
                "invalid wrapped CEK"
            )

        nonce = wrapped_cek[:cls.NONCE_SIZE]
        ciphertext = wrapped_cek[cls.NONCE_SIZE:]

        aes = AESGCM(kek)

        cek = aes.decrypt(
            nonce,
            ciphertext,
            recipient_id.encode("utf-8"),
        )

        if len(cek) != cls.CEK_SIZE:
            raise ValueError(
                "recovered CEK has invalid length"
            )

        return cek