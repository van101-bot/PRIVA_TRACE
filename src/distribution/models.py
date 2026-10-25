from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WrappedDocumentKey:
    recipient_id: str
    mlkem_ciphertext: bytes
    wrapped_cek: bytes


@dataclass(frozen=True)
class EncryptedDocumentEnvelope:
    document_id: str
    document_hash: str
    encryption_nonce: bytes
    encrypted_document: bytes
    recipients: tuple[WrappedDocumentKey, ...]