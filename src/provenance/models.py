from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WatermarkPayload:
    """
    Cryptographic payload identifying a single decryption session.

    No plaintext recipient identity is stored in the watermark.
    """

    version: int
    watermark_id: str
    document_id: str
    document_hash: str
    recipient_commitment: str
    session_id: str
    nonce: str


@dataclass(frozen=True)
class DecryptionRecord:
    """
    Canonical provenance information for one decryption event.
    """

    record_version: int
    event_type: str
    event_id: str
    document_id: str
    document_hash: str
    recipient_commitment: str
    session_id: str
    watermark_id: str
    watermark_nonce: str
    timestamp_utc: str
    kem_algorithm: str
    signature_algorithm: str
    encryption_algorithm: str
    record_hash: str | None = None


@dataclass(frozen=True)
class SignedDecryptionRecord:
    """
    Decryption record plus the recipient's ML-DSA signature.
    """

    record: DecryptionRecord
    signature: bytes
    signer_public_key: bytes