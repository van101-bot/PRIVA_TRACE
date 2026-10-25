from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LedgerProvenanceRecord:
    """
    Immutable provenance information intended for the DLT.

    No plaintext document is stored here.
    No private key is stored here.
    """

    transaction_id: str
    event_id: str

    document_id: str
    document_hash: str

    watermark_id: str

    recipient_commitment: str

    session_id: str

    record_hash: str

    signature: bytes

    signer_key_id: str
    signer_key_version: int

    timestamp: str

    signature_algorithm: str = "ML-DSA-65"
    hash_algorithm: str = "SHA-256"
    provenance_version: int = 1

    def as_dict(self) -> dict:
        return {
            "transaction_id": self.transaction_id,
            "event_id": self.event_id,
            "document_id": self.document_id,
            "document_hash": self.document_hash,
            "watermark_id": self.watermark_id,
            "recipient_commitment": self.recipient_commitment,
            "session_id": self.session_id,
            "record_hash": self.record_hash,
            "signature": self.signature.hex(),
            "signer_key_id": self.signer_key_id,
            "signer_key_version": self.signer_key_version,
            "timestamp": self.timestamp,
            "signature_algorithm": self.signature_algorithm,
            "hash_algorithm": self.hash_algorithm,
            "provenance_version": self.provenance_version,
        }