from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FabricDecryptionRecord:
    """
    Application-level representation of a decryption provenance event.
    """

    event_id: str
    recipient_id: str
    document_hash: str
    watermark_id: str
    timestamp: str
    ml_dsa_signature: bytes
    record_hash: str


@dataclass(frozen=True)
class FabricTransactionResult:
    """
    Result returned after submitting a provenance transaction.
    """

    transaction_id: str
    committed: bool


@dataclass(frozen=True)
class FabricQueryResult:
    """
    Provenance returned from a watermark lookup.
    """

    record: FabricDecryptionRecord
    transaction_id: str