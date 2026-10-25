from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from src.provenance.canonical import calculate_record_hash
from src.provenance.models import (
    DecryptionRecord,
    WatermarkPayload,
)


class ProvenanceRecordBuilder:
    """
    Builds cryptographically canonical decryption records.
    """

    EVENT_TYPE = "DOCUMENT_DECRYPTED"

    @staticmethod
    def calculate_document_hash(document: bytes) -> str:
        if not document:
            raise ValueError("document must not be empty")

        return hashlib.sha256(document).hexdigest()

    @staticmethod
    def generate_session_id() -> str:
        return uuid.uuid4().hex

    @staticmethod
    def generate_event_id() -> str:
        return uuid.uuid4().hex

    @staticmethod
    def utc_timestamp() -> str:
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def build(
        cls,
        *,
        document_id: str,
        document_hash: str,
        recipient_commitment: str,
        session_id: str,
        watermark: WatermarkPayload,
        kem_algorithm: str = "ML-KEM-768",
        signature_algorithm: str = "ML-DSA-65",
        encryption_algorithm: str = "AES-256-GCM",
    ) -> DecryptionRecord:

        if not document_id:
            raise ValueError("document_id must not be empty")

        if not document_hash:
            raise ValueError("document_hash must not be empty")

        if not recipient_commitment:
            raise ValueError(
                "recipient_commitment must not be empty"
            )

        if not session_id:
            raise ValueError("session_id must not be empty")

        if watermark.watermark_id == "":
            raise ValueError("watermark ID must not be empty")

        record = DecryptionRecord(
            record_version=1,
            event_type=cls.EVENT_TYPE,
            event_id=cls.generate_event_id(),
            document_id=document_id,
            document_hash=document_hash,
            recipient_commitment=recipient_commitment,
            session_id=session_id,
            watermark_id=watermark.watermark_id,
            watermark_nonce=watermark.nonce,
            timestamp_utc=cls.utc_timestamp(),
            kem_algorithm=kem_algorithm,
            signature_algorithm=signature_algorithm,
            encryption_algorithm=encryption_algorithm,
            record_hash=None,
        )

        record_hash = calculate_record_hash(record)

        return DecryptionRecord(
            record_version=record.record_version,
            event_type=record.event_type,
            event_id=record.event_id,
            document_id=record.document_id,
            document_hash=record.document_hash,
            recipient_commitment=record.recipient_commitment,
            session_id=record.session_id,
            watermark_id=record.watermark_id,
            watermark_nonce=record.watermark_nonce,
            timestamp_utc=record.timestamp_utc,
            kem_algorithm=record.kem_algorithm,
            signature_algorithm=record.signature_algorithm,
            encryption_algorithm=record.encryption_algorithm,
            record_hash=record_hash,
        )