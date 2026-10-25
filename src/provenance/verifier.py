from __future__ import annotations

from src.provenance.canonical import verify_record_hash
from src.provenance.models import (
    SignedDecryptionRecord,
    WatermarkPayload,
)
from src.provenance.signer import ProvenanceSigner
from src.provenance.watermark import ForensicWatermark


class ProvenanceVerifier:
    """
    Performs cryptographic verification of watermark and provenance.
    """

    def __init__(
        self,
        signature_algorithm: str = "ML-DSA-65",
    ) -> None:
        self.signer = ProvenanceSigner(
            signature_algorithm
        )

    def verify_watermark(
        self,
        watermark: WatermarkPayload,
    ) -> bool:
        return ForensicWatermark.verify(watermark)

    def verify_record(
        self,
        signed_record: SignedDecryptionRecord,
    ) -> bool:

        if not verify_record_hash(
            signed_record.record
        ):
            return False

        return self.signer.verify(
            signed_record
        )

    def verify_complete(
        self,
        watermark: WatermarkPayload,
        signed_record: SignedDecryptionRecord,
    ) -> bool:

        if not self.verify_watermark(watermark):
            return False

        if not self.verify_record(signed_record):
            return False

        if (
            watermark.watermark_id
            != signed_record.record.watermark_id
        ):
            return False

        if (
            watermark.document_id
            != signed_record.record.document_id
        ):
            return False

        if (
            watermark.session_id
            != signed_record.record.session_id
        ):
            return False

        return True