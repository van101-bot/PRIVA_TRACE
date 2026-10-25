
from __future__ import annotations

from src.hsm.backend import HSMBackend
from src.hsm.models import KeyType
from src.provenance.canonical import (
    canonical_record_bytes,
    verify_record_hash,
)
from src.provenance.models import (
    DecryptionRecord,
    DualSignedDecryptionRecord,
)
from src.pqc.signature import MLDSA


class DualProvenanceSigner:
    """
    Recipient + trusted-service signatures over one canonical record.

    Recipient private key: supplied by the recipient-side signing flow.
    Service private key: retained inside the HSM backend.
    """

    def __init__(
        self,
        hsm: HSMBackend,
        algorithm: str = "ML-DSA-65",
    ) -> None:
        self.hsm = hsm
        self.dsa = MLDSA(algorithm)

    def sign(
        self,
        record: DecryptionRecord,
        *,
        recipient_private_key: bytes,
        recipient_public_key: bytes,
        service_key_id: str,
    ) -> DualSignedDecryptionRecord:
        if not recipient_private_key:
            raise ValueError("recipient_private_key must not be empty")
        if not recipient_public_key:
            raise ValueError("recipient_public_key must not be empty")
        if not service_key_id:
            raise ValueError("service_key_id must not be empty")
        if not verify_record_hash(record):
            raise ValueError("record hash is missing or invalid")

        metadata = self.hsm.get_key_metadata(service_key_id)
        if metadata.key_type != KeyType.ML_DSA:
            raise ValueError("service key must be an ML-DSA signing key")

        service_public_key = self.hsm.get_public_key(service_key_id)
        if not service_public_key:
            raise ValueError("service public key must not be empty")

        # Both signers sign precisely the same canonical message.
        message = canonical_record_bytes(record)

        recipient_signature = self.dsa.sign(
            message,
            recipient_private_key,
        )

        service_signature = self.hsm.sign(
            service_key_id,
            message,
        )

        return DualSignedDecryptionRecord(
            record=record,
            recipient_signature=recipient_signature,
            recipient_public_key=recipient_public_key,
            service_signature=service_signature,
            service_public_key=service_public_key,
            service_key_id=service_key_id,
        )

    def verify(
        self,
        signed: DualSignedDecryptionRecord,
        *,
        trusted_recipient_public_key: bytes,
        trusted_service_public_key: bytes,
    ) -> bool:
        if not isinstance(signed, DualSignedDecryptionRecord):
            return False

        if not trusted_recipient_public_key or not trusted_service_public_key:
            return False

        # Do not trust public keys merely because they are embedded in a record.
        if signed.recipient_public_key != trusted_recipient_public_key:
            return False
        if signed.service_public_key != trusted_service_public_key:
            return False

        if not signed.recipient_signature or not signed.service_signature:
            return False
        if not signed.service_key_id:
            return False

        # Independently check the record's stored digest.
        if not verify_record_hash(signed.record):
            return False

        message = canonical_record_bytes(signed.record)

        try:
            recipient_valid = self.dsa.verify(
                message,
                signed.recipient_signature,
                trusted_recipient_public_key,
            )
            service_valid = self.dsa.verify(
                message,
                signed.service_signature,
                trusted_service_public_key,
            )
        except (TypeError, ValueError):
            return False

        return bool(recipient_valid and service_valid)