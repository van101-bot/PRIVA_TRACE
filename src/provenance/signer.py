from __future__ import annotations

from src.pqc.signature import MLDSA
from src.provenance.canonical import canonical_record_bytes
from src.provenance.models import (
    DecryptionRecord,
    SignedDecryptionRecord,
)


class ProvenanceSigner:
    """
    Signs decryption provenance using ML-DSA-65.

    The private key belongs to the recipient.
    """

    def __init__(
        self,
        algorithm: str = "ML-DSA-65",
    ) -> None:
        self.algorithm = algorithm
        self.dsa = MLDSA(algorithm)

    def sign(
        self,
        record: DecryptionRecord,
        private_key: bytes,
        public_key: bytes,
    ) -> SignedDecryptionRecord:

        if not private_key:
            raise ValueError("private_key must not be empty")

        if not public_key:
            raise ValueError("public_key must not be empty")

        if not record.record_hash:
            raise ValueError(
                "record must contain a record_hash before signing"
            )

        message = canonical_record_bytes(record)

        signature = self.dsa.sign(
            message,
            private_key,
        )

        return SignedDecryptionRecord(
            record=record,
            signature=signature,
            signer_public_key=public_key,
        )

    def verify(
        self,
        signed_record: SignedDecryptionRecord,
    ) -> bool:

        message = canonical_record_bytes(
            signed_record.record
        )

        return self.dsa.verify(
            message,
            signed_record.signature,
            signed_record.signer_public_key,
        )