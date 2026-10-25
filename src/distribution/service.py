
from __future__ import annotations

from dataclasses import dataclass

from src.distribution.envelope import DocumentEnvelope
from src.distribution.models import (
    EncryptedDocumentEnvelope,
    WrappedDocumentKey,
)
from src.hybrid.kdf import HybridKDF
from src.pqc.kem import MLKEM
from src.qkd.simulator import QKDProvider


@dataclass(frozen=True)
class RecipientEncryptionContext:
    recipient_id: str
    public_key: bytes
    qkd_secret: bytes


class MultiRecipientEncryptionService:
    """Encrypt documents for multiple recipients using hybrid keys."""

    def __init__(
        self,
        mlkem_algorithm: str = "ML-KEM-768",
    ) -> None:
        self.mlkem = MLKEM(mlkem_algorithm)

    def create_recipient_context(
        self,
        recipient_id: str,
        public_key: bytes,
        qkd_provider: QKDProvider,
    ) -> RecipientEncryptionContext:
        if not recipient_id:
            raise ValueError("recipient_id must not be empty")
        if not public_key:
            raise ValueError("public_key must not be empty")

        qkd_session = qkd_provider.establish_key()

        return RecipientEncryptionContext(
            recipient_id=recipient_id,
            public_key=public_key,
            qkd_secret=qkd_session.key,
        )

    def encrypt_for_recipients(
        self,
        *,
        document: bytes,
        document_id: str,
        recipients: list[RecipientEncryptionContext],
    ) -> EncryptedDocumentEnvelope:
        if not document:
            raise ValueError("document must not be empty")
        if not document_id:
            raise ValueError("document_id must not be empty")
        if not recipients:
            raise ValueError("at least one recipient is required")

        recipient_ids = [r.recipient_id for r in recipients]
        if len(recipient_ids) != len(set(recipient_ids)):
            raise ValueError("recipient IDs must be unique")

        cek = DocumentEnvelope.generate_cek()

        nonce, encrypted_document, document_hash = (
            DocumentEnvelope.encrypt_document(
                document=document,
                cek=cek,
                document_id=document_id,
            )
        )

        wrapped_keys: list[WrappedDocumentKey] = []

        for recipient in recipients:
            encapsulation = self.mlkem.encapsulate(
                recipient.public_key
            )

            hybrid_kek = HybridKDF.derive_key(
                qkd_secret=recipient.qkd_secret,
                mlkem_secret=encapsulation.shared_secret,
                context=(
                    b"SIH26237-MULTI-RECIPIENT-KEK-V1|"
                    + document_id.encode("utf-8")
                    + b"|"
                    + recipient.recipient_id.encode("utf-8")
                ),
            )

            wrapped_cek = DocumentEnvelope.wrap_cek(
                cek=cek,
                kek=hybrid_kek,
                recipient_id=recipient.recipient_id,
            )

            wrapped_keys.append(
                WrappedDocumentKey(
                    recipient_id=recipient.recipient_id,
                    mlkem_ciphertext=encapsulation.ciphertext,
                    wrapped_cek=wrapped_cek,
                )
            )

        return EncryptedDocumentEnvelope(
            document_id=document_id,
            document_hash=document_hash,
            encryption_nonce=nonce,
            encrypted_document=encrypted_document,
            recipients=tuple(wrapped_keys),
        )

    def decrypt_for_recipient(
        self,
        *,
        envelope: EncryptedDocumentEnvelope,
        recipient_id: str,
        recipient_private_key: bytes,
        qkd_secret: bytes,
    ) -> bytes:
        if not recipient_id:
            raise ValueError("recipient_id must not be empty")
        if not recipient_private_key:
            raise ValueError("recipient_private_key must not be empty")
        if not qkd_secret:
            raise ValueError("qkd_secret must not be empty")

        matching = [
            item
            for item in envelope.recipients
            if item.recipient_id == recipient_id
        ]
        if not matching:
            raise PermissionError(
                f"Recipient is not authorized: {recipient_id}"
            )

        recipient_entry = matching[0]

        mlkem_secret = self.mlkem.decapsulate(
            recipient_entry.mlkem_ciphertext,
            recipient_private_key,
        )

        hybrid_kek = HybridKDF.derive_key(
            qkd_secret=qkd_secret,
            mlkem_secret=mlkem_secret,
            context=(
                b"SIH26237-MULTI-RECIPIENT-KEK-V1|"
                + envelope.document_id.encode("utf-8")
                + b"|"
                + recipient_id.encode("utf-8")
            ),
        )

        cek = DocumentEnvelope.unwrap_cek(
            wrapped_cek=recipient_entry.wrapped_cek,
            kek=hybrid_kek,
            recipient_id=recipient_id,
        )

        document = DocumentEnvelope.decrypt_document(
            encrypted_document=envelope.encrypted_document,
            nonce=envelope.encryption_nonce,
            cek=cek,
            document_id=envelope.document_id,
        )

        actual_hash = DocumentEnvelope.document_hash(document)

        if actual_hash != envelope.document_hash:
            raise ValueError(
                "decrypted document hash does not match "
                "envelope metadata"
            )

        return document