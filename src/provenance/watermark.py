from __future__ import annotations

import base64
import hashlib
import json
import secrets

from src.provenance.models import WatermarkPayload


WATERMARK_DOMAIN = b"SIH26237-FORENSIC-WATERMARK-V1|"


class ForensicWatermark:
    """
    Generates and extracts cryptographic watermark payloads.

    Important:
        This class creates the cryptographic watermark identity.
        A document-format adapter is responsible for embedding the
        payload into an actual PDF/DOCX/image/etc.

    The watermark contains no plaintext recipient identity.
    """

    VERSION = 1
    NONCE_BYTES = 16

    @staticmethod
    def _encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    @staticmethod
    def _decode(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(
            value + padding
        )

    @classmethod
    def generate(
        cls,
        *,
        document_id: str,
        document_hash: str,
        recipient_commitment: str,
        session_id: str,
    ) -> WatermarkPayload:
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

        nonce = secrets.token_bytes(cls.NONCE_BYTES)

        nonce_encoded = cls._encode(nonce)

        material = (
            WATERMARK_DOMAIN
            + document_id.encode("utf-8")
            + b"|"
            + document_hash.encode("ascii")
            + b"|"
            + recipient_commitment.encode("ascii")
            + b"|"
            + session_id.encode("utf-8")
            + b"|"
            + nonce_encoded.encode("ascii")
        )

        digest = hashlib.sha256(material).digest()

        watermark_id = cls._encode(digest)

        return WatermarkPayload(
            version=cls.VERSION,
            watermark_id=watermark_id,
            document_id=document_id,
            document_hash=document_hash,
            recipient_commitment=recipient_commitment,
            session_id=session_id,
            nonce=nonce_encoded,
        )

    @classmethod
    def serialize(cls, payload: WatermarkPayload) -> bytes:
        data = {
            "version": payload.version,
            "watermark_id": payload.watermark_id,
            "document_id": payload.document_id,
            "document_hash": payload.document_hash,
            "recipient_commitment": payload.recipient_commitment,
            "session_id": payload.session_id,
            "nonce": payload.nonce,
        }

        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def deserialize(cls, data: bytes) -> WatermarkPayload:
        if not data:
            raise ValueError("watermark data must not be empty")

        try:
            decoded = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "invalid watermark encoding"
            ) from exc

        required = {
            "version",
            "watermark_id",
            "document_id",
            "document_hash",
            "recipient_commitment",
            "session_id",
            "nonce",
        }

        if set(decoded.keys()) != required:
            raise ValueError(
                "watermark payload contains invalid fields"
            )

        return WatermarkPayload(
            version=int(decoded["version"]),
            watermark_id=str(decoded["watermark_id"]),
            document_id=str(decoded["document_id"]),
            document_hash=str(decoded["document_hash"]),
            recipient_commitment=str(
                decoded["recipient_commitment"]
            ),
            session_id=str(decoded["session_id"]),
            nonce=str(decoded["nonce"]),
        )

    @classmethod
    def verify(cls, payload: WatermarkPayload) -> bool:
        """
        Recompute the watermark ID and verify integrity.
        """

        material = (
            WATERMARK_DOMAIN
            + payload.document_id.encode("utf-8")
            + b"|"
            + payload.document_hash.encode("ascii")
            + b"|"
            + payload.recipient_commitment.encode("ascii")
            + b"|"
            + payload.session_id.encode("utf-8")
            + b"|"
            + payload.nonce.encode("ascii")
        )

        expected = cls._encode(
            hashlib.sha256(material).digest()
        )

        return (
            payload.version == cls.VERSION
            and secrets.compare_digest(
                expected,
                payload.watermark_id,
            )
        )