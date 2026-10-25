
from __future__ import annotations

import base64
import binascii
import json
import logging
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.key_management import load_master_key
from src.distribution.models import (
    EncryptedDocumentEnvelope,
    WrappedDocumentKey,
)
from src.distribution.service import MultiRecipientEncryptionService

router = APIRouter(prefix="/hybrid", tags=["Hybrid Decryption"])

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENCRYPTED_DIR = PROJECT_ROOT / "storage" / "encrypted"
METADATA_DIR = PROJECT_ROOT / "storage" / "metadata"
KEY_DIR = PROJECT_ROOT / "storage" / "keys" / "recipient_sessions"

ALGORITHM = "ML-KEM-768"
SESSION_KEY_VERSION = 1
logger = logging.getLogger(__name__)

service = MultiRecipientEncryptionService(ALGORITHM)


class DecryptionRequest(BaseModel):
    recipient_id: str = Field(min_length=1, max_length=128)
    private_key: str = Field(
        description="Base64-encoded ML-KEM private key"
    )


class DecryptionResponse(BaseModel):
    document_id: str
    status: str
    document_hash: str
    decrypted_text_base64: str


def decode_base64(value: str, field_name: str) -> bytes:
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} must contain valid Base64",
        ) from exc

    if not result:
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} must not be empty",
        )

    return result


def unprotect_qkd_secret(
    protected: dict,
    encrypted_file_id: str,
    recipient_id: str,
) -> bytes:
    if protected.get("version") != SESSION_KEY_VERSION:
        raise ValueError("Unsupported QKD session format")

    nonce = decode_base64(protected["nonce"], "session nonce")
    ciphertext = decode_base64(
        protected["ciphertext"], "protected session secret"
    )

    if len(nonce) != 12:
        raise ValueError("Invalid session nonce")

    associated_data = (
        f"SIH26237-QKD-SESSION-V1|{encrypted_file_id}|{recipient_id}"
    ).encode("utf-8")

    # InvalidTag means the secret, nonce, AAD, or master key does not match.
    return AESGCM(load_master_key()).decrypt(
        nonce, ciphertext, associated_data
    )


@router.post(
    "/decrypt/{encrypted_file_id}",
    response_model=DecryptionResponse,
)
def decrypt_hybrid_document(
    encrypted_file_id: str,
    request: DecryptionRequest,
    current_user: User = Depends(get_current_user),
):
    allowed_chars = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-"
    )
    if (
        not encrypted_file_id
        or len(encrypted_file_id) > 64
        or any(character not in allowed_chars for character in encrypted_file_id)
    ):
        raise HTTPException(status_code=400, detail="Invalid encrypted file ID")

    envelope_path = ENCRYPTED_DIR / f"{encrypted_file_id}.json"
    metadata_path = METADATA_DIR / f"{encrypted_file_id}.json"
    session_path = KEY_DIR / f"{encrypted_file_id}.json"

    if (
        not envelope_path.is_file()
        or not metadata_path.is_file()
        or not session_path.is_file()
    ):
        raise HTTPException(
            status_code=404,
            detail="Encrypted document or session data not found",
        )

    try:
        with metadata_path.open("r", encoding="utf-8") as source:
            metadata = json.load(source)

        # Ownership is checked before attempting decryption.
        if metadata.get("encrypted_file_id") != encrypted_file_id:
            raise HTTPException(
                status_code=422,
                detail="Document metadata is inconsistent",
            )

        if metadata.get("owner_user_id") != current_user.id:
            raise HTTPException(
                status_code=403,
                detail="You do not own this encrypted document",
            )

        recipient_ids = metadata.get("recipient_ids", [])
        if request.recipient_id not in recipient_ids:
            raise HTTPException(
                status_code=403,
                detail="Recipient is not authorized for this document",
            )

        with envelope_path.open("r", encoding="utf-8") as source:
            saved = json.load(source)

        with session_path.open("r", encoding="utf-8") as source:
            session_data = json.load(source)

        if (
            saved.get("document_id") != encrypted_file_id
            or session_data.get("encrypted_file_id") != encrypted_file_id
        ):
            raise HTTPException(
                status_code=422,
                detail="Encrypted document data is inconsistent",
            )

        protected_session = session_data.get("sessions", {}).get(
            request.recipient_id
        )
        if not isinstance(protected_session, dict):
            raise HTTPException(
                status_code=403,
                detail="No session key is available for this recipient",
            )

        qkd_secret = unprotect_qkd_secret(
            protected_session,
            encrypted_file_id,
            request.recipient_id,
        )

        recipients = tuple(
            WrappedDocumentKey(
                recipient_id=item["recipient_id"],
                mlkem_ciphertext=decode_base64(
                    item["mlkem_ciphertext"], "ML-KEM ciphertext"
                ),
                wrapped_cek=decode_base64(
                    item["wrapped_cek"], "wrapped document key"
                ),
            )
            for item in saved["recipients"]
        )

        envelope = EncryptedDocumentEnvelope(
            document_id=saved["document_id"],
            document_hash=saved["document_hash"],
            encryption_nonce=decode_base64(
                saved["encryption_nonce"], "encryption nonce"
            ),
            encrypted_document=decode_base64(
                saved["encrypted_document"], "encrypted document"
            ),
            recipients=recipients,
        )

        private_key = decode_base64(request.private_key, "private_key")

        original = service.decrypt_for_recipient(
            envelope=envelope,
            recipient_id=request.recipient_id,
            recipient_private_key=private_key,
            qkd_secret=qkd_secret,
        )

        return DecryptionResponse(
            document_id=encrypted_file_id,
            status="decrypted",
            document_hash=envelope.document_hash,
            decrypted_text_base64=base64.b64encode(original).decode("ascii"),
        )

    except HTTPException:
        raise

    except (InvalidTag, PermissionError):
        raise HTTPException(
            status_code=422,
            detail="Decryption failed: invalid key or encrypted data",
        ) from None

    except (ValueError, TypeError, KeyError, binascii.Error):
        logger.exception("Invalid hybrid envelope for %s", encrypted_file_id)
        raise HTTPException(
            status_code=422,
            detail="Encrypted document data or key is invalid",
        ) from None

    except OSError:
        logger.exception("Unable to read hybrid envelope %s", encrypted_file_id)
        raise HTTPException(
            status_code=500,
            detail="Unable to read encrypted document",
        ) from None

    except Exception:
        logger.exception("Hybrid decryption failed for %s", encrypted_file_id)
        raise HTTPException(
            status_code=500,
            detail="Hybrid decryption failed",
        ) from None