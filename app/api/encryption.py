
from __future__ import annotations

import base64
import json
import os
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from app.core.dependencies import get_current_user
from app.models.user import User
from app.services.key_management import load_master_key
from src.distribution.service import MultiRecipientEncryptionService
from src.pqc.kem import MLKEM
from src.qkd.simulator import SimulatedQKDProvider

router = APIRouter(tags=["Encryption"])

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENCRYPTED_DIR = PROJECT_ROOT / "storage" / "encrypted"
KEY_DIR = PROJECT_ROOT / "storage" / "keys" / "recipient_sessions"
METADATA_DIR = PROJECT_ROOT / "storage" / "metadata"

MAX_FILE_SIZE = 20 * 1024 * 1024
MAX_RECIPIENTS = 100
ALGORITHM = "ML-KEM-768"
SESSION_KEY_VERSION = 1

service = MultiRecipientEncryptionService(ALGORITHM)
qkd_provider = SimulatedQKDProvider()


class RecipientPublicKey(BaseModel):
    recipient_id: str = Field(min_length=1, max_length=128)
    public_key: str = Field(description="Base64-encoded ML-KEM public key")


class EncryptionResponse(BaseModel):
    document_hash: str
    encrypted_file_id: str
    status: str


def protect_qkd_secret(
    secret: bytes,
    encrypted_file_id: str,
    recipient_id: str,
) -> dict:
    """Encrypt a simulated QKD session secret using the server master key."""
    if not secret:
        raise ValueError("QKD session secret is empty")

    nonce = os.urandom(12)
    associated_data = (
        f"SIH26237-QKD-SESSION-V1|{encrypted_file_id}|{recipient_id}"
    ).encode("utf-8")

    ciphertext = AESGCM(load_master_key()).encrypt(
        nonce, secret, associated_data
    )

    return {
        "version": SESSION_KEY_VERSION,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


@router.post(
    "/encrypt",
    response_model=EncryptionResponse,
    status_code=201,
)
async def encrypt_document(
    file: UploadFile = File(...),
    recipients_json: str = Form(...),
    current_user: User = Depends(get_current_user),
):
    encrypted_file_id = str(uuid.uuid4())
    envelope_path = ENCRYPTED_DIR / f"{encrypted_file_id}.json"
    metadata_path = METADATA_DIR / f"{encrypted_file_id}.json"
    session_path = KEY_DIR / f"{encrypted_file_id}.json"

    created_paths: list[Path] = []

    try:
        try:
            recipients_data = json.loads(recipients_json)
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=422,
                detail="recipients_json must be valid JSON",
            ) from exc

        if not isinstance(recipients_data, list) or not recipients_data:
            raise HTTPException(
                status_code=422,
                detail="Provide a non-empty JSON array of recipients",
            )

        if len(recipients_data) > MAX_RECIPIENTS:
            raise HTTPException(
                status_code=422,
                detail=f"At most {MAX_RECIPIENTS} recipients are allowed",
            )

        try:
            recipients = [
                RecipientPublicKey.model_validate(item)
                for item in recipients_data
            ]
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail="Each recipient needs a valid recipient_id and public_key",
            ) from exc

        recipient_ids = [item.recipient_id for item in recipients]
        if len(recipient_ids) != len(set(recipient_ids)):
            raise HTTPException(
                status_code=422,
                detail="Recipient IDs must be unique",
            )

        document = await file.read(MAX_FILE_SIZE + 1)

        if not document:
            raise HTTPException(status_code=422, detail="Uploaded file is empty")

        if len(document) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="File exceeds the 20 MiB limit",
            )

        recipient_contexts = []
        protected_sessions = {}

        for recipient in recipients:
            try:
                public_key = base64.b64decode(
                    recipient.public_key, validate=True
                )
            except Exception as exc:
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid Base64 public key for {recipient.recipient_id}",
                ) from exc

            context = service.create_recipient_context(
                recipient_id=recipient.recipient_id,
                public_key=public_key,
                qkd_provider=qkd_provider,
            )
            recipient_contexts.append(context)

            protected_sessions[recipient.recipient_id] = protect_qkd_secret(
                context.qkd_secret,
                encrypted_file_id,
                recipient.recipient_id,
            )

        envelope = service.encrypt_for_recipients(
            document=document,
            document_id=encrypted_file_id,
            recipients=recipient_contexts,
        )

        ENCRYPTED_DIR.mkdir(parents=True, exist_ok=True)
        KEY_DIR.mkdir(parents=True, exist_ok=True)
        METADATA_DIR.mkdir(parents=True, exist_ok=True)

        envelope_json = {
            "document_id": envelope.document_id,
            "document_hash": envelope.document_hash,
            "encryption_nonce": base64.b64encode(
                envelope.encryption_nonce
            ).decode("ascii"),
            "encrypted_document": base64.b64encode(
                envelope.encrypted_document
            ).decode("ascii"),
            "recipients": [
                {
                    "recipient_id": item.recipient_id,
                    "mlkem_ciphertext": base64.b64encode(
                        item.mlkem_ciphertext
                    ).decode("ascii"),
                    "wrapped_cek": base64.b64encode(
                        item.wrapped_cek
                    ).decode("ascii"),
                }
                for item in envelope.recipients
            ],
        }

        metadata_json = {
            "encrypted_file_id": encrypted_file_id,
            "document_hash": envelope.document_hash,
            "original_filename": Path(file.filename or "document").name,
            "algorithm": ALGORITHM,
            "recipient_ids": recipient_ids,
            "owner_user_id": current_user.id,
            "qkd_mode": "simulated",
            "status": "encrypted",
        }

        session_json = {
            "encrypted_file_id": encrypted_file_id,
            "sessions": protected_sessions,
        }

        # Exclusive creation prevents accidental overwriting.
        for path, payload in (
            (envelope_path, envelope_json),
            (metadata_path, metadata_json),
            (session_path, session_json),
        ):
            with path.open("x", encoding="utf-8") as output:
                created_paths.append(path)
                json.dump(payload, output)

        return EncryptionResponse(
            document_hash=envelope.document_hash,
            encrypted_file_id=encrypted_file_id,
            status="encrypted",
        )

    except HTTPException:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise

    except (ValueError, TypeError) as exc:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    except Exception as exc:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=500,
            detail="Document encryption failed",
        ) from exc

    finally:
        await file.close()