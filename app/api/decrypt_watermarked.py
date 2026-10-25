"""
POST /decrypt  (privacy-first)

Decrypts for an authorized recipient, embeds a watermark, creates a ZKP
proof and stores a signed DecryptionRecord. The response never contains
the recipient's identity.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request 
from sqlalchemy.orm import Session

from app.api.decryption import (
    METADATA_DIR,
    DecryptionRequest,
    decrypt_hybrid_document,
)
from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.decryption_record import DecryptionRecord
from app.models.user import User
from app.schemas.privacy import DecryptRequest, DecryptResponse
from app.services.revocation import is_revoked
from app.services.ledger_signer import sign_record
from app.services.zkp_service import create_zkp_proof
from src.provenance.apply import SUPPORTED_EXTENSIONS, apply_watermark

router = APIRouter(tags=["Decryption"])
logger = logging.getLogger(__name__)

EMBEDDABLE = SUPPORTED_EXTENSIONS  # .pdf/.png robust; .jpg/.jpeg/.docx metadata


@router.post("/decrypt", response_model=DecryptResponse)
def decrypt_with_watermark(
    body: DecryptRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    request.state.audit_resource = body.encrypted_file_id
    # 0) Revoked recipients get nothing, before any crypto work.
    if is_revoked(db, current_user.id, body.recipient_id):
        raise HTTPException(
            status_code=403,
            detail="This recipient's key has been revoked",
        )
    # 1) Existing checks + decryption (ownership, recipient list, keys).
    result = decrypt_hybrid_document(
        body.encrypted_file_id,
        DecryptionRequest(
            recipient_id=body.recipient_id,
            private_key=body.private_key,
        ),
        current_user,
    )
    original = base64.b64decode(result.decrypted_text_base64)
    document_hash = result.document_hash

    # 2) Find the file type; refuse to release a copy we cannot watermark.
    try:
        metadata_path = METADATA_DIR / f"{body.encrypted_file_id}.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(status_code=500, detail="Unable to read document metadata")

    extension = Path(metadata.get("original_filename", "")).suffix.lower()

    if extension not in EMBEDDABLE:
        raise HTTPException(
            status_code=415,
            detail=(
                "Watermarking is not available for this file type yet "
                "(supported: PNG, JPG, DOCX). No copy was released."
            ),
        )

    try:
        # 3) ZKP proof. The identity is used inside and never stored.
        zkp_proof = create_zkp_proof(
            body.recipient_id, body.encrypted_file_id, document_hash
        )
        # 4) Watermark bound to the proof: PDF/PNG carry SHA256(proof) in a
        #    robust mark (read back before release); JPG/DOCX use metadata.
        marked = apply_watermark(
            original,
            extension,
            zkp_proof=zkp_proof,
            document_id=body.encrypted_file_id,
            document_hash=document_hash,
        )
        watermarked = marked.file_bytes
        watermark_id = marked.watermark_id

        # 5) Signed ledger record. No record means no file.
        now = datetime.now(timezone.utc)
        signature = sign_record(
            watermark_id=watermark_id,
            zkp_proof=zkp_proof,
            document_hash=document_hash,
            encrypted_file_id=body.encrypted_file_id,
            timestamp=now,
        )
        db.add(
            DecryptionRecord(
                watermark_id=watermark_id,
                zkp_proof=zkp_proof,
                document_hash=document_hash,
                encrypted_file_id=body.encrypted_file_id,
                created_by=current_user.id,
                timestamp=now,
                signature=signature,
            )
        )
        db.commit()

    except HTTPException:
        raise
    except Exception:
        db.rollback()
        logger.exception("Watermarked decryption failed")
        raise HTTPException(
            status_code=500,
            detail="Decryption failed; no copy was released",
        ) from None

    return DecryptResponse(
        watermark_id=watermark_id,
        zkp_proof=zkp_proof,
        timestamp=now,
        watermarked_file=base64.b64encode(watermarked).decode("ascii"),
    )