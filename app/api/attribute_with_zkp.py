"""
POST /attribute-with-zkp

watermark_id -> {is_authorized, zkp_verified}. No recipient name, ID or
commitment is ever returned. Only the user who created the record can ask.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.decryption_record import DecryptionRecord
from app.models.user import User
from app.schemas.privacy import AttributeRequest, AttributeResponse
from app.services.zkp_service import verify_zkp_proof

router = APIRouter(tags=["Attribution"])


@router.post("/attribute-with-zkp", response_model=AttributeResponse)
def attribute_with_zkp(
    body: AttributeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    request.state.audit_resource = body.watermark_id
    record = (
        db.query(DecryptionRecord)
        .filter(DecryptionRecord.watermark_id == body.watermark_id)
        .first()
    )

    if record is None or record.created_by != current_user.id:
        raise HTTPException(
            status_code=404,
            detail="No decryption record exists for this watermark_id",
        )

    zkp_verified = verify_zkp_proof(
        record.zkp_proof,
        document_id=record.encrypted_file_id,
        document_hash=record.document_hash,
    )

    # For now "authorized" means: a valid proof exists, bound to this document.
    # Checking the proof's commitment against the document's recipient list
    # is a later step.
    return AttributeResponse(is_authorized=zkp_verified, zkp_verified=zkp_verified)