"""
GET /ledger/{watermark_id}

Returns the signed ZKP record for a watermark. No recipient identity.
Only the user who created the record can read it (others get 404).
If the stored row no longer matches its signature, returns 409.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.decryption_record import DecryptionRecord
from app.models.user import User
from app.schemas.privacy import WATERMARK_ID_PATTERN, LedgerProofResponse
from app.services.ledger_signer import verify_record_signature

router = APIRouter(tags=["Ledger"])


@router.get("/ledger/{watermark_id}", response_model=LedgerProofResponse)
def get_ledger_proof(
    watermark_id: str = Path(pattern=WATERMARK_ID_PATTERN),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = (
        db.query(DecryptionRecord)
        .filter(DecryptionRecord.watermark_id == watermark_id)
        .first()
    )

    if record is None or record.created_by != current_user.id:
        raise HTTPException(
            status_code=404,
            detail="No ledger record exists for this watermark_id",
        )

    intact = verify_record_signature(
        record.signature,
        watermark_id=record.watermark_id,
        zkp_proof=record.zkp_proof,
        document_hash=record.document_hash,
        encrypted_file_id=record.encrypted_file_id,
        timestamp=record.timestamp,
    )

    if not intact:
        raise HTTPException(
            status_code=409,
            detail="Ledger record failed its integrity check",
        )

    return LedgerProofResponse(
        watermark_id=record.watermark_id,
        zkp_proof=record.zkp_proof,
        timestamp=record.timestamp,
        signature=record.signature,
    )