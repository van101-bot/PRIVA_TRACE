"""
GET  /provenance/{watermark_id}  - full provenance of one decryption event
POST /provenance/trace           - leaked file in, provenance out (one call)

No recipient identity is ever returned. Only the user who created the record
can see it (others get 404 on GET, known=false on trace).
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, Path, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.extract_watermark import extract_watermark
from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.decryption_record import DecryptionRecord
from app.models.user import User
from app.schemas.privacy import WATERMARK_ID_PATTERN
from app.services.ledger_signer import verify_record_signature
from app.services.report_pdf import ledger_backend_label
from app.services.zkp_service import verify_zkp_proof

router = APIRouter(tags=["Provenance"])


class ProvenanceResponse(BaseModel):
    watermark_id: str
    known: bool
    status: str  # confirmed | not_confirmed | unknown_watermark
    confidence: float | None = None
    encrypted_file_id: str | None = None
    document_hash: str | None = None
    decrypted_at: datetime | None = None
    zkp_verified: bool | None = None
    signature_valid: bool | None = None
    ledger_backend: str | None = None


def _build(
    db: Session, user_id: int, watermark_id: str, confidence: float | None
) -> ProvenanceResponse:
    record = (
        db.query(DecryptionRecord)
        .filter(
            DecryptionRecord.watermark_id == watermark_id,
            DecryptionRecord.created_by == user_id,
        )
        .first()
    )

    if record is None:
        return ProvenanceResponse(
            watermark_id=watermark_id,
            known=False,
            status="unknown_watermark",
            confidence=confidence,
        )

    zkp_ok = verify_zkp_proof(
        record.zkp_proof,
        document_id=record.encrypted_file_id,
        document_hash=record.document_hash,
    )
    sig_ok = verify_record_signature(
        record.signature,
        watermark_id=record.watermark_id,
        zkp_proof=record.zkp_proof,
        document_hash=record.document_hash,
        encrypted_file_id=record.encrypted_file_id,
        timestamp=record.timestamp,
    )

    return ProvenanceResponse(
        watermark_id=record.watermark_id,
        known=True,
        status="confirmed" if (zkp_ok and sig_ok) else "not_confirmed",
        confidence=confidence,
        encrypted_file_id=record.encrypted_file_id,
        document_hash=record.document_hash,
        decrypted_at=record.timestamp,
        zkp_verified=zkp_ok,
        signature_valid=sig_ok,
        ledger_backend=ledger_backend_label(),
    )


@router.get("/provenance/{watermark_id}", response_model=ProvenanceResponse)
def get_provenance(
    request: Request,
    watermark_id: str = Path(pattern=WATERMARK_ID_PATTERN),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    request.state.audit_resource = watermark_id
    result = _build(db, current_user.id, watermark_id, None)
    if not result.known:
        raise HTTPException(
            status_code=404,
            detail="No provenance record exists for this watermark_id",
        )
    return result


@router.post("/provenance/trace", response_model=ProvenanceResponse)
async def trace_leak(
    request: Request,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Reuses /extract-watermark: 404 if no valid watermark, 415/413 for bad files.
    found = await extract_watermark(file, current_user, db)
    request.state.audit_resource = found.watermark_id
    return await run_in_threadpool(
        _build, db, current_user.id, found.watermark_id, found.confidence
    )