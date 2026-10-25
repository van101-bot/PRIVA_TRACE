"""
POST /generate-attribution-report

watermark_id -> PDF. Only the user who created the decryption record can
generate its report (anyone else gets 404, so existence is not revealed).
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.decryption_record import DecryptionRecord
from app.models.user import User
from app.schemas.privacy import ReportRequest
from app.services.ledger_signer import verify_record_signature
from app.services.report_pdf import build_attribution_report
from app.services.zkp_service import verify_zkp_proof

router = APIRouter(tags=["Reports"])

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8001").rstrip("/")


@router.post(
    "/generate-attribution-report",
    responses={200: {"content": {"application/pdf": {}}}},
)
def generate_attribution_report(
    body: ReportRequest,
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
            detail="No report is available for this watermark_id",
        )

    zkp_valid = verify_zkp_proof(
        record.zkp_proof,
        document_id=record.encrypted_file_id,
        document_hash=record.document_hash,
    )
    signature_valid = verify_record_signature(
        record.signature,
        watermark_id=record.watermark_id,
        zkp_proof=record.zkp_proof,
        document_hash=record.document_hash,
        encrypted_file_id=record.encrypted_file_id,
        timestamp=record.timestamp,
    )

    pdf = build_attribution_report(
        watermark_id=record.watermark_id,
        encrypted_file_id=record.encrypted_file_id,
        document_hash=record.document_hash,
        timestamp=record.timestamp,
        zkp_valid=zkp_valid,
        signature_valid=signature_valid,
        zkp_proof=record.zkp_proof,
        signature=record.signature,
        verify_url=f"{PUBLIC_BASE_URL}/ledger/{record.watermark_id}",
    )

    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="attribution_{record.watermark_id[:8]}.pdf"'
            )
        },
    )