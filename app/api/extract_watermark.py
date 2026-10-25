"""
POST /extract-watermark

Upload a leaked file -> get the watermark_id and a confidence score.
Privacy-first: the response never contains the recipient's identity,
commitment or session data.

PDF/PNG carry a robust watermark, so an extracted ID is only a candidate: it
is matched against the caller's own ledger by bit distance (see
src/provenance/apply.py). JPG/DOCX carry an exact, verifiable metadata mark.
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.decryption_record import DecryptionRecord
from app.models.user import User
from app.schemas.privacy import ExtractWatermarkResponse
from src.provenance.apply import (
    ROBUST_EXTENSIONS,
    SUPPORTED_EXTENSIONS as APPLY_EXTENSIONS,
    match_known,
    read_watermark,
)

router = APIRouter(tags=["Watermark"])
logger = logging.getLogger(__name__)

MAX_FILE_SIZE = 50 * 1024 * 1024
# Formats the embedding module can read back.
SUPPORTED_EXTENSIONS = APPLY_EXTENSIONS


def _identify(content: bytes, extension: str, db: Session, user_id: int):
    """Blocking work (image/PDF decoding + ledger match). Run in a thread."""
    candidate_id, raw_confidence = read_watermark(content, extension)

    if extension not in ROBUST_EXTENSIONS:
        return candidate_id, raw_confidence  # exact, self-verifying

    known = [
        row[0]
        for row in db.query(DecryptionRecord.watermark_id)
        .filter(DecryptionRecord.created_by == user_id)
        .all()
    ]
    matched = match_known(candidate_id, known)
    if matched is None:
        raise ValueError("candidate not in ledger")
    return matched


@router.post("/extract-watermark", response_model=ExtractWatermarkResponse)
async def extract_watermark(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail="A filename is required")

        extension = Path(file.filename.replace("\\", "/")).suffix.lower()

        if extension not in SUPPORTED_EXTENSIONS:
            raise HTTPException(
                status_code=415,
                detail="Supported formats: PDF, PNG, JPG, JPEG, DOCX",
            )

        content = await file.read(MAX_FILE_SIZE + 1)

        if not content:
            raise HTTPException(status_code=400, detail="The uploaded file is empty")

        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(status_code=413, detail="File exceeds 50 MB limit")

        try:
            watermark_id, confidence = await run_in_threadpool(
                _identify, content, extension, db, current_user.id
            )
        except Exception:
            # Deliberately vague: do not reveal parser details.
            raise HTTPException(
                status_code=404,
                detail="No valid watermark found in this file",
            ) from None

        return ExtractWatermarkResponse(
            watermark_id=watermark_id,
            confidence=confidence,
        )

    except HTTPException:
        raise

    except Exception:
        logger.exception("Watermark extraction failed")
        raise HTTPException(
            status_code=500,
            detail="Watermark extraction failed",
        ) from None

    finally:
        await file.close()