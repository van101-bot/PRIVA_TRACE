"""
POST /ledger-chain/append   copy one of YOUR signed ledger records into the local hash chain
GET  /ledger-chain/verify   recompute the whole chain (valid / tip hash only, no identities)
Same rules as /fabric: own records only (404 otherwise), ML-DSA signature must still pass.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.api.fabric import AnchorRequest, _own_intact_record
from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.decryption_record import DecryptionRecord
from app.models.user import User
from app.services.hash_chain import append_decryption, get_chain, list_records

router = APIRouter(prefix="/ledger-chain", tags=["Ledger chain"])


@router.post("/append", status_code=201)
async def append(
    body: AnchorRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    record = _own_intact_record(db, current_user, body.watermark_id)
    result = await run_in_threadpool(
        append_decryption, record.watermark_id, record.document_hash, record.signature
    )
    return {k: result[k] for k in ("status", "sequence", "record_hash", "previous_hash")}


@router.get("/verify")
async def verify(current_user: User = Depends(get_current_user)):
    return await run_in_threadpool(lambda: get_chain().verify_chain())


@router.get("/records")
async def records(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Chain records, newest first. watermark_id is revealed only for the caller's own records."""
    rows = await run_in_threadpool(list_records, limit)
    ids = [r["watermark_id"] for r in rows]
    own: set[str] = set()
    if ids:
        own = {
            w
            for (w,) in db.query(DecryptionRecord.watermark_id).filter(
                DecryptionRecord.watermark_id.in_(ids),
                DecryptionRecord.created_by == current_user.id,
            )
        }
    return [
        {
            "sequence": r["sequence"],
            "event": r["event"] or r["event_type"],
            "watermark_id": r["watermark_id"] if r["watermark_id"] in own else None,
            "own": r["watermark_id"] in own,
            "document_hash": r["document_hash"],
            "timestamp": r["event_timestamp"],
            "previous_hash": r["previous_hash"],
            "record_hash": r["record_hash"],
        }
        for r in rows
    ]
