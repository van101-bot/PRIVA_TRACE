"""
Hyperledger Fabric anchoring (optional; needs FABRIC_ENABLED=1).
Uses Member 4's FabricClient (app/services/fabric_client.py), unchanged.

GET  /fabric/status                  is the integration switched on?
POST /fabric/anchor                  copy one signed ledger record onto Fabric
GET  /fabric/verify/{watermark_id}   is it on Fabric, and does it match ours?

Same rules as /ledger: only the user who created the record can use it (others
get 404), the stored row must still pass its ML-DSA signature, and no
recipient identity is involved anywhere.
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Path
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.decryption_record import DecryptionRecord
from app.models.user import User
from app.schemas.privacy import WATERMARK_ID_PATTERN
from app.services.fabric_client import FabricClient
from app.services.ledger_signer import normalize_timestamp, verify_record_signature

router = APIRouter(prefix="/fabric", tags=["Fabric"])
logger = logging.getLogger(__name__)


def is_enabled() -> bool:
    return os.environ.get("FABRIC_ENABLED", "0") == "1"


def get_client() -> FabricClient:
    """A dependency so tests can swap in a fake. Member 4's client, unchanged."""
    return FabricClient()


class AnchorRequest(BaseModel):
    watermark_id: str = Field(pattern=WATERMARK_ID_PATTERN)


def _require_enabled() -> None:
    if not is_enabled():
        raise HTTPException(status_code=503, detail="Fabric integration is not enabled")


def _own_intact_record(db: Session, user: User, watermark_id: str) -> DecryptionRecord:
    record = (
        db.query(DecryptionRecord)
        .filter(DecryptionRecord.watermark_id == watermark_id)
        .first()
    )
    if record is None or record.created_by != user.id:
        raise HTTPException(
            status_code=404, detail="No ledger record exists for this watermark_id"
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
            status_code=409, detail="Ledger record failed its integrity check"
        )
    return record


def _fields(record: DecryptionRecord) -> dict:
    return {
        "watermark_id": record.watermark_id,
        "document_hash": record.document_hash,
        "timestamp": normalize_timestamp(record.timestamp),
        "signature": record.signature,
        "zkp_proof": record.zkp_proof,
    }


@router.get("/status")
def fabric_status():
    return {"enabled": is_enabled()}


@router.post("/anchor")
def anchor_record(
    body: AnchorRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    client: FabricClient = Depends(get_client),
):
    _require_enabled()
    record = _own_intact_record(db, current_user, body.watermark_id)

    try:
        client.record_decryption(**_fields(record))
    except RuntimeError as exc:
        # The chaincode refuses a watermark ID that was already recorded.
        if "already exists" in str(exc):
            raise HTTPException(status_code=409, detail="Already anchored on Fabric") from None
        logger.error("Fabric anchor failed: %s", exc)
        raise HTTPException(status_code=502, detail="Fabric network unavailable") from None

    return {"watermark_id": record.watermark_id, "anchored": True}


@router.get("/verify/{watermark_id}")
def verify_record(
    watermark_id: str = Path(pattern=WATERMARK_ID_PATTERN),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    client: FabricClient = Depends(get_client),
):
    _require_enabled()
    record = _own_intact_record(db, current_user, watermark_id)

    try:
        on_chain, matches = client.verify(**_fields(record))
    except RuntimeError as exc:
        logger.error("Fabric verify failed: %s", exc)
        raise HTTPException(status_code=502, detail="Fabric network unavailable") from None

    return {
        "watermark_id": watermark_id,
        "on_chain": on_chain,
        "matches_local": matches,
    }
