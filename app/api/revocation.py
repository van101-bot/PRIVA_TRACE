"""
POST /keys/generate - create an ML-KEM key pair (private key returned once)
POST /keys/revoke   - revoke a recipient's key (for documents you own)
GET  /keys/revoked  - list your revocations (hashes only, never recipient IDs)
"""

from __future__ import annotations

import base64
from datetime import datetime

from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.key_revocation import KeyRevocation
from app.models.user import User
from app.schemas.privacy import RevokeKeyRequest, RevokeKeyResponse, StrictModel
from app.services.revocation import recipient_hash
from src.pqc.kem import MLKEM

router = APIRouter(tags=["Keys"])


# ---------- key generation ----------

class GenerateKeyRequest(StrictModel):
    recipient_id: str = Field(min_length=1, max_length=128)


class GenerateKeyResponse(BaseModel):
    recipient_id: str
    algorithm: str
    public_key: str
    private_key: str
    note: str


@router.post("/keys/generate", response_model=GenerateKeyResponse, status_code=201)
def generate_key(body: GenerateKeyRequest):
    """Creates an ML-KEM key pair. The private key is returned once, never stored."""
    pair = MLKEM().generate_keypair()
    return GenerateKeyResponse(
        recipient_id=body.recipient_id,
        algorithm="ML-KEM-768",
        public_key=base64.b64encode(pair.public_key).decode(),
        private_key=base64.b64encode(pair.private_key).decode(),
        note=(
            "Shown once and not stored. Server-side generation is for demos; "
            "in production each recipient generates their own key pair."
        ),
    )


# ---------- revocation ----------

class RevokedKeyItem(BaseModel):
    recipient_id_hash: str
    reason: str
    revoked_at: datetime


@router.post("/keys/revoke", response_model=RevokeKeyResponse, status_code=201)
def revoke_key(
    body: RevokeKeyRequest,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    digest = recipient_hash(body.recipient_id)

    existing = (
        db.query(KeyRevocation)
        .filter(
            KeyRevocation.recipient_id_hash == digest,
            KeyRevocation.revoked_by == current_user.id,
        )
        .first()
    )
    if existing is not None:
        response.status_code = 200
        return RevokeKeyResponse(
            recipient_id_hash=digest,
            revoked_at=existing.revoked_at,
            status="already_revoked",
        )

    row = KeyRevocation(
        recipient_id_hash=digest,
        reason=body.reason,
        revoked_by=current_user.id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    return RevokeKeyResponse(
        recipient_id_hash=digest,
        revoked_at=row.revoked_at,
        status="revoked",
    )


@router.get("/keys/revoked", response_model=list[RevokedKeyItem])
def list_revoked_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    rows = (
        db.query(KeyRevocation)
        .filter(KeyRevocation.revoked_by == current_user.id)
        .order_by(KeyRevocation.revoked_at.desc())
        .all()
    )
    return [
        RevokedKeyItem(
            recipient_id_hash=r.recipient_id_hash,
            reason=r.reason,
            revoked_at=r.revoked_at,
        )
        for r in rows
    ]