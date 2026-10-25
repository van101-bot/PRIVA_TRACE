"""
Key revocation helpers.

recipient_id is never stored. We store a keyed hash (HMAC-SHA256 with the
server master key), so a guessable ID cannot be confirmed from the table.
A revocation applies only to documents owned by the user who made it.
"""

from __future__ import annotations

import hashlib
import hmac

from sqlalchemy.orm import Session

from app.models.key_revocation import KeyRevocation
from app.services.key_management import load_master_key


def recipient_hash(recipient_id: str) -> str:
    return hmac.new(
        load_master_key(),
        b"SIH26237-REVOCATION-V1|" + recipient_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def revoked_recipients(
    db: Session, owner_id: int, recipient_ids: list[str]
) -> set[str]:
    """Returns the subset of recipient_ids revoked by this owner (one query)."""
    by_hash = {recipient_hash(r): r for r in recipient_ids}
    if not by_hash:
        return set()

    rows = (
        db.query(KeyRevocation.recipient_id_hash)
        .filter(
            KeyRevocation.revoked_by == owner_id,
            KeyRevocation.recipient_id_hash.in_(list(by_hash)),
        )
        .all()
    )
    return {by_hash[row[0]] for row in rows}


def is_revoked(db: Session, owner_id: int, recipient_id: str) -> bool:
    return recipient_id in revoked_recipients(db, owner_id, [recipient_id])