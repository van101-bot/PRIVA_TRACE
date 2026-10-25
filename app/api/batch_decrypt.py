"""
POST /batch-decrypt

One encrypted document -> one watermarked copy per recipient, returned as a
ZIP. Each copy gets its own watermark, ZKP proof and signed ledger record.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import re
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api.decrypt_watermarked import EMBEDDABLE
from app.api.decryption import (
    ENCRYPTED_DIR,
    METADATA_DIR,
    DecryptionRequest,
    decrypt_hybrid_document,
)
from app.core.dependencies import get_current_user
from app.database.database import get_db
from app.models.decryption_record import DecryptionRecord
from app.models.user import User
from app.schemas.privacy import BatchDecryptRequest, BatchRecipient
from app.services.ledger_signer import sign_record
from app.services.zkp_service import create_zkp_proof
from src.provenance.apply import apply_watermark
from app.services.revocation import revoked_recipients

router = APIRouter(tags=["Decryption"])
logger = logging.getLogger(__name__)

MAX_WORKERS = 8
MAX_TOTAL_BYTES = 400 * 1024 * 1024  # rough cap on all copies together


@dataclass
class BatchItem:
    index: int
    recipient_id: str
    ok: bool = False
    error: str = ""
    filename: str = ""
    file_bytes: bytes = b""
    record: DecryptionRecord | None = None


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)[:60] or "recipient"


def _process_one(
    index: int,
    encrypted_file_id: str,
    recipient: BatchRecipient,
    extension: str,
    user,
) -> BatchItem:
    """Runs in a worker thread. Never touches the database session."""
    item = BatchItem(index=index, recipient_id=recipient.recipient_id)
    try:
        result = decrypt_hybrid_document(
            encrypted_file_id,
            DecryptionRequest(
                recipient_id=recipient.recipient_id,
                private_key=recipient.private_key,
            ),
            user,
        )
        original = base64.b64decode(result.decrypted_text_base64)
        document_hash = result.document_hash

        zkp_proof = create_zkp_proof(
            recipient.recipient_id, encrypted_file_id, document_hash
        )
        result_wm = apply_watermark(
            original,
            extension,
            zkp_proof=zkp_proof,
            document_id=encrypted_file_id,
            document_hash=document_hash,
        )
        marked = result_wm.file_bytes
        watermark_id = result_wm.watermark_id

        now = datetime.now(timezone.utc)
        signature = sign_record(
            watermark_id=result_wm.watermark_id,
            zkp_proof=zkp_proof,
            document_hash=document_hash,
            encrypted_file_id=encrypted_file_id,
            timestamp=now,
        )

        item.record = DecryptionRecord(
            watermark_id=result_wm.watermark_id,
            zkp_proof=zkp_proof,
            document_hash=document_hash,
            encrypted_file_id=encrypted_file_id,
            created_by=user.id,
            timestamp=now,
            signature=signature,
        )
        item.file_bytes = marked
        item.filename = f"{index:03d}_{_safe_name(recipient.recipient_id)}{extension}"
        item.ok = True

    except HTTPException as exc:
        item.error = str(exc.detail)
    except Exception:
        logger.exception("Batch item %d failed", index)
        item.error = "Internal error while processing this recipient"
    return item


@router.post("/batch-decrypt")
def batch_decrypt(
    body: BatchDecryptRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    request.state.audit_resource = body.encrypted_file_id
    started = time.perf_counter()

    ids = [r.recipient_id for r in body.recipients]
    if len(set(ids)) != len(ids):
        raise HTTPException(status_code=422, detail="Recipient IDs must be unique")

    # ---- document-level checks, done once before any crypto ----
    metadata_path = METADATA_DIR / f"{body.encrypted_file_id}.json"
    envelope_path = ENCRYPTED_DIR / f"{body.encrypted_file_id}.json"
    if not metadata_path.is_file() or not envelope_path.is_file():
        raise HTTPException(status_code=404, detail="Encrypted document not found")

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise HTTPException(status_code=500, detail="Unable to read document metadata")

    if metadata.get("owner_user_id") != current_user.id:
        raise HTTPException(status_code=403, detail="You do not own this encrypted document")

    extension = Path(metadata.get("original_filename", "")).suffix.lower()
    if extension not in EMBEDDABLE:
        raise HTTPException(
            status_code=415,
            detail=(
                "Watermarking is not available for this file type yet "
                "(supported: PNG, JPG, DOCX). No copy was released."
            ),
        )

    # Envelope JSON is base64, so original size is roughly 3/4 of it.
    estimated = envelope_path.stat().st_size * 3 // 4
    if estimated * len(ids) > MAX_TOTAL_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Document is too large for this many recipients in one batch",
        )

    # ---- parallel work (no database access inside the threads) ----
        # ---- parallel work (no database access inside the threads) ----
    user = SimpleNamespace(id=current_user.id)
    revoked = revoked_recipients(db, current_user.id, ids)

    def run(pair):
        index, recipient = pair
        if recipient.recipient_id in revoked:
            return BatchItem(
                index=index,
                recipient_id=recipient.recipient_id,
                error="This recipient's key has been revoked",
            )
        return _process_one(
            index, body.encrypted_file_id, recipient, extension, user
        )

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        items = list(pool.map(run, enumerate(body.recipients, start=1)))

    succeeded = [i for i in items if i.ok]
    failed = [i for i in items if not i.ok]

    if not succeeded:
        raise HTTPException(
            status_code=422,
            detail={
                "message": "No copy could be produced",
                "failures": [
                    {"index": i.index, "recipient_id": i.recipient_id, "error": i.error}
                    for i in failed
                ],
            },
        )

    # ---- one transaction: no ledger records means no ZIP ----
    try:
        db.add_all([i.record for i in succeeded])
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not save batch ledger records")
        raise HTTPException(
            status_code=500,
            detail="Could not record the batch; no copies were released",
        ) from None

    # ---- build the ZIP (images/DOCX are already compressed: store only) ----
    manifest = {
        "encrypted_file_id": body.encrypted_file_id,
        "requested": len(items),
        "succeeded": len(succeeded),
        "failed": len(failed),
        "files": [
            {"index": i.index, "recipient_id": i.recipient_id, "file": i.filename}
            for i in succeeded
        ],
        "failures": [
            {"index": i.index, "recipient_id": i.recipient_id, "error": i.error}
            for i in failed
        ],
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as archive:
        for item in succeeded:
            archive.writestr(item.filename, item.file_bytes)
        archive.writestr("manifest.json", json.dumps(manifest, indent=2))

    logger.info(
        "Batch %s: %d ok, %d failed in %.2fs",
        body.encrypted_file_id, len(succeeded), len(failed),
        time.perf_counter() - started,
    )

    return Response(
        content=buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="batch_{body.encrypted_file_id[:8]}.zip"',
            "X-Batch-Requested": str(len(items)),
            "X-Batch-Succeeded": str(len(succeeded)),
            "X-Batch-Failed": str(len(failed)),
        },
    )
