"""
Signs and verifies ledger records with ML-DSA-65 (Dilithium).

The signing key pair is created on first use and stored in
storage/keys/ledger_signing.json.
DEMO ONLY: in production this key must live in an HSM.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from src.pqc.signature import MLDSA

PROJECT_ROOT = Path(__file__).resolve().parents[2]
KEY_PATH = PROJECT_ROOT / "storage" / "keys" / "ledger_signing.json"

DOMAIN = b"SIH26237-LEDGER-V1|"
_lock = threading.Lock()


def normalize_timestamp(value: datetime) -> str:
    """Same string whether the datetime came from Postgres or SQLite."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


@lru_cache(maxsize=1)
def _keys() -> tuple[bytes, bytes]:
    """Returns (public_key, private_key). Creates them on first use."""
    with _lock:
        if KEY_PATH.is_file():
            data = json.loads(KEY_PATH.read_text(encoding="utf-8"))
            return (
                base64.b64decode(data["public_key"]),
                base64.b64decode(data["private_key"]),
            )

        pair = MLDSA().generate_keypair()
        KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
        KEY_PATH.write_text(
            json.dumps(
                {
                    "algorithm": "ML-DSA-65",
                    "public_key": base64.b64encode(pair.public_key).decode(),
                    "private_key": base64.b64encode(pair.private_key).decode(),
                }
            ),
            encoding="utf-8",
        )
        return pair.public_key, pair.private_key


def ledger_message(
    *,
    watermark_id: str,
    zkp_proof: str,
    document_hash: str,
    encrypted_file_id: str,
    timestamp: datetime,
) -> bytes:
    body = {
        "watermark_id": watermark_id,
        "zkp_proof_sha256": hashlib.sha256(zkp_proof.encode("utf-8")).hexdigest(),
        "document_hash": document_hash,
        "encrypted_file_id": encrypted_file_id,
        "timestamp": normalize_timestamp(timestamp),
    }
    return DOMAIN + json.dumps(
        body, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sign_record(**fields) -> str:
    _, private_key = _keys()
    signature = MLDSA().sign(ledger_message(**fields), private_key)
    return base64.b64encode(signature).decode("ascii")


def verify_record_signature(signature: str | None, **fields) -> bool:
    """Never raises: a missing or broken signature just returns False."""
    if not signature:
        return False
    try:
        public_key, _ = _keys()
        return MLDSA().verify(
            ledger_message(**fields),
            base64.b64decode(signature),
            public_key,
        )
    except Exception:
        return False