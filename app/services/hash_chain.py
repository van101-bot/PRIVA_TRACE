"""Local SHA-256 hash-chained audit ledger (Member 4/5 starter), privacy-first wrapper.

Only watermark_id + hashes go in. recipient_id is ALWAYS None, so no recipient
identity ever reaches this ledger. It is a tamper-evident local log, NOT a
distributed blockchain (Fabric is the distributed anchor: see /fabric).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from app.services.provenance_ledger import ProvenanceLedger

_DEFAULT = Path(__file__).resolve().parents[2] / "storage" / "provenance_chain.sqlite3"


def get_chain() -> ProvenanceLedger:
    return ProvenanceLedger(os.environ.get("LEDGER_CHAIN_DB", str(_DEFAULT)))


def append_decryption(watermark_id: str, document_hash: str, signature: str) -> dict:
    return get_chain().record_watermark_extraction(
        watermark_id=watermark_id,
        recipient_id=None,
        metadata={
            "event": "decryption",
            "document_hash": document_hash,
            "signature_sha256": hashlib.sha256(signature.encode()).hexdigest(),
        },
    )


def list_records(limit: int = 50) -> list[dict]:
    """Newest-first chain records. recipient_id is never selected."""
    import json
    import sqlite3

    chain = get_chain()
    with chain._connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT sequence, event_type, watermark_id, event_timestamp, metadata_json,
                      previous_hash, record_hash
               FROM provenance_records ORDER BY sequence DESC LIMIT ?""",
            (int(limit),),
        ).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        meta = json.loads(d.pop("metadata_json") or "{}")
        d["event"] = meta.get("event")
        d["document_hash"] = meta.get("document_hash")
        out.append(d)
    return out
