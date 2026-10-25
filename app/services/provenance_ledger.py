"""SQLite-backed, hash-chained provenance ledger starter.

This is a local tamper-evident audit ledger, NOT a distributed blockchain.
Use a protected database path and externally anchor/export ledger hashes if stronger
immutability or independent verification is required.
"""
from __future__ import annotations
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Optional

GENESIS_HASH = "0" * 64


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _record_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


class ProvenanceLedger:
    """Append events to a local SQLite ledger whose records form a SHA-256 chain."""
    def __init__(self, db_path: str | Path = "provenance_ledger.sqlite3") -> None:
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS provenance_records (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                watermark_id TEXT NOT NULL,
                recipient_id TEXT,
                event_timestamp REAL NOT NULL,
                metadata_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL UNIQUE
            )""")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def record_watermark_extraction(
        self,
        watermark_id: str,
        recipient_id: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        event_timestamp: Optional[float] = None,
    ) -> dict[str, Any]:
        """Record successful extraction. Returns sequence, record_hash and status.

        watermark_id must be a non-empty stable identifier extracted/resolved by the
        watermarking system. Do not pass raw document contents or secrets in metadata.
        """
        if not isinstance(watermark_id, str) or not watermark_id.strip():
            raise ValueError("watermark_id must be a non-empty string")
        if recipient_id is not None and not isinstance(recipient_id, str):
            raise ValueError("recipient_id must be a string or None")
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be a dict or None")

        timestamp = float(event_timestamp if event_timestamp is not None else time.time())
        metadata_json = _canonical_json(metadata or {})
        # BEGIN IMMEDIATE serializes concurrent writers before reading the chain tip.
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            last = conn.execute(
                "SELECT sequence, record_hash FROM provenance_records ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous_hash = last[1] if last else GENESIS_HASH
            sequence = (last[0] + 1) if last else 1
            payload = {
                "sequence": sequence,
                "event_type": "watermark_extraction",
                "watermark_id": watermark_id.strip(),
                "recipient_id": recipient_id,
                "event_timestamp": timestamp,
                "metadata_json": metadata_json,
                "previous_hash": previous_hash,
            }
            digest = _record_hash(payload)
            conn.execute(
                """INSERT INTO provenance_records
                (sequence,event_type,watermark_id,recipient_id,event_timestamp,metadata_json,previous_hash,record_hash)
                VALUES (?,?,?,?,?,?,?,?)""",
                (sequence, payload["event_type"], payload["watermark_id"], recipient_id,
                 timestamp, metadata_json, previous_hash, digest),
            )
            conn.commit()
        # Read-after-write check so callers can surface an explicit success result.
        with self._connect() as conn:
            row = conn.execute(
                "SELECT record_hash FROM provenance_records WHERE sequence=?", (sequence,)
            ).fetchone()
        if not row or row[0] != digest:
            raise RuntimeError("Provenance record write verification failed")
        return {"status": "recorded", "sequence": sequence, "watermark_id": watermark_id.strip(),
                "record_hash": digest, "previous_hash": previous_hash, "verified_write": True}

    def verify_chain(self) -> dict[str, Any]:
        """Recompute every record hash and previous-hash link."""
        with self._connect() as conn:
            rows = conn.execute(
                """SELECT sequence,event_type,watermark_id,recipient_id,event_timestamp,
                metadata_json,previous_hash,record_hash FROM provenance_records ORDER BY sequence"""
            ).fetchall()
        previous = GENESIS_HASH
        for expected_seq, row in enumerate(rows, start=1):
            seq, event_type, watermark_id, recipient_id, timestamp, metadata_json, prev_hash, digest = row
            payload = {"sequence": seq, "event_type": event_type, "watermark_id": watermark_id,
                       "recipient_id": recipient_id, "event_timestamp": timestamp,
                       "metadata_json": metadata_json, "previous_hash": prev_hash}
            if seq != expected_seq:
                return {"valid": False, "records_checked": expected_seq - 1,
                        "failed_sequence": seq, "reason": "sequence_gap_or_reordering"}
            if prev_hash != previous:
                return {"valid": False, "records_checked": expected_seq - 1,
                        "failed_sequence": seq, "reason": "previous_hash_mismatch"}
            if _record_hash(payload) != digest:
                return {"valid": False, "records_checked": expected_seq - 1,
                        "failed_sequence": seq, "reason": "record_hash_mismatch"}
            previous = digest
        return {"valid": True, "records_checked": len(rows), "ledger_tip_hash": previous}

    def find_by_watermark_id(self, watermark_id: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM provenance_records WHERE watermark_id=? ORDER BY sequence",
                (watermark_id,),
            ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["metadata"] = json.loads(item.pop("metadata_json"))
            results.append(item)
        return results


def record_watermark_extraction(watermark_id: str, recipient_id: Optional[str] = None,
                                metadata: Optional[dict[str, Any]] = None,
                                db_path: str | Path = "provenance_ledger.sqlite3") -> dict[str, Any]:
    """Convenience API requested by the integration team."""
    return ProvenanceLedger(db_path).record_watermark_extraction(
        watermark_id=watermark_id, recipient_id=recipient_id, metadata=metadata
    )


if __name__ == "__main__":
    ledger = ProvenanceLedger("provenance_ledger.sqlite3")
    result = ledger.record_watermark_extraction(
        watermark_id="WM-EXAMPLE-001",
        recipient_id="RECIPIENT_001",
        metadata={"source": "manual_smoke_test", "checksum_valid": True},
    )
    print("Record result:", json.dumps(result, indent=2))
    print("Chain verification:", json.dumps(ledger.verify_chain(), indent=2))
