from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from src.provenance.models import DecryptionRecord


DOMAIN_SEPARATOR = b"SIH26237-PROVENANCE-RECORD-V1|"


def canonical_record_bytes(record: DecryptionRecord) -> bytes:
    """
    Serialize a provenance record deterministically.

    The record_hash field is deliberately excluded because the hash
    is calculated over the record before the hash is inserted.
    """

    data = asdict(record)
    data.pop("record_hash", None)

    encoded = json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")

    return DOMAIN_SEPARATOR + encoded


def calculate_record_hash(record: DecryptionRecord) -> str:
    """
    Calculate SHA-256 over the canonical provenance representation.
    """

    return hashlib.sha256(
        canonical_record_bytes(record)
    ).hexdigest()


def verify_record_hash(record: DecryptionRecord) -> bool:
    """
    Verify the stored record hash.
    """

    if not record.record_hash:
        return False

    expected = calculate_record_hash(record)

    return expected == record.record_hash