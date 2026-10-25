from src.provenance.canonical import (
    calculate_record_hash,
    verify_record_hash,
)
from src.provenance.models import DecryptionRecord


def make_record() -> DecryptionRecord:
    return DecryptionRecord(
        record_version=1,
        event_type="DOCUMENT_DECRYPTED",
        event_id="event-001",
        document_id="document-001",
        document_hash="a" * 64,
        recipient_commitment="b" * 64,
        session_id="session-001",
        watermark_id="c" * 43,
        watermark_nonce="d" * 22,
        timestamp_utc="2026-10-01T10:00:00+00:00",
        kem_algorithm="ML-KEM-768",
        signature_algorithm="ML-DSA-65",
        encryption_algorithm="AES-256-GCM",
    )


def test_record_hash_is_deterministic():
    record = make_record()

    first = calculate_record_hash(record)
    second = calculate_record_hash(record)

    assert first == second
    assert len(first) == 64


def test_record_hash_verification():
    record = make_record()

    hashed = record.__class__(
        **{
            **record.__dict__,
            "record_hash": calculate_record_hash(record),
        }
    )

    assert verify_record_hash(hashed)


def test_modified_record_fails_hash_verification():
    record = make_record()

    record_hash = calculate_record_hash(record)

    hashed = record.__class__(
        **{
            **record.__dict__,
            "record_hash": record_hash,
        }
    )

    modified = record.__class__(
        **{
            **hashed.__dict__,
            "document_id": "modified-document",
        }
    )

    assert not verify_record_hash(modified)