from src.provenance.record import ProvenanceRecordBuilder
from src.provenance.watermark import ForensicWatermark
from src.provenance.canonical import verify_record_hash


def test_decryption_record_creation():
    watermark = ForensicWatermark.generate(
        document_id="document-001",
        document_hash="a" * 64,
        recipient_commitment="b" * 64,
        session_id="session-001",
    )

    record = ProvenanceRecordBuilder.build(
        document_id="document-001",
        document_hash="a" * 64,
        recipient_commitment="b" * 64,
        session_id="session-001",
        watermark=watermark,
    )

    assert record.event_type == "DOCUMENT_DECRYPTED"
    assert record.record_hash
    assert verify_record_hash(record)


def test_record_binds_watermark():
    watermark = ForensicWatermark.generate(
        document_id="document-001",
        document_hash="a" * 64,
        recipient_commitment="b" * 64,
        session_id="session-001",
    )

    record = ProvenanceRecordBuilder.build(
        document_id="document-001",
        document_hash="a" * 64,
        recipient_commitment="b" * 64,
        session_id="session-001",
        watermark=watermark,
    )

    assert record.watermark_id == watermark.watermark_id