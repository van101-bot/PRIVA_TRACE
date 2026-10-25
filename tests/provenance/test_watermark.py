from src.provenance.watermark import ForensicWatermark


def make_watermark():
    return ForensicWatermark.generate(
        document_id="document-001",
        document_hash="a" * 64,
        recipient_commitment="b" * 64,
        session_id="session-001",
    )


def test_watermark_generation():
    watermark = make_watermark()

    assert watermark.version == 1
    assert watermark.watermark_id
    assert watermark.nonce


def test_watermark_verification():
    watermark = make_watermark()

    assert ForensicWatermark.verify(watermark)


def test_watermark_serialization_round_trip():
    watermark = make_watermark()

    serialized = ForensicWatermark.serialize(
        watermark
    )

    recovered = ForensicWatermark.deserialize(
        serialized
    )

    assert recovered == watermark


def test_watermark_changes_between_sessions():
    first = ForensicWatermark.generate(
        document_id="document-001",
        document_hash="a" * 64,
        recipient_commitment="b" * 64,
        session_id="session-001",
    )

    second = ForensicWatermark.generate(
        document_id="document-001",
        document_hash="a" * 64,
        recipient_commitment="b" * 64,
        session_id="session-002",
    )

    assert first.watermark_id != second.watermark_id


def test_tampered_watermark_fails():
    watermark = make_watermark()

    modified = watermark.__class__(
        **{
            **watermark.__dict__,
            "watermark_id": "tampered",
        }
    )

    assert not ForensicWatermark.verify(modified)