from src.pqc.signature import MLDSA
from src.provenance.record import ProvenanceRecordBuilder
from src.provenance.signer import ProvenanceSigner
from src.provenance.verifier import ProvenanceVerifier
from src.provenance.watermark import ForensicWatermark


def create_complete_package():
    dsa = MLDSA("ML-DSA-65")
    keypair = dsa.generate_keypair()

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

    signer = ProvenanceSigner()

    signed = signer.sign(
        record,
        keypair.private_key,
        keypair.public_key,
    )

    return watermark, signed


def test_complete_provenance_verification():
    watermark, signed = create_complete_package()

    verifier = ProvenanceVerifier()

    assert verifier.verify_complete(
        watermark,
        signed,
    )


def test_mismatched_watermark_fails():
    watermark, signed = create_complete_package()

    other = ForensicWatermark.generate(
        document_id="different-document",
        document_hash="a" * 64,
        recipient_commitment="b" * 64,
        session_id="different-session",
    )

    verifier = ProvenanceVerifier()

    assert not verifier.verify_complete(
        other,
        signed,
    )