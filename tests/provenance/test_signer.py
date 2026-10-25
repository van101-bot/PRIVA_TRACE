from src.pqc.signature import MLDSA
from src.provenance.record import ProvenanceRecordBuilder
from src.provenance.signer import ProvenanceSigner
from src.provenance.watermark import ForensicWatermark


def make_signed_record():
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

    return signer, signed


def test_provenance_signature_verifies():
    signer, signed = make_signed_record()

    assert signer.verify(signed)


def test_modified_record_signature_fails():
    signer, signed = make_signed_record()

    modified_record = signed.record.__class__(
        **{
            **signed.record.__dict__,
            "document_id": "tampered-document",
        }
    )

    modified = signed.__class__(
        record=modified_record,
        signature=signed.signature,
        signer_public_key=signed.signer_public_key,
    )

    assert not signer.verify(modified)