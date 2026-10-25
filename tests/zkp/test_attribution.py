from src.zkp.attribution import (
    AttributionProver,
    AttributionVerifier,
)


def test_attribution_proof_verifies():
    credential = AttributionProver.create_credential(
        "recipient-001"
    )

    proof = AttributionProver.create_proof(
        credential=credential,
        document_id="document-001",
        provenance_digest=b"provenance-digest",
    )

    assert AttributionVerifier.verify(
        proof,
        document_id="document-001",
        provenance_digest=b"provenance-digest",
    )


def test_wrong_document_fails():
    credential = AttributionProver.create_credential(
        "recipient-001"
    )

    proof = AttributionProver.create_proof(
        credential=credential,
        document_id="document-001",
        provenance_digest=b"provenance-digest",
    )

    assert not AttributionVerifier.verify(
        proof,
        document_id="document-002",
        provenance_digest=b"provenance-digest",
    )


def test_wrong_provenance_digest_fails():
    credential = AttributionProver.create_credential(
        "recipient-001"
    )

    proof = AttributionProver.create_proof(
        credential=credential,
        document_id="document-001",
        provenance_digest=b"digest-a",
    )

    assert not AttributionVerifier.verify(
        proof,
        document_id="document-001",
        provenance_digest=b"digest-b",
    )


def test_different_recipient_cannot_reuse_proof():
    credential_a = AttributionProver.create_credential(
        "recipient-001"
    )

    credential_b = AttributionProver.create_credential(
        "recipient-002"
    )

    proof_a = AttributionProver.create_proof(
        credential=credential_a,
        document_id="document-001",
        provenance_digest=b"digest",
    )

    assert proof_a.recipient_commitment != (
        credential_b.commitment.value
    )


def test_empty_document_id_rejected():
    credential = AttributionProver.create_credential(
        "recipient-001"
    )

    try:
        AttributionProver.create_proof(
            credential=credential,
            document_id="",
            provenance_digest=b"digest",
        )
        assert False
    except ValueError:
        assert True