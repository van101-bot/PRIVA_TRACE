import pytest

from src.zkp.commitment import (
    Commitment,
    CommitmentSecret,
    PedersenStyleCommitment,
    derive_secret_from_identity,
)


def test_commitment_generation():
    secret = PedersenStyleCommitment.generate_secret()

    commitment = PedersenStyleCommitment.commit(secret)

    assert isinstance(secret, CommitmentSecret)
    assert isinstance(commitment, Commitment)
    assert commitment.value > 0


def test_commitment_opening_verifies():
    secret = PedersenStyleCommitment.generate_secret()

    commitment = PedersenStyleCommitment.commit(secret)

    assert PedersenStyleCommitment.verify_opening(
        commitment,
        secret,
    )


def test_wrong_secret_does_not_open_commitment():
    secret = PedersenStyleCommitment.generate_secret()
    attacker_secret = PedersenStyleCommitment.generate_secret()

    commitment = PedersenStyleCommitment.commit(secret)

    assert not PedersenStyleCommitment.verify_opening(
        commitment,
        attacker_secret,
    )


def test_identity_derivation_is_deterministic():
    secret_a = derive_secret_from_identity(
        "recipient-001"
    )
    secret_b = derive_secret_from_identity(
        "recipient-001"
    )

    assert secret_a == secret_b


def test_different_identities_produce_different_secrets():
    secret_a = derive_secret_from_identity(
        "recipient-001"
    )
    secret_b = derive_secret_from_identity(
        "recipient-002"
    )

    assert secret_a != secret_b


def test_empty_identity_rejected():
    with pytest.raises(ValueError):
        derive_secret_from_identity("")


def test_invalid_secret_type_rejected():
    with pytest.raises(TypeError):
        PedersenStyleCommitment.commit("invalid")  # type: ignore[arg-type]