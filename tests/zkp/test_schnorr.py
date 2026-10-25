from src.zkp.commitment import (
    PedersenStyleCommitment,
)
from src.zkp.schnorr import (
    SchnorrProver,
    SchnorrVerifier,
)


def test_schnorr_proof_verifies():
    credential = PedersenStyleCommitment.generate_secret()

    commitment = PedersenStyleCommitment.commit(
        credential
    )

    statement = b"SIH26237 test statement"

    proof = SchnorrProver.prove(
        secret=credential.value,
        commitment=commitment.value,
        statement=statement,
    )

    assert SchnorrVerifier.verify(
        commitment=commitment.value,
        proof=proof,
        statement=statement,
    )


def test_modified_statement_fails():
    credential = PedersenStyleCommitment.generate_secret()

    commitment = PedersenStyleCommitment.commit(
        credential
    )

    proof = SchnorrProver.prove(
        secret=credential.value,
        commitment=commitment.value,
        statement=b"original",
    )

    assert not SchnorrVerifier.verify(
        commitment=commitment.value,
        proof=proof,
        statement=b"modified",
    )


def test_modified_challenge_fails():
    credential = PedersenStyleCommitment.generate_secret()

    commitment = PedersenStyleCommitment.commit(
        credential
    )

    proof = SchnorrProver.prove(
        secret=credential.value,
        commitment=commitment.value,
        statement=b"statement",
    )

    modified = type(proof)(
        commitment=proof.commitment,
        challenge=(proof.challenge + 1),
        response=proof.response,
    )

    assert not SchnorrVerifier.verify(
        commitment=commitment.value,
        proof=modified,
        statement=b"statement",
    )


def test_wrong_commitment_fails():
    credential = PedersenStyleCommitment.generate_secret()
    other_credential = (
        PedersenStyleCommitment.generate_secret()
    )

    commitment = PedersenStyleCommitment.commit(
        credential
    )

    other_commitment = PedersenStyleCommitment.commit(
        other_credential
    )

    proof = SchnorrProver.prove(
        secret=credential.value,
        commitment=commitment.value,
        statement=b"statement",
    )

    assert not SchnorrVerifier.verify(
        commitment=other_commitment.value,
        proof=proof,
        statement=b"statement",
    )