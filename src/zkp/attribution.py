from __future__ import annotations

import hashlib
from dataclasses import dataclass

from src.zkp.commitment import (
    Commitment,
    CommitmentSecret,
    PedersenStyleCommitment,
    derive_secret_from_identity,
)
from src.zkp.schnorr import (
    SchnorrProof,
    SchnorrProver,
    SchnorrVerifier,
)


@dataclass(frozen=True)
class AttributionCredential:
    """
    Public/private components of an attribution credential.

    secret:
        kept private by the recipient.

    commitment:
        safe to publish as part of authorization metadata.
    """

    secret: CommitmentSecret
    commitment: Commitment


@dataclass(frozen=True)
class AttributionProof:
    recipient_commitment: int
    proof: SchnorrProof
    document_binding: bytes


class AttributionProver:
    """
    Creates privacy-preserving attribution proofs.

    The prover demonstrates knowledge of the secret corresponding
    to a registered recipient commitment.
    """

    @staticmethod
    def create_credential(
        identity: str,
    ) -> AttributionCredential:
        secret = derive_secret_from_identity(identity)

        commitment = PedersenStyleCommitment.commit(secret)

        return AttributionCredential(
            secret=secret,
            commitment=commitment,
        )

    @staticmethod
    def create_proof(
        credential: AttributionCredential,
        document_id: str,
        provenance_digest: bytes,
    ) -> AttributionProof:
        if not document_id:
            raise ValueError("document_id must not be empty")

        if not provenance_digest:
            raise ValueError(
                "provenance_digest must not be empty"
            )

        statement = AttributionProver._build_statement(
            document_id,
            provenance_digest,
        )

        proof = SchnorrProver.prove(
            secret=credential.secret.value,
            commitment=credential.commitment.value,
            statement=statement,
        )

        return AttributionProof(
            recipient_commitment=credential.commitment.value,
            proof=proof,
            document_binding=statement,
        )

    @staticmethod
    def _build_statement(
        document_id: str,
        provenance_digest: bytes,
    ) -> bytes:
        document_hash = hashlib.sha256(
            document_id.encode("utf-8")
        ).digest()

        return (
            b"SIH26237-ATTRIBUTION-V1|" +
            document_hash +
            b"|" +
            provenance_digest
        )


class AttributionVerifier:
    """
    Verifies an attribution proof without learning the recipient
    identity or secret.
    """

    @staticmethod
    def verify(
        proof: AttributionProof,
        *,
        document_id: str,
        provenance_digest: bytes,
    ) -> bool:
        if not isinstance(proof, AttributionProof):
            return False

        if not document_id:
            return False

        if not provenance_digest:
            return False

        expected_statement = AttributionProver._build_statement(
            document_id,
            provenance_digest,
        )

        if proof.document_binding != expected_statement:
            return False

        return SchnorrVerifier.verify(
            commitment=proof.recipient_commitment,
            proof=proof.proof,
            statement=expected_statement,
        )