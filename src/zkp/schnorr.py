from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from src.zkp.commitment import G, P, Q


@dataclass(frozen=True)
class SchnorrProof:
    commitment: int
    challenge: int
    response: int


class SchnorrProver:
    """
    Non-interactive Schnorr-style proof using Fiat-Shamir.

    Proves knowledge of x such that:

        commitment = g^x mod p

    without revealing x.
    """

    @staticmethod
    def _hash_to_challenge(
        commitment: int,
        nonce_commitment: int,
        statement: bytes,
    ) -> int:
        digest = hashlib.sha256(
            b"SIH26237-SCHNORR-V1|" +
            statement +
            b"|" +
            commitment.to_bytes(
                (commitment.bit_length() + 7) // 8,
                "big",
            ) +
            b"|" +
            nonce_commitment.to_bytes(
                (nonce_commitment.bit_length() + 7) // 8,
                "big",
            )
        ).digest()

        return int.from_bytes(digest, "big") % Q

    @classmethod
    def prove(
        cls,
        secret: int,
        commitment: int,
        *,
        statement: bytes,
    ) -> SchnorrProof:
        if not isinstance(secret, int):
            raise TypeError("secret must be an integer")

        if not isinstance(commitment, int):
            raise TypeError("commitment must be an integer")

        if not isinstance(statement, bytes):
            raise TypeError("statement must be bytes")

        if not statement:
            raise ValueError("statement must not be empty")

        if not 1 <= secret < Q:
            raise ValueError(
                "secret must satisfy 1 <= secret < subgroup order"
            )

        expected_commitment = pow(G, secret, P)

        if expected_commitment != commitment:
            raise ValueError(
                "secret does not match commitment"
            )

        nonce = secrets.randbelow(Q - 1) + 1

        nonce_commitment = pow(G, nonce, P)

        challenge = cls._hash_to_challenge(
            commitment,
            nonce_commitment,
            statement,
        )

        response = (
            nonce +
            challenge * secret
        ) % Q

        return SchnorrProof(
            commitment=nonce_commitment,
            challenge=challenge,
            response=response,
        )


class SchnorrVerifier:
    @staticmethod
    def _hash_to_challenge(
        statement_commitment: int,
        nonce_commitment: int,
        statement: bytes,
    ) -> int:
        digest = hashlib.sha256(
            b"SIH26237-SCHNORR-V1|" +
            statement +
            b"|" +
            statement_commitment.to_bytes(
                (statement_commitment.bit_length() + 7) // 8,
                "big",
            ) +
            b"|" +
            nonce_commitment.to_bytes(
                (nonce_commitment.bit_length() + 7) // 8,
                "big",
            )
        ).digest()

        return int.from_bytes(digest, "big") % Q

    @classmethod
    def verify(
        cls,
        commitment: int,
        proof: SchnorrProof,
        *,
        statement: bytes,
    ) -> bool:
        if not isinstance(commitment, int):
            return False

        if not isinstance(proof, SchnorrProof):
            return False

        if not isinstance(statement, bytes):
            return False

        if not statement:
            return False

        if not 1 <= commitment < P:
            return False

        if not 1 <= proof.commitment < P:
            return False

        if not 0 <= proof.challenge < Q:
            return False

        if not 0 <= proof.response < Q:
            return False

        expected_challenge = cls._hash_to_challenge(
            commitment,
            proof.commitment,
            statement,
        )

        if proof.challenge != expected_challenge:
            return False

        left = pow(G, proof.response, P)

        right = (
            proof.commitment *
            pow(commitment, proof.challenge, P)
        ) % P

        return left == right