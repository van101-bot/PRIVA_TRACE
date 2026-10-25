from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


# RFC 3526 / finite-field Diffie-Hellman 2048-bit MODP group.
# This prototype uses the well-known safe-prime group.
P = int(
    """
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC
2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83
655D23DCA3AD961C62F356208552BB9ED529077096966D67
0C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE3
9E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2
BCBF6955817183995497CEA956AE515D2261898FA05101572
8E5A8AACAA68FFFFFFFFFFFFFFFF
""".replace("\n", "").replace(" ", ""),
    16,
)

G = 2

# Order of the large prime-order subgroup.
# For this prototype we use q = (p - 1) / 2.
Q = (P - 1) // 2


@dataclass(frozen=True)
class Commitment:
    value: int


@dataclass(frozen=True)
class CommitmentSecret:
    value: int


class PedersenStyleCommitment:
    """
    Prototype discrete-log commitment.

    Commitment:
        C = g^x mod p

    where:
        x = secret

    The commitment hides the secret under the discrete-log assumption.

    This class is intentionally small and educational. It is not intended
    to replace an audited production ZKP library.
    """

    @staticmethod
    def _validate_secret(secret: int) -> None:
        if not isinstance(secret, int):
            raise TypeError("secret must be an integer")

        if not 1 <= secret < Q:
            raise ValueError(
                "secret must satisfy 1 <= secret < subgroup order"
            )

    @staticmethod
    def generate_secret() -> CommitmentSecret:
        secret = secrets.randbelow(Q - 1) + 1
        return CommitmentSecret(value=secret)

    @staticmethod
    def commit(secret: CommitmentSecret) -> Commitment:
        if not isinstance(secret, CommitmentSecret):
            raise TypeError(
                "secret must be a CommitmentSecret"
            )

        PedersenStyleCommitment._validate_secret(secret.value)

        commitment = pow(G, secret.value, P)

        return Commitment(value=commitment)

    @staticmethod
    def verify_opening(
        commitment: Commitment,
        secret: CommitmentSecret,
    ) -> bool:
        if not isinstance(commitment, Commitment):
            raise TypeError(
                "commitment must be a Commitment"
            )

        if not isinstance(secret, CommitmentSecret):
            raise TypeError(
                "secret must be a CommitmentSecret"
            )

        try:
            PedersenStyleCommitment._validate_secret(secret.value)
        except (TypeError, ValueError):
            return False

        expected = pow(G, secret.value, P)

        return expected == commitment.value


def derive_secret_from_identity(
    identity: str,
    *,
    domain: str = "SIH26237-ZKP-IDENTITY-V1",
) -> CommitmentSecret:
    """
    Deterministically derives a scalar from an identity.

    IMPORTANT:
    This is useful for the prototype, but production systems should
    normally use a randomly generated secret stored in a secure
    credential/key-management system.

    The identity itself should not be exposed to the verifier.
    """

    if not isinstance(identity, str):
        raise TypeError("identity must be a string")

    if not identity:
        raise ValueError("identity must not be empty")

    digest = hashlib.sha256(
        domain.encode("utf-8") +
        b"|" +
        identity.encode("utf-8")
    ).digest()

    value = int.from_bytes(digest, "big") % (Q - 1) + 1

    return CommitmentSecret(value=value)