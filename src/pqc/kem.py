"""
ML-KEM wrapper for SIH26237.

ML-KEM is the NIST-standardized KEM specified by FIPS 203.

This module deliberately keeps the application-facing API small so that
the underlying PQC library can be replaced or upgraded later.
"""

from __future__ import annotations

from dataclasses import dataclass

import oqs


DEFAULT_ALGORITHM = "ML-KEM-768"


@dataclass(frozen=True)
class KEMKeyPair:
    """ML-KEM public/private key pair."""

    public_key: bytes
    private_key: bytes


@dataclass(frozen=True)
class KEMEncapsulation:
    """Result of KEM encapsulation."""

    ciphertext: bytes
    shared_secret: bytes


class MLKEM:
    """Application wrapper around liboqs ML-KEM."""

    def __init__(self, algorithm: str = DEFAULT_ALGORITHM) -> None:
        self.algorithm = algorithm

        enabled = oqs.get_enabled_kem_mechanisms()

        if algorithm not in enabled:
            raise ValueError(
                f"{algorithm} is not enabled by liboqs. "
                f"Available algorithms: {enabled}"
            )

    def generate_keypair(self) -> KEMKeyPair:
        """Generate a new ML-KEM key pair."""

        with oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()

        return KEMKeyPair(
            public_key=public_key,
            private_key=private_key,
        )

    def encapsulate(self, public_key: bytes) -> KEMEncapsulation:
        """Encapsulate a shared secret using a recipient public key."""

        if not public_key:
            raise ValueError("public_key must not be empty")

        with oqs.KeyEncapsulation(self.algorithm) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)

        return KEMEncapsulation(
            ciphertext=ciphertext,
            shared_secret=shared_secret,
        )

    def decapsulate(
        self,
        ciphertext: bytes,
        private_key: bytes,
    ) -> bytes:
        """Recover the shared secret using the recipient private key."""

        if not ciphertext:
            raise ValueError("ciphertext must not be empty")

        if not private_key:
            raise ValueError("private_key must not be empty")

        with oqs.KeyEncapsulation(
            self.algorithm,
            private_key,
        ) as kem:
            return kem.decap_secret(ciphertext)