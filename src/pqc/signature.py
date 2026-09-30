"""
ML-DSA wrapper for SIH26237.

ML-DSA is the NIST-standardized digital signature algorithm
specified by FIPS 204.
"""

from __future__ import annotations

from dataclasses import dataclass

import oqs


DEFAULT_ALGORITHM = "ML-DSA-65"


@dataclass(frozen=True)
class SignatureKeyPair:
    public_key: bytes
    private_key: bytes


class MLDSA:
    """Application wrapper around liboqs ML-DSA."""

    def __init__(self, algorithm: str = DEFAULT_ALGORITHM) -> None:
        self.algorithm = algorithm

        enabled = oqs.get_enabled_sig_mechanisms()

        if algorithm not in enabled:
            raise ValueError(
                f"{algorithm} is not enabled by liboqs. "
                f"Available algorithms: {enabled}"
            )

    def generate_keypair(self) -> SignatureKeyPair:
        """Generate ML-DSA signing keys."""

        with oqs.Signature(self.algorithm) as signer:
            public_key = signer.generate_keypair()
            private_key = signer.export_secret_key()

        return SignatureKeyPair(
            public_key=public_key,
            private_key=private_key,
        )

    def sign(
        self,
        message: bytes,
        private_key: bytes,
    ) -> bytes:
        """Sign a message."""

        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")

        if not private_key:
            raise ValueError("private_key must not be empty")

        with oqs.Signature(
            self.algorithm,
            private_key,
        ) as signer:
            return signer.sign(message)

    def verify(
        self,
        message: bytes,
        signature: bytes,
        public_key: bytes,
    ) -> bool:
        """Verify an ML-DSA signature."""

        if not isinstance(message, bytes):
            raise TypeError("message must be bytes")

        if not signature:
            return False

        if not public_key:
            return False

        with oqs.Signature(self.algorithm) as verifier:
            return verifier.verify(
                message,
                signature,
                public_key,
            )