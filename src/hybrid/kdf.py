from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class HybridKDF:
    """
    Combines independent QKD and ML-KEM shared secrets
    into application key material using HKDF-SHA256.
    """

    OUTPUT_LENGTH = 32

    @staticmethod
    def derive_key(
        qkd_secret: bytes,
        mlkem_secret: bytes,
        *,
        context: bytes = b"SIH26237-HYBRID-DOCUMENT-KEY-V1",
    ) -> bytes:
        if not qkd_secret:
            raise ValueError("qkd_secret must not be empty")

        if not mlkem_secret:
            raise ValueError("mlkem_secret must not be empty")

        if not context:
            raise ValueError("context must not be empty")

        combined_secret = (
            b"SIH26237-QKD|" +
            qkd_secret +
            b"|SIH26237-MLKEM|" +
            mlkem_secret
        )

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=HybridKDF.OUTPUT_LENGTH,
            salt=None,
            info=context,
        )

        return hkdf.derive(combined_secret)