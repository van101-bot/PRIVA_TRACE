from __future__ import annotations

from dataclasses import dataclass

from src.pqc.kem import MLKEM
from src.qkd.simulator import QKDProvider, QKDSession
from src.hybrid.kdf import HybridKDF


@dataclass(frozen=True)
class HybridSession:
    qkd_session: QKDSession
    mlkem_ciphertext: bytes
    hybrid_key: bytes


class HybridKeyExchange:
    """
    Performs:

        QKD key establishment
              +
        ML-KEM key establishment
              ↓
        HKDF-SHA256
              ↓
        hybrid AES key
    """

    def __init__(
        self,
        qkd_provider: QKDProvider,
        mlkem_algorithm: str = "ML-KEM-768",
    ) -> None:
        self.qkd_provider = qkd_provider
        self.mlkem = MLKEM(mlkem_algorithm)

    def establish(
        self,
        recipient_public_key: bytes,
    ) -> HybridSession:
        if not recipient_public_key:
            raise ValueError(
                "recipient_public_key must not be empty"
            )

        qkd_session = self.qkd_provider.establish_key()

        encapsulation = self.mlkem.encapsulate(
            recipient_public_key
        )

        hybrid_key = HybridKDF.derive_key(
            qkd_secret=qkd_session.key,
            mlkem_secret=encapsulation.shared_secret,
        )

        return HybridSession(
            qkd_session=qkd_session,
            mlkem_ciphertext=encapsulation.ciphertext,
            hybrid_key=hybrid_key,
        )

    def recover_recipient_key(
        self,
        qkd_secret: bytes,
        mlkem_ciphertext: bytes,
        recipient_private_key: bytes,
    ) -> bytes:
        if not qkd_secret:
            raise ValueError("qkd_secret must not be empty")

        if not mlkem_ciphertext:
            raise ValueError(
                "mlkem_ciphertext must not be empty"
            )

        if not recipient_private_key:
            raise ValueError(
                "recipient_private_key must not be empty"
            )

        mlkem_secret = self.mlkem.decapsulate(
            mlkem_ciphertext,
            recipient_private_key,
        )

        return HybridKDF.derive_key(
            qkd_secret=qkd_secret,
            mlkem_secret=mlkem_secret,
        )