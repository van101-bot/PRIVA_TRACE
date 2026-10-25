from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SignerKeyReference:
    """
    Identifies which recipient signing key generated
    the provenance signature.

    The private key itself is NEVER stored here.
    """

    recipient_id: str
    key_id: str
    key_version: int
    algorithm: str = "ML-DSA-65"

    def as_dict(self) -> dict:
        return {
            "recipient_id": self.recipient_id,
            "key_id": self.key_id,
            "key_version": self.key_version,
            "algorithm": self.algorithm,
        }


@dataclass(frozen=True)
class ProvenanceAlgorithmProfile:
    kem_algorithm: str = "ML-KEM-768"
    signature_algorithm: str = "ML-DSA-65"
    symmetric_algorithm: str = "AES-256-GCM"
    kdf_algorithm: str = "HKDF-SHA256"
    hash_algorithm: str = "SHA-256"
    qkd_provider: Optional[str] = "BB84-SIMULATOR"

    def as_dict(self) -> dict:
        return {
            "kem_algorithm": self.kem_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "symmetric_algorithm": self.symmetric_algorithm,
            "kdf_algorithm": self.kdf_algorithm,
            "hash_algorithm": self.hash_algorithm,
            "qkd_provider": self.qkd_provider,
        }