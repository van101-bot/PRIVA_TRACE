from dataclasses import dataclass


@dataclass(frozen=True)
class SecurityProfile:
    """
    Cryptographic configuration for SIH26237.

    This centralizes algorithm identifiers so that the system
    does not silently use different algorithms in different modules.
    """

    profile_id: str = "SIH26237-PQC-1"

    kem_algorithm: str = "ML-KEM-768"
    kem_standard: str = "FIPS-203"

    signature_algorithm: str = "ML-DSA-65"
    signature_standard: str = "FIPS-204"

    symmetric_algorithm: str = "AES-256-GCM"

    kdf_algorithm: str = "HKDF-SHA256"

    hash_algorithm: str = "SHA-256"

    qkd_provider: str = "BB84-SIMULATOR"

    watermark_version: int = 1
    provenance_version: int = 1

    cek_length: int = 32
    aes_gcm_nonce_length: int = 12

    def as_dict(self) -> dict:
        return {
            "profile_id": self.profile_id,
            "kem": {
                "algorithm": self.kem_algorithm,
                "standard": self.kem_standard,
            },
            "signature": {
                "algorithm": self.signature_algorithm,
                "standard": self.signature_standard,
            },
            "symmetric": self.symmetric_algorithm,
            "kdf": self.kdf_algorithm,
            "hash": self.hash_algorithm,
            "qkd_provider": self.qkd_provider,
            "watermark_version": self.watermark_version,
            "provenance_version": self.provenance_version,
        }


DEFAULT_SECURITY_PROFILE = SecurityProfile()