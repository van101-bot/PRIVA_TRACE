from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from src.pqc.signature import MLDSA


@dataclass(frozen=True)
class SigningKeyRecord:
    """
    Metadata for a recipient ML-DSA signing identity.

    The private key itself is deliberately not stored in this record.
    Production deployments should keep private material inside an HSM
    or another protected keystore.
    """

    recipient_id: str
    key_version: int
    algorithm: str
    public_key: bytes
    created_at: str
    revoked: bool = False
    revocation_reason: str | None = None
    revoked_at: str | None = None


class SigningBackend(Protocol):
    """
    Abstract signing backend.

    This allows the application to use:
      - software storage during development
      - HSM storage later
      - PKCS#11-backed storage in production
    """

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """
        Return (public_key, private_key).
        """
        ...

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        """
        Sign a message.
        """
        ...

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        """
        Verify a signature.
        """
        ...


class SoftwareSigningBackend:
    """
    Development-only signing backend.

    This stores key material in memory.

    Do NOT describe this as an HSM.
    """

    def __init__(self, algorithm: str = "ML-DSA-65") -> None:
        self.algorithm = MLDSA(algorithm)

    def generate_keypair(self) -> tuple[bytes, bytes]:
        keypair = self.algorithm.generate_keypair()

        return (
            keypair.public_key,
            keypair.private_key,
        )

    def sign(
        self,
        private_key: bytes,
        message: bytes,
    ) -> bytes:
        return self.algorithm.sign(
            message,
            private_key,
        )

    def verify(
        self,
        public_key: bytes,
        message: bytes,
        signature: bytes,
    ) -> bool:
        return self.algorithm.verify(
            message,
            signature,
            public_key,
        )


class SigningKeyManager:
    """
    Version-aware ML-DSA signing identity manager.

    This intentionally keeps the interface separate from ML-KEM key
    management because encryption/decryption identity and signing
    identity have different security roles.
    """

    def __init__(
        self,
        backend: SigningBackend | None = None,
        algorithm: str = "ML-DSA-65",
    ) -> None:
        self.algorithm = algorithm
        self.backend = backend or SoftwareSigningBackend(algorithm)

        self._records: dict[tuple[str, int], SigningKeyRecord] = {}
        self._private_keys: dict[tuple[str, int], bytes] = {}

    def _next_key_version(self, recipient_id: str) -> int:
        versions = [
            version
            for (rid, version) in self._records
            if rid == recipient_id
        ]

        return max(versions, default=0) + 1

    def generate_keypair(
        self,
        recipient_id: str,
    ) -> SigningKeyRecord:
        if not recipient_id:
            raise ValueError("recipient_id must not be empty")

        public_key, private_key = self.backend.generate_keypair()

        key_version = self._next_key_version(recipient_id)

        created_at = datetime.now(timezone.utc).isoformat()

        record = SigningKeyRecord(
            recipient_id=recipient_id,
            key_version=key_version,
            algorithm=self.algorithm,
            public_key=public_key,
            created_at=created_at,
        )

        key = (recipient_id, key_version)

        self._records[key] = record
        self._private_keys[key] = private_key

        return record

    def get_public_key(
        self,
        recipient_id: str,
        key_version: int | None = None,
    ) -> bytes:
        record = self._get_record(
            recipient_id,
            key_version,
        )

        if record.revoked:
            raise PermissionError(
                f"Signing key is revoked: {recipient_id}"
            )

        return record.public_key

    def sign(
        self,
        *,
        recipient_id: str,
        message: bytes,
        key_version: int | None = None,
    ) -> bytes:
        if not message:
            raise ValueError("message must not be empty")

        record = self._get_record(
            recipient_id,
            key_version,
        )

        if record.revoked:
            raise PermissionError(
                f"Signing key is revoked: {recipient_id}"
            )

        key = (
            recipient_id,
            record.key_version,
        )

        private_key = self._private_keys.get(key)

        if private_key is None:
            raise RuntimeError(
                "Private signing key is unavailable"
            )

        return self.backend.sign(
            private_key,
            message,
        )

    def verify(
        self,
        *,
        recipient_id: str,
        message: bytes,
        signature: bytes,
        key_version: int | None = None,
    ) -> bool:
        if not message:
            raise ValueError("message must not be empty")

        if not signature:
            raise ValueError("signature must not be empty")

        record = self._get_record(
            recipient_id,
            key_version,
        )

        return self.backend.verify(
            record.public_key,
            message,
            signature,
        )

    def revoke(
        self,
        *,
        recipient_id: str,
        reason: str,
        key_version: int | None = None,
    ) -> SigningKeyRecord:
        if not reason:
            raise ValueError("revocation reason must not be empty")

        record = self._get_record(
            recipient_id,
            key_version,
        )

        if record.revoked:
            return record

        revoked_at = datetime.now(timezone.utc).isoformat()

        updated = SigningKeyRecord(
            recipient_id=record.recipient_id,
            key_version=record.key_version,
            algorithm=record.algorithm,
            public_key=record.public_key,
            created_at=record.created_at,
            revoked=True,
            revocation_reason=reason,
            revoked_at=revoked_at,
        )

        key = (
            recipient_id,
            record.key_version,
        )

        self._records[key] = updated

        return updated

    def list_key_versions(
        self,
        recipient_id: str,
    ) -> list[SigningKeyRecord]:
        return sorted(
            (
                record
                for (rid, _), record in self._records.items()
                if rid == recipient_id
            ),
            key=lambda item: item.key_version,
        )

    def _get_record(
        self,
        recipient_id: str,
        key_version: int | None,
    ) -> SigningKeyRecord:
        if not recipient_id:
            raise ValueError("recipient_id must not be empty")

        if key_version is None:
            versions = self.list_key_versions(recipient_id)

            if not versions:
                raise KeyError(
                    f"No signing key found for recipient: {recipient_id}"
                )

            active = [
                record
                for record in versions
                if not record.revoked
            ]

            if not active:
                raise PermissionError(
                    f"No active signing key for recipient: {recipient_id}"
                )

            return active[-1]

        key = (recipient_id, key_version)

        record = self._records.get(key)

        if record is None:
            raise KeyError(
                f"Signing key not found: "
                f"{recipient_id} v{key_version}"
            )

        return record