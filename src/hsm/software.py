from __future__ import annotations

from dataclasses import dataclass

from src.hsm.backend import HSMBackend
from src.hsm.models import (
    HSMKeyMetadata,
    HSMKeyReference,
    KeyType,
)
from src.pqc.signature import MLDSA


@dataclass
class _StoredSigningKey:
    reference: HSMKeyReference
    private_key: bytes
    public_key: bytes


class SoftwareHSMBackend(HSMBackend):
    """
    Development-only HSM simulator.

    This backend intentionally keeps keys in process memory.

    It must NOT be described as an actual HSM.
    """

    def __init__(self) -> None:
        self._connected = False
        self._keys: dict[str, _StoredSigningKey] = {}
        self._signatures = MLDSA("ML-DSA-65")

    def connect(self) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def _require_connection(self) -> None:
        if not self._connected:
            raise RuntimeError("HSM backend is not connected")

    def generate_keypair(
        self,
        *,
        key_id: str,
        key_type: KeyType,
        label: str,
    ) -> HSMKeyReference:
        self._require_connection()

        if not key_id:
            raise ValueError("key_id must not be empty")

        if not label:
            raise ValueError("label must not be empty")

        if key_id in self._keys:
            raise ValueError(
                f"Key already exists: {key_id}"
            )

        if key_type != KeyType.ML_DSA:
            raise NotImplementedError(
                "Software HSM currently supports ML-DSA signing keys only"
            )

        keypair = self._signatures.generate_keypair()

        reference = HSMKeyReference(
            key_id=key_id,
            key_type=key_type,
            label=label,
        )

        self._keys[key_id] = _StoredSigningKey(
            reference=reference,
            private_key=keypair.private_key,
            public_key=keypair.public_key,
        )

        return reference

    def get_key_metadata(
        self,
        key_id: str,
    ) -> HSMKeyMetadata:
        self._require_connection()

        stored = self._get_key(key_id)

        return HSMKeyMetadata(
            key_id=stored.reference.key_id,
            key_type=stored.reference.key_type,
            label=stored.reference.label,
            extractable=False,
        )

    def sign(
        self,
        key_id: str,
        message: bytes,
    ) -> bytes:
        self._require_connection()

        if not message:
            raise ValueError("message must not be empty")

        stored = self._get_key(key_id)

        return self._signatures.sign(
            message,
            stored.private_key,
        )

    def verify(
        self,
        key_id: str,
        message: bytes,
        signature: bytes,
    ) -> bool:
        self._require_connection()

        if not message:
            return False

        if not signature:
            return False

        stored = self._get_key(key_id)

        return self._signatures.verify(
            message,
            signature,
            stored.public_key,
        )

    def delete_key(
        self,
        key_id: str,
    ) -> None:
        self._require_connection()

        if key_id not in self._keys:
            raise KeyError(
                f"Key not found: {key_id}"
            )

        del self._keys[key_id]

    def _get_key(
        self,
        key_id: str,
    ) -> _StoredSigningKey:
        if key_id not in self._keys:
            raise KeyError(
                f"Key not found: {key_id}"
            )

        return self._keys[key_id]