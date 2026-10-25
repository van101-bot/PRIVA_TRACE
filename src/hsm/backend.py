from __future__ import annotations

from abc import ABC, abstractmethod

from src.hsm.models import (
    HSMKeyMetadata,
    HSMKeyReference,
    KeyType,
)


class HSMBackend(ABC):
    """
    Abstract interface for hardware-backed key management.

    Application code should depend on this interface rather than
    directly depending on a specific HSM vendor.
    """

    @abstractmethod
    def connect(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def disconnect(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def generate_keypair(
        self,
        *,
        key_id: str,
        key_type: KeyType,
        label: str,
    ) -> HSMKeyReference:
        raise NotImplementedError

    @abstractmethod
    def get_key_metadata(
        self,
        key_id: str,
    ) -> HSMKeyMetadata:
        raise NotImplementedError

    @abstractmethod
    def sign(
        self,
        key_id: str,
        message: bytes,
    ) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def verify(
        self,
        key_id: str,
        message: bytes,
        signature: bytes,
    ) -> bool:
        raise NotImplementedError

    @abstractmethod
    def delete_key(
        self,
        key_id: str,
    ) -> None:
        raise NotImplementedError