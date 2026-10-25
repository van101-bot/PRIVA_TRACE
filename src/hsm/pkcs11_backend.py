from __future__ import annotations

from pathlib import Path

from src.hsm.backend import HSMBackend
from src.hsm.models import (
    HSMKeyMetadata,
    HSMKeyReference,
    KeyType,
)


class PKCS11Backend(HSMBackend):
    """
    PKCS#11 HSM integration boundary.

    This class intentionally does not assume a specific vendor,
    token library, slot ID, or mechanism.

    A real deployment should connect this layer to the vendor's
    PKCS#11 shared library using a PKCS#11 binding such as PyKCS11
    or an equivalent audited integration.
    """

    def __init__(
        self,
        library_path: str | Path,
        *,
        slot_id: int | None = None,
    ) -> None:
        self.library_path = str(library_path)
        self.slot_id = slot_id
        self._connected = False

    def connect(self) -> None:
        if not self.library_path:
            raise ValueError(
                "library_path must not be empty"
            )

        library = Path(self.library_path)

        if not library.exists():
            raise FileNotFoundError(
                f"PKCS#11 library not found: {library}"
            )

        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def _require_connection(self) -> None:
        if not self._connected:
            raise RuntimeError(
                "PKCS#11 backend is not connected"
            )

    def generate_keypair(
        self,
        *,
        key_id: str,
        key_type: KeyType,
        label: str,
    ) -> HSMKeyReference:
        self._require_connection()

        raise NotImplementedError(
            "Vendor-specific PKCS#11 key generation is "
            "not implemented yet"
        )

    def get_key_metadata(
        self,
        key_id: str,
    ) -> HSMKeyMetadata:
        self._require_connection()

        raise NotImplementedError(
            "Vendor-specific PKCS#11 metadata lookup "
            "is not implemented yet"
        )

    def sign(
        self,
        key_id: str,
        message: bytes,
    ) -> bytes:
        self._require_connection()

        raise NotImplementedError(
            "Vendor-specific PKCS#11 signing "
            "is not implemented yet"
        )

    def verify(
        self,
        key_id: str,
        message: bytes,
        signature: bytes,
    ) -> bool:
        self._require_connection()

        raise NotImplementedError(
            "Vendor-specific PKCS#11 verification "
            "is not implemented yet"
        )

    def delete_key(
        self,
        key_id: str,
    ) -> None:
        self._require_connection()

        raise NotImplementedError(
            "Vendor-specific PKCS#11 deletion "
            "is not implemented yet"
        )