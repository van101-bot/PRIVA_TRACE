from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    RETIRED = "RETIRED"


@dataclass(frozen=True)
class RecipientIdentity:
    recipient_id: str
    display_name: str

    kem_key_id: str
    kem_key_version: int

    signing_key_id: str
    signing_key_version: int

    status: KeyStatus = KeyStatus.ACTIVE

    created_at: str = ""

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def validate_for_decryption(self):
        if self.status != KeyStatus.ACTIVE:
            raise ValueError(
                f"Recipient {self.recipient_id} is not active"
            )

    def as_public_reference(self) -> dict:
        """
        Safe reference for provenance/ledger.

        No private keys.
        """
        return {
            "recipient_id": self.recipient_id,
            "kem_key_id": self.kem_key_id,
            "kem_key_version": self.kem_key_version,
            "signing_key_id": self.signing_key_id,
            "signing_key_version": self.signing_key_version,
            "status": self.status.value,
        }