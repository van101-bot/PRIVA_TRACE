"""
High-level key management for SIH26237.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.key_management.database import KeyDatabase
from src.key_management.keystore import EncryptedKeyStore
from src.pqc.kem import MLKEM


class KeyManager:
    """
    Manage recipient ML-KEM keys.

    Current implementation:
        software encrypted keystore

    Future implementation:
        HSM-backed private-key storage
    """

    def __init__(
        self,
        database_path: str | Path,
        encryption_key: bytes,
    ) -> None:
        self.database = KeyDatabase(database_path)

        self.keystore = EncryptedKeyStore(
            encryption_key
        )

        self.kem = MLKEM("ML-KEM-768")

    def store_keypair(
        self,
        recipient_id: str,
        public_key: bytes,
        private_key: bytes,
    ) -> None:
        """Encrypt and store a recipient key pair."""

        if not recipient_id:
            raise ValueError(
                "recipient_id must not be empty"
            )

        encrypted_private_key = self.keystore.encrypt(
            private_key
        )

        created_at = datetime.now(
            timezone.utc
        ).isoformat()

        connection = self.database.connect()

        try:
            connection.execute(
                """
                INSERT OR REPLACE INTO recipient_keys (
                    recipient_id,
                    public_key,
                    encrypted_private_key,
                    created_at,
                    revoked,
                    revocation_reason
                )
                VALUES (?, ?, ?, ?, 0, NULL)
                """,
                (
                    recipient_id,
                    public_key,
                    encrypted_private_key,
                    created_at,
                ),
            )

            connection.commit()

        finally:
            connection.close()

    def get_public_key(
        self,
        recipient_id: str,
    ) -> bytes:
        """Retrieve a recipient public key."""

        connection = self.database.connect()

        try:
            row = connection.execute(
                """
                SELECT public_key, revoked
                FROM recipient_keys
                WHERE recipient_id = ?
                """,
                (recipient_id,),
            ).fetchone()

        finally:
            connection.close()

        if row is None:
            raise KeyError(
                f"Recipient not found: {recipient_id}"
            )

        public_key, revoked = row

        if revoked:
            raise PermissionError(
                f"Recipient key is revoked: {recipient_id}"
            )

        return bytes(public_key)

    def get_private_key(
        self,
        recipient_id: str,
    ) -> bytes:
        """Decrypt and return a recipient private key."""

        connection = self.database.connect()

        try:
            row = connection.execute(
                """
                SELECT encrypted_private_key, revoked
                FROM recipient_keys
                WHERE recipient_id = ?
                """,
                (recipient_id,),
            ).fetchone()

        finally:
            connection.close()

        if row is None:
            raise KeyError(
                f"Recipient not found: {recipient_id}"
            )

        encrypted_private_key, revoked = row

        if revoked:
            raise PermissionError(
                f"Recipient key is revoked: {recipient_id}"
            )

        return self.keystore.decrypt(
            bytes(encrypted_private_key)
        )

    def generate_keys_for_recipients(
        self,
        recipient_ids: list[str],
    ) -> dict[str, bytes]:
        """
        Generate and store ML-KEM keys for multiple recipients.

        Returns public keys only.
        """

        public_keys: dict[str, bytes] = {}

        for recipient_id in recipient_ids:

            keypair = self.kem.generate_keypair()

            self.store_keypair(
                recipient_id,
                keypair.public_key,
                keypair.private_key,
            )

            public_keys[
                recipient_id
            ] = keypair.public_key

        return public_keys

    def revoke_key(
        self,
        recipient_id: str,
        reason: str,
    ) -> bool:
        """Revoke a recipient key."""

        if not reason:
            raise ValueError(
                "Revocation reason must not be empty"
            )

        connection = self.database.connect()

        try:
            cursor = connection.execute(
                """
                UPDATE recipient_keys
                SET revoked = 1,
                    revocation_reason = ?
                WHERE recipient_id = ?
                """,
                (
                    reason,
                    recipient_id,
                ),
            )

            connection.commit()

            return cursor.rowcount == 1

        finally:
            connection.close()