"""
SQLite database layer for the SIH26237 prototype keystore.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


class KeyDatabase:
    """SQLite database used for encrypted key metadata."""

    def __init__(self, database_path: str | Path) -> None:
        self.database_path = str(database_path)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS recipient_keys (
                recipient_id TEXT PRIMARY KEY,
                public_key BLOB NOT NULL,
                encrypted_private_key BLOB NOT NULL,
                created_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                revocation_reason TEXT
            )
            """
        )

        connection.commit()

        return connection