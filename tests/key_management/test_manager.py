from pathlib import Path

import pytest

from src.key_management.keystore import EncryptedKeyStore
from src.key_management.manager import KeyManager


def create_manager(tmp_path: Path) -> KeyManager:
    database = tmp_path / "test.sqlite3"

    master_key = EncryptedKeyStore.generate_key()

    return KeyManager(
        database,
        master_key,
    )


def test_store_and_retrieve_keypair(tmp_path):
    manager = create_manager(tmp_path)

    keypair = manager.kem.generate_keypair()

    manager.store_keypair(
        "recipient-001",
        keypair.public_key,
        keypair.private_key,
    )

    public_key = manager.get_public_key(
        "recipient-001"
    )

    private_key = manager.get_private_key(
        "recipient-001"
    )

    assert public_key == keypair.public_key
    assert private_key == keypair.private_key


def test_generate_multiple_recipients(tmp_path):
    manager = create_manager(tmp_path)

    recipients = [
        "recipient-001",
        "recipient-002",
        "recipient-003",
        "recipient-004",
        "recipient-005",
    ]

    public_keys = manager.generate_keys_for_recipients(
        recipients
    )

    assert set(public_keys.keys()) == set(
        recipients
    )

    for recipient in recipients:
        assert len(
            manager.get_public_key(recipient)
        ) > 0


def test_missing_recipient(tmp_path):
    manager = create_manager(tmp_path)

    with pytest.raises(KeyError):
        manager.get_private_key(
            "does-not-exist"
        )


def test_revocation(tmp_path):
    manager = create_manager(tmp_path)

    keypair = manager.kem.generate_keypair()

    manager.store_keypair(
        "recipient-001",
        keypair.public_key,
        keypair.private_key,
    )

    assert manager.revoke_key(
        "recipient-001",
        "Security incident",
    )

    with pytest.raises(PermissionError):
        manager.get_private_key(
            "recipient-001"
        )