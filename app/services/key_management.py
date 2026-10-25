import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_DIR = Path("storage/keys")
KEY_FILE = KEY_DIR / "master.key"


def load_master_key() -> bytes:
    """Load the existing development master key or create it once."""

    KEY_DIR.mkdir(parents=True, exist_ok=True)

    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes()

        if len(key) != 32:
            raise ValueError("Invalid master key file")

        return key

    key = AESGCM.generate_key(bit_length=256)

    # Exclusive creation avoids silently overwriting an existing key.
    with KEY_FILE.open("xb") as file:
        file.write(key)

    return key


def wrap_document_key(document_key: bytes) -> dict:
    """Encrypt a document's AES key using the development master key."""

    if len(document_key) != 32:
        raise ValueError("Document key must be 32 bytes")

    master_key = load_master_key()
    nonce = os.urandom(12)

    aesgcm = AESGCM(master_key)
    wrapped_key = aesgcm.encrypt(nonce, document_key, None)

    return {
        "wrapped_key": wrapped_key.hex(),
        "key_nonce": nonce.hex(),
    }


def unwrap_document_key(
    wrapped_key: str,
    key_nonce: str,
) -> bytes:
    """Recover and authenticate a wrapped document key."""

    master_key = load_master_key()

    try:
        nonce = bytes.fromhex(key_nonce)
        encrypted_key = bytes.fromhex(wrapped_key)
    except (ValueError, TypeError) as exc:
        raise ValueError("Invalid wrapped-key metadata") from exc

    if len(nonce) != 12:
        raise ValueError("Invalid key nonce")

    aesgcm = AESGCM(master_key)

    try:
        document_key = aesgcm.decrypt(nonce, encrypted_key, None)
    except InvalidTag:
        raise

    if len(document_key) != 32:
        raise ValueError("Invalid unwrapped document key")

    return document_key