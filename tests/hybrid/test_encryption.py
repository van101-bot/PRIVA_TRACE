import pytest

from src.hybrid.encryption import (
    EncryptedDocument,
    HybridDocumentEncryption,
)


def test_encrypt_decrypt():
    key = b"A" * 32
    plaintext = b"SIH26237 confidential document"

    encrypted = HybridDocumentEncryption.encrypt(
        plaintext,
        key,
    )

    recovered = HybridDocumentEncryption.decrypt(
        encrypted,
        key,
    )

    assert recovered == plaintext


def test_encryption_produces_different_nonce():
    key = b"A" * 32
    plaintext = b"same plaintext"

    encrypted_a = HybridDocumentEncryption.encrypt(
        plaintext,
        key,
    )

    encrypted_b = HybridDocumentEncryption.encrypt(
        plaintext,
        key,
    )

    assert encrypted_a.nonce != encrypted_b.nonce
    assert encrypted_a.ciphertext != encrypted_b.ciphertext


def test_wrong_key_fails():
    key_a = b"A" * 32
    key_b = b"B" * 32

    plaintext = b"secret"

    encrypted = HybridDocumentEncryption.encrypt(
        plaintext,
        key_a,
    )

    with pytest.raises(Exception):
        HybridDocumentEncryption.decrypt(
            encrypted,
            key_b,
        )


def test_modified_ciphertext_fails():
    key = b"A" * 32

    encrypted = HybridDocumentEncryption.encrypt(
        b"important document",
        key,
    )

    modified = bytearray(encrypted.ciphertext)
    modified[0] ^= 1

    tampered = EncryptedDocument(
        nonce=encrypted.nonce,
        ciphertext=bytes(modified),
    )

    with pytest.raises(Exception):
        HybridDocumentEncryption.decrypt(
            tampered,
            key,
        )


def test_wrong_associated_data_fails():
    key = b"A" * 32

    encrypted = HybridDocumentEncryption.encrypt(
        b"document",
        key,
        associated_data=b"document-id-001",
    )

    with pytest.raises(Exception):
        HybridDocumentEncryption.decrypt(
            encrypted,
            key,
            associated_data=b"document-id-002",
        )