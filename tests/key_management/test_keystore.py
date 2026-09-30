from src.key_management.keystore import EncryptedKeyStore


def test_encrypt_decrypt():
    key = EncryptedKeyStore.generate_key()

    store = EncryptedKeyStore(key)

    plaintext = b"private key material"

    encrypted = store.encrypt(plaintext)

    assert encrypted != plaintext

    recovered = store.decrypt(encrypted)

    assert recovered == plaintext


def test_encryption_is_randomized():
    key = EncryptedKeyStore.generate_key()

    store = EncryptedKeyStore(key)

    plaintext = b"same private key"

    encrypted_a = store.encrypt(plaintext)
    encrypted_b = store.encrypt(plaintext)

    assert encrypted_a != encrypted_b


def test_wrong_key_fails():
    key_a = EncryptedKeyStore.generate_key()
    key_b = EncryptedKeyStore.generate_key()

    store_a = EncryptedKeyStore(key_a)
    store_b = EncryptedKeyStore(key_b)

    encrypted = store_a.encrypt(b"secret")

    import pytest

    with pytest.raises(Exception):
        store_b.decrypt(encrypted)