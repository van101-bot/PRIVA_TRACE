import pytest

from src.hsm.models import KeyType
from src.hsm.software import SoftwareHSMBackend


def test_software_hsm_generates_ml_dsa_key():
    backend = SoftwareHSMBackend()
    backend.connect()

    reference = backend.generate_keypair(
        key_id="provenance-signer",
        key_type=KeyType.ML_DSA,
        label="SIH26237 Provenance Signer",
    )

    assert reference.key_id == "provenance-signer"
    assert reference.key_type == KeyType.ML_DSA


def test_software_hsm_metadata():
    backend = SoftwareHSMBackend()
    backend.connect()

    backend.generate_keypair(
        key_id="provenance-signer",
        key_type=KeyType.ML_DSA,
        label="SIH26237 Provenance Signer",
    )

    metadata = backend.get_key_metadata(
        "provenance-signer"
    )

    assert metadata.key_id == "provenance-signer"
    assert metadata.key_type == KeyType.ML_DSA
    assert metadata.extractable is False


def test_software_hsm_sign_verify():
    backend = SoftwareHSMBackend()
    backend.connect()

    backend.generate_keypair(
        key_id="provenance-signer",
        key_type=KeyType.ML_DSA,
        label="SIH26237 Provenance Signer",
    )

    message = b"SIH26237 provenance record"

    signature = backend.sign(
        "provenance-signer",
        message,
    )

    assert signature

    assert backend.verify(
        "provenance-signer",
        message,
        signature,
    )


def test_modified_message_fails():
    backend = SoftwareHSMBackend()
    backend.connect()

    backend.generate_keypair(
        key_id="provenance-signer",
        key_type=KeyType.ML_DSA,
        label="SIH26237 Provenance Signer",
    )

    signature = backend.sign(
        "provenance-signer",
        b"original",
    )

    assert not backend.verify(
        "provenance-signer",
        b"modified",
        signature,
    )


def test_missing_key_fails():
    backend = SoftwareHSMBackend()
    backend.connect()

    with pytest.raises(KeyError):
        backend.sign(
            "missing",
            b"message",
        )


def test_duplicate_key_fails():
    backend = SoftwareHSMBackend()
    backend.connect()

    backend.generate_keypair(
        key_id="duplicate",
        key_type=KeyType.ML_DSA,
        label="Test",
    )

    with pytest.raises(ValueError):
        backend.generate_keypair(
            key_id="duplicate",
            key_type=KeyType.ML_DSA,
            label="Test",
        )


def test_delete_key():
    backend = SoftwareHSMBackend()
    backend.connect()

    backend.generate_keypair(
        key_id="delete-me",
        key_type=KeyType.ML_DSA,
        label="Delete Test",
    )

    backend.delete_key("delete-me")

    with pytest.raises(KeyError):
        backend.get_key_metadata("delete-me")