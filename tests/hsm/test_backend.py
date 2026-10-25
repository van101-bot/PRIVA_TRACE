import pytest

from src.hsm.models import KeyType
from src.hsm.software import SoftwareHSMBackend


def test_backend_requires_connection():
    backend = SoftwareHSMBackend()

    with pytest.raises(RuntimeError):
        backend.generate_keypair(
            key_id="test-key",
            key_type=KeyType.ML_DSA,
            label="test",
        )


def test_backend_connect_disconnect():
    backend = SoftwareHSMBackend()

    backend.connect()

    backend.disconnect()

    with pytest.raises(RuntimeError):
        backend.get_key_metadata("missing")


def test_unsupported_key_type_rejected():
    backend = SoftwareHSMBackend()
    backend.connect()

    with pytest.raises(NotImplementedError):
        backend.generate_keypair(
            key_id="aes-key",
            key_type=KeyType.AES,
            label="AES test",
        )