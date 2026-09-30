import pytest

from src.pqc.kem import MLKEM


def test_mlkem_round_trip():
    kem = MLKEM("ML-KEM-768")

    keypair = kem.generate_keypair()

    result = kem.encapsulate(keypair.public_key)

    recovered_secret = kem.decapsulate(
        result.ciphertext,
        keypair.private_key,
    )

    assert result.shared_secret == recovered_secret


def test_mlkem_public_key_is_not_empty():
    kem = MLKEM("ML-KEM-768")

    keypair = kem.generate_keypair()

    assert len(keypair.public_key) > 0


def test_mlkem_private_key_is_not_empty():
    kem = MLKEM("ML-KEM-768")

    keypair = kem.generate_keypair()

    assert len(keypair.private_key) > 0


def test_empty_public_key_rejected():
    kem = MLKEM("ML-KEM-768")

    with pytest.raises(ValueError):
        kem.encapsulate(b"")


def test_empty_ciphertext_rejected():
    kem = MLKEM("ML-KEM-768")

    keypair = kem.generate_keypair()

    with pytest.raises(ValueError):
        kem.decapsulate(b"", keypair.private_key)


def test_wrong_private_key_does_not_recover_original_secret():
    kem = MLKEM("ML-KEM-768")

    recipient = kem.generate_keypair()
    attacker = kem.generate_keypair()

    result = kem.encapsulate(recipient.public_key)

    attacker_secret = kem.decapsulate(
        result.ciphertext,
        attacker.private_key,
    )

    assert attacker_secret != result.shared_secret