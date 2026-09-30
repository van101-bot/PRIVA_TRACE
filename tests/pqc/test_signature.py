from src.pqc.signature import MLDSA


def test_signature_round_trip():
    dsa = MLDSA("ML-DSA-65")

    keypair = dsa.generate_keypair()

    message = b"SIH26237 test message"

    signature = dsa.sign(
        message,
        keypair.private_key,
    )

    assert dsa.verify(
        message,
        signature,
        keypair.public_key,
    )


def test_modified_message_fails():
    dsa = MLDSA("ML-DSA-65")

    keypair = dsa.generate_keypair()

    message = b"original message"

    signature = dsa.sign(
        message,
        keypair.private_key,
    )

    assert not dsa.verify(
        b"modified message",
        signature,
        keypair.public_key,
    )


def test_wrong_public_key_fails():
    dsa = MLDSA("ML-DSA-65")

    signer = dsa.generate_keypair()
    attacker = dsa.generate_keypair()

    message = b"test"

    signature = dsa.sign(
        message,
        signer.private_key,
    )

    assert not dsa.verify(
        message,
        signature,
        attacker.public_key,
    )