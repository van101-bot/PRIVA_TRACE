import pytest

from src.distribution.service import (
    MultiRecipientEncryptionService,
)
from src.pqc.kem import MLKEM
from src.qkd.simulator import SimulatedQKDProvider


def create_recipient(service, recipient_id):
    kem = MLKEM("ML-KEM-768")

    keypair = kem.generate_keypair()

    qkd = SimulatedQKDProvider(
        num_qubits=4096,
        qber_threshold=0.11,
        eve_enabled=False,
    )

    context = service.create_recipient_context(
        recipient_id=recipient_id,
        public_key=keypair.public_key,
        qkd_provider=qkd,
    )

    return keypair, context


def test_one_document_can_be_decrypted_by_multiple_recipients():
    service = MultiRecipientEncryptionService()

    alice_keys, alice = create_recipient(
        service,
        "alice",
    )

    bob_keys, bob = create_recipient(
        service,
        "bob",
    )

    carol_keys, carol = create_recipient(
        service,
        "carol",
    )

    document = (
        b"SIH26237 confidential multi-recipient document"
    )

    envelope = service.encrypt_for_recipients(
        document=document,
        document_id="document-001",
        recipients=[
            alice,
            bob,
            carol,
        ],
    )

    alice_document = service.decrypt_for_recipient(
        envelope=envelope,
        recipient_id="alice",
        recipient_private_key=alice_keys.private_key,
        qkd_secret=alice.qkd_secret,
    )

    bob_document = service.decrypt_for_recipient(
        envelope=envelope,
        recipient_id="bob",
        recipient_private_key=bob_keys.private_key,
        qkd_secret=bob.qkd_secret,
    )

    carol_document = service.decrypt_for_recipient(
        envelope=envelope,
        recipient_id="carol",
        recipient_private_key=carol_keys.private_key,
        qkd_secret=carol.qkd_secret,
    )

    assert alice_document == document
    assert bob_document == document
    assert carol_document == document


def test_document_is_encrypted_only_once():
    service = MultiRecipientEncryptionService()

    alice_keys, alice = create_recipient(
        service,
        "alice",
    )

    bob_keys, bob = create_recipient(
        service,
        "bob",
    )

    document = b"same plaintext for all recipients"

    envelope = service.encrypt_for_recipients(
        document=document,
        document_id="document-001",
        recipients=[alice, bob],
    )

    assert len(envelope.recipients) == 2

    assert (
        envelope.encrypted_document
        != document
    )

    # The encrypted document exists as one shared ciphertext.
    assert isinstance(
        envelope.encrypted_document,
        bytes,
    )


def test_unauthorized_recipient_is_rejected():
    service = MultiRecipientEncryptionService()

    alice_keys, alice = create_recipient(
        service,
        "alice",
    )

    document = b"secret"

    envelope = service.encrypt_for_recipients(
        document=document,
        document_id="document-001",
        recipients=[alice],
    )

    attacker_keys, _ = create_recipient(
        service,
        "attacker",
    )

    with pytest.raises(PermissionError):
        service.decrypt_for_recipient(
            envelope=envelope,
            recipient_id="attacker",
            recipient_private_key=attacker_keys.private_key,
            qkd_secret=b"attacker-qkd-secret",
        )


def test_wrong_qkd_secret_fails():
    service = MultiRecipientEncryptionService()

    alice_keys, alice = create_recipient(
        service,
        "alice",
    )

    document = b"secret document"

    envelope = service.encrypt_for_recipients(
        document=document,
        document_id="document-001",
        recipients=[alice],
    )

    with pytest.raises(Exception):
        service.decrypt_for_recipient(
            envelope=envelope,
            recipient_id="alice",
            recipient_private_key=alice_keys.private_key,
            qkd_secret=b"wrong-qkd-secret",
        )


def test_wrong_private_key_fails():
    service = MultiRecipientEncryptionService()

    alice_keys, alice = create_recipient(
        service,
        "alice",
    )

    attacker_keys, _ = create_recipient(
        service,
        "attacker",
    )

    document = b"secret document"

    envelope = service.encrypt_for_recipients(
        document=document,
        document_id="document-001",
        recipients=[alice],
    )

    with pytest.raises(Exception):
        service.decrypt_for_recipient(
            envelope=envelope,
            recipient_id="alice",
            recipient_private_key=attacker_keys.private_key,
            qkd_secret=alice.qkd_secret,
        )