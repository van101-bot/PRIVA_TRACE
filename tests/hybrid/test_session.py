from src.pqc.kem import MLKEM
from src.qkd.simulator import SimulatedQKDProvider
from src.hybrid.session import HybridKeyExchange


def test_hybrid_session_establishment():
    qkd = SimulatedQKDProvider(
        num_qubits=4096,
        qber_threshold=0.11,
        eve_enabled=False,
    )

    kem = MLKEM("ML-KEM-768")
    recipient = kem.generate_keypair()

    exchange = HybridKeyExchange(qkd)

    session = exchange.establish(
        recipient.public_key
    )

    assert session.qkd_session.key
    assert session.mlkem_ciphertext
    assert len(session.hybrid_key) == 32


def test_sender_and_recipient_derive_same_hybrid_key():
    qkd_sender = SimulatedQKDProvider(
        num_qubits=4096,
        qber_threshold=0.11,
        eve_enabled=False,
    )

    qkd_recipient = None

    kem = MLKEM("ML-KEM-768")
    recipient = kem.generate_keypair()

    exchange = HybridKeyExchange(qkd_sender)

    session = exchange.establish(
        recipient.public_key
    )

    # The simulator models the shared QKD result.
    # The recipient uses the same established QKD key.
    recovered_key = exchange.recover_recipient_key(
        qkd_secret=session.qkd_session.key,
        mlkem_ciphertext=session.mlkem_ciphertext,
        recipient_private_key=recipient.private_key,
    )

    assert recovered_key == session.hybrid_key