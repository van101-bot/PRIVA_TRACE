import pytest

from src.qkd.simulator import SimulatedQKDProvider


def test_simulated_qkd_provider():
    provider = SimulatedQKDProvider(
        num_qubits=4096,
        qber_threshold=0.11,
        eve_enabled=False,
    )

    session = provider.establish_key()

    assert isinstance(session.key, bytes)
    assert len(session.key) == 32
    assert session.sifted_key_length > 0
    assert 0.0 <= session.qber <= 0.11


def test_qkd_provider_returns_different_keys():
    provider = SimulatedQKDProvider(
        num_qubits=4096,
        qber_threshold=0.11,
        eve_enabled=False,
    )

    session_a = provider.establish_key()
    session_b = provider.establish_key()

    assert session_a.key != session_b.key


def test_eavesdropping_can_cause_rejection():
    provider = SimulatedQKDProvider(
        num_qubits=4096,
        qber_threshold=0.11,
        eve_enabled=True,
    )

    rejected = False

    for _ in range(5):
        try:
            provider.establish_key()
        except RuntimeError:
            rejected = True
            break

    assert rejected