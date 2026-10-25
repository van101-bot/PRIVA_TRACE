import pytest

from src.qkd.bb84 import BB84Simulator


def test_bb84_generates_accepted_session():
    simulator = BB84Simulator(
        num_qubits=4096,
        qber_threshold=0.11,
        eve_enabled=False,
    )

    result = simulator.run()

    assert result.accepted
    assert result.sifted_key_length > 0
    assert 0.0 <= result.qber <= 1.0


def test_bb84_no_eve_has_low_qber():
    simulator = BB84Simulator(
        num_qubits=4096,
        qber_threshold=0.11,
        eve_enabled=False,
    )

    result = simulator.run()

    assert result.qber <= 0.11


def test_bb84_produces_key_material():
    simulator = BB84Simulator(
        num_qubits=4096,
        qber_threshold=0.11,
        eve_enabled=False,
    )

    result = simulator.run()

    key = simulator.derive_key(result)

    assert isinstance(key, bytes)
    assert len(key) == 32


def test_rejected_session_cannot_derive_key():
    simulator = BB84Simulator(
        num_qubits=4096,
        qber_threshold=0.0,
        eve_enabled=True,
    )

    result = simulator.run()

    if result.accepted:
        pytest.skip(
            "Randomized run did not exceed zero QBER threshold"
        )

    with pytest.raises(ValueError):
        simulator.derive_key(result)


def test_invalid_qubit_count_rejected():
    with pytest.raises(ValueError):
        BB84Simulator(num_qubits=64)


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError):
        BB84Simulator(qber_threshold=1.5)