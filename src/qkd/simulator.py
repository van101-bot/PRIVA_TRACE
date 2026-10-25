from __future__ import annotations

from dataclasses import dataclass

from src.qkd.bb84 import BB84Simulator


@dataclass(frozen=True)
class QKDSession:
    key: bytes
    qber: float
    sifted_key_length: int


class QKDProvider:
    """
    Application-facing QKD abstraction.

    Phase 3 uses BB84Simulator.

    Later, this interface can be backed by:
      - laboratory QKD hardware
      - vendor SDK
      - optical QKD endpoint
      - authenticated QKD service
    """

    def establish_key(self) -> QKDSession:
        raise NotImplementedError


class SimulatedQKDProvider(QKDProvider):
    def __init__(
        self,
        num_qubits: int = 4096,
        qber_threshold: float = 0.11,
        eve_enabled: bool = False,
    ) -> None:
        self.simulator = BB84Simulator(
            num_qubits=num_qubits,
            qber_threshold=qber_threshold,
            eve_enabled=eve_enabled,
        )

    def establish_key(self) -> QKDSession:
        result = self.simulator.run()

        if not result.accepted:
            raise RuntimeError(
                f"QKD session rejected: {result.reason}"
            )

        key = self.simulator.derive_key(result)

        return QKDSession(
            key=key,
            qber=result.qber,
            sifted_key_length=result.sifted_key_length,
        )