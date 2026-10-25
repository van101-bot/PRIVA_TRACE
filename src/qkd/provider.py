from abc import ABC, abstractmethod
from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class QKDSession:
    session_id: str
    shared_secret: bytes
    qber: float
    accepted: bool
    provider: str


class QKDProvider(ABC):
    """
    Abstract interface between the cryptographic system
    and a QKD implementation.

    The rest of the application must not care whether the
    secret came from a simulator or physical QKD hardware.
    """

    @abstractmethod
    def establish_session(self, session_id: str) -> QKDSession:
        raise NotImplementedError


class SimulatedQKDProvider(QKDProvider):
    """
    Adapter around the existing BB84 simulator.

    This class is deliberately an adapter. Your existing
    BB84 implementation remains the source of simulation.
    """

    def __init__(self, simulator):
        self.simulator = simulator

    def establish_session(self, session_id: str) -> QKDSession:
        result = self.simulator.run()

        accepted = getattr(result, "accepted", False)
        qber = getattr(result, "qber", 1.0)
        shared_secret = getattr(result, "shared_secret", None)

        if not accepted:
            raise RuntimeError(
                f"QKD session rejected: qber={qber}"
            )

        if not isinstance(shared_secret, bytes):
            raise RuntimeError(
                "QKD simulator did not return a byte shared secret"
            )

        return QKDSession(
            session_id=session_id,
            shared_secret=shared_secret,
            qber=qber,
            accepted=True,
            provider="BB84-SIMULATOR",
        )