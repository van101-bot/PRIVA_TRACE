from __future__ import annotations

import hashlib
import secrets

from src.qkd.models import QKDResult


class BB84Simulator:
    """
    Educational BB84-style QKD simulator.

    This is NOT a physical QKD implementation.
    It models:
      - random preparation
      - random measurement bases
      - basis sifting
      - optional intercept-resend interference
      - QBER estimation
      - simple key material extraction
    """

    BASIS_Z = 0
    BASIS_X = 1

    def __init__(
        self,
        num_qubits: int = 4096,
        qber_threshold: float = 0.11,
        eve_enabled: bool = False,
    ) -> None:
        if num_qubits < 128:
            raise ValueError("num_qubits must be at least 128")

        if not 0.0 <= qber_threshold <= 1.0:
            raise ValueError("qber_threshold must be between 0 and 1")

        self.num_qubits = num_qubits
        self.qber_threshold = qber_threshold
        self.eve_enabled = eve_enabled

    @staticmethod
    def _random_bit() -> int:
        return secrets.randbits(1)

    @staticmethod
    def _random_basis() -> int:
        return secrets.randbits(1)

    @staticmethod
    def _measure(bit: int, prepared_basis: int, measurement_basis: int) -> int:
        """
        Simulates measurement.

        If the measurement basis matches the preparation basis,
        the original bit is recovered.

        If the bases differ, the result is random.
        """
        if prepared_basis == measurement_basis:
            return bit

        return secrets.randbits(1)

    @staticmethod
    def _bits_to_bytes(bits: list[int]) -> bytes:
        if not bits:
            raise ValueError("Cannot convert empty bit list")

        padded = list(bits)

        while len(padded) % 8 != 0:
            padded.append(0)

        result = bytearray()

        for offset in range(0, len(padded), 8):
            value = 0

            for bit in padded[offset : offset + 8]:
                value = (value << 1) | bit

            result.append(value)

        return bytes(result)

    @classmethod
    def _derive_key_material(cls, bits: list[int]) -> bytes:
        """
        Compress sifted bits into 256-bit key material.

        This is a prototype simplification, not a complete
        production QKD privacy-amplification protocol.
        """
        raw_bytes = cls._bits_to_bytes(bits)

        return hashlib.sha256(
            b"SIH26237-QKD-BB84-PROTOTYPE-V1|" + raw_bytes
        ).digest()

    def run(self) -> QKDResult:
        alice_bits = [
            self._random_bit()
            for _ in range(self.num_qubits)
        ]

        alice_bases = [
            self._random_basis()
            for _ in range(self.num_qubits)
        ]

        bob_bases = [
            self._random_basis()
            for _ in range(self.num_qubits)
        ]

        bob_measurements: list[int] = []

        for index in range(self.num_qubits):
            transmitted_bit = alice_bits[index]
            transmitted_basis = alice_bases[index]

            if self.eve_enabled:
                eve_basis = self._random_basis()

                eve_measurement = self._measure(
                    transmitted_bit,
                    transmitted_basis,
                    eve_basis,
                )

                transmitted_bit = eve_measurement
                transmitted_basis = eve_basis

            bob_measurement = self._measure(
                transmitted_bit,
                transmitted_basis,
                bob_bases[index],
            )

            bob_measurements.append(bob_measurement)

        sifted_alice: list[int] = []
        sifted_bob: list[int] = []

        for index in range(self.num_qubits):
            if alice_bases[index] == bob_bases[index]:
                sifted_alice.append(alice_bits[index])
                sifted_bob.append(bob_measurements[index])

        if not sifted_alice:
            return QKDResult(
                raw_key_bits=alice_bits,
                sifted_key_bits=[],
                qber=1.0,
                accepted=False,
                reason="No sifted bits were produced",
            )

        mismatches = sum(
            alice_bit != bob_bit
            for alice_bit, bob_bit in zip(
                sifted_alice,
                sifted_bob,
            )
        )

        qber = mismatches / len(sifted_alice)

        accepted = qber <= self.qber_threshold

        if not accepted:
            return QKDResult(
                raw_key_bits=alice_bits,
                sifted_key_bits=sifted_alice,
                qber=qber,
                accepted=False,
                reason=(
                    f"QBER {qber:.4f} exceeds  threshold "
                    f"{self.qber_threshold:.4f}"
                ),
            )

        return QKDResult(
            raw_key_bits=alice_bits,
            sifted_key_bits=sifted_alice,
            qber=qber,
            accepted=True,
            reason="QKD session accepted",
        )

    def derive_key(self, result: QKDResult) -> bytes:
        if not result.accepted:
            raise ValueError(
                f"Cannot derive QKD key from rejected session: "
                f"{result.reason}"
            )

        if len(result.sifted_key_bits) < 128:
            raise ValueError(
                "Insufficient sifted key material"
            )

        return self._derive_key_material(
            result.sifted_key_bits
        )