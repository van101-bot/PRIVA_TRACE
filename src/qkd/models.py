from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class QKDResult:
    raw_key_bits: list[int]
    sifted_key_bits: list[int]
    qber: float
    accepted: bool
    reason: str

    @property
    def sifted_key_length(self) -> int:
        return len(self.sifted_key_bits)