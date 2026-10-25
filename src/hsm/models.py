from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class KeyType(str, Enum):
    ML_DSA = "ML-DSA"
    ML_KEM = "ML-KEM"
    AES = "AES"


@dataclass(frozen=True)
class HSMKeyReference:
    key_id: str
    key_type: KeyType
    label: str


@dataclass(frozen=True)
class HSMKeyMetadata:
    key_id: str
    key_type: KeyType
    label: str
    extractable: bool