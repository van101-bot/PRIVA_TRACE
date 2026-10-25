from __future__ import annotations

from typing import Protocol

from src.fabric.models import (
    FabricDecryptionRecord,
    FabricQueryResult,
    FabricTransactionResult,
)


class FabricProvenanceStore(Protocol):
    """
    Application boundary for Hyperledger Fabric.

    The rest of the application must not know about Fabric SDK details.
    """

    def record_decryption(
        self,
        record: FabricDecryptionRecord,
    ) -> FabricTransactionResult:
        ...

    def query_by_watermark(
        self,
        watermark_id: str,
    ) -> FabricQueryResult:
        ...

    def record_key_revocation(
        self,
        *,
        recipient_id: str,
        key_id: str,
        reason: str,
        timestamp: str,
    ) -> FabricTransactionResult:
        ...