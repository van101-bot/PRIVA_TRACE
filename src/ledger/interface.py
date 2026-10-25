from __future__ import annotations

from abc import ABC, abstractmethod

from src.ledger.models import LedgerProvenanceRecord


class ProvenanceLedger(ABC):

    @abstractmethod
    def record_event(
        self,
        record: LedgerProvenanceRecord,
    ) -> str:
        """
        Commit provenance record to immutable ledger.

        Returns:
            Ledger transaction ID.
        """
        raise NotImplementedError

    @abstractmethod
    def get_by_watermark(
        self,
        watermark_id: str,
    ) -> LedgerProvenanceRecord:
        raise NotImplementedError

    @abstractmethod
    def get_by_event_id(
        self,
        event_id: str,
    ) -> LedgerProvenanceRecord:
        raise NotImplementedError

    @abstractmethod
    def verify_record(
        self,
        record: LedgerProvenanceRecord,
    ) -> bool:
        raise NotImplementedError