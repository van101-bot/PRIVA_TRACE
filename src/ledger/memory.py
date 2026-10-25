from __future__ import annotations

from src.ledger.interface import ProvenanceLedger
from src.ledger.models import LedgerProvenanceRecord


class InMemoryProvenanceLedger(
    ProvenanceLedger
):

    def __init__(self) -> None:
        self._records_by_watermark: dict[
            str,
            LedgerProvenanceRecord,
        ] = {}

        self._records_by_event: dict[
            str,
            LedgerProvenanceRecord,
        ] = {}

    def record_event(
        self,
        record: LedgerProvenanceRecord,
    ) -> str:

        if record.watermark_id in (
            self._records_by_watermark
        ):
            raise ValueError(
                "Watermark already exists in ledger"
            )

        if record.event_id in (
            self._records_by_event
        ):
            raise ValueError(
                "Event already exists in ledger"
            )

        self._records_by_watermark[
            record.watermark_id
        ] = record

        self._records_by_event[
            record.event_id
        ] = record

        return record.transaction_id

    def get_by_watermark(
        self,
        watermark_id: str,
    ) -> LedgerProvenanceRecord:

        try:
            return self._records_by_watermark[
                watermark_id
            ]
        except KeyError:
            raise KeyError(
                f"Watermark not found: {watermark_id}"
            )

    def get_by_event_id(
        self,
        event_id: str,
    ) -> LedgerProvenanceRecord:

        try:
            return self._records_by_event[
                event_id
            ]
        except KeyError:
            raise KeyError(
                f"Event not found: {event_id}"
            )

    def verify_record(
        self,
        record: LedgerProvenanceRecord,
    ) -> bool:

        stored = self.get_by_event_id(
            record.event_id
        )

        return stored == record