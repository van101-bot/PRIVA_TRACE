from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.document import Base


class DecryptionRecord(Base):
    """
    One row per decryption event.

    Privacy-first: stores the watermark_id and the ZKP proof only.
    The recipient's real identity is never stored in this table.
    """

    __tablename__ = "decryption_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # Public identifier embedded in the watermarked file.
    watermark_id: Mapped[str] = mapped_column(
        String(128), unique=True, index=True, nullable=False
    )

    # Serialized zero-knowledge proof (JSON/base64 text).
    zkp_proof: Mapped[str] = mapped_column(Text, nullable=False)

    document_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    # Links the record to the encrypted document (used for ownership checks later).
    encrypted_file_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    # The API user who triggered the decryption.
    created_by: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True, index=True
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
        # ML-DSA-65 signature (base64) over the canonical record, made at insert time.
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)