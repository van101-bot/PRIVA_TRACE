from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.document import Base


class KeyRevocation(Base):
    """
    Records that a recipient's key was revoked.

    Privacy-first: only a SHA-256 hash of the recipient ID is stored,
    never the recipient ID itself.
    """

    __tablename__ = "key_revocations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)

    # SHA-256 hex digest of the recipient ID (64 characters).
    recipient_id_hash: Mapped[str] = mapped_column(
        String(64), index=True, nullable=False
    )

    reason: Mapped[str] = mapped_column(String(255), nullable=False)

    revoked_by: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False, index=True
    )

    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )