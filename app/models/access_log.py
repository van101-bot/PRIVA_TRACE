from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.document import Base


class AccessLog(Base):
    """One row per API request. Never stores bodies, keys, tokens or recipient IDs."""

    __tablename__ = "access_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    request_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)

    # Taken from the JWT; no foreign key so logs survive user deletion.
    user_id: Mapped[int | None] = mapped_column(Integer, index=True, nullable=True)

    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[str | None] = mapped_column(String(128), nullable=True)

    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(String(10), index=True, nullable=False)

    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        default=lambda: datetime.now(timezone.utc),
    )