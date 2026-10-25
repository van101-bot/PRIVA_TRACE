from sqlalchemy import ForeignKey, Integer
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        default="uploaded",
        nullable=False,
    )

    sha256: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    encrypted_path: Mapped[str | None] = mapped_column(
        String(500),
        nullable=True,
    )

    nonce: Mapped[str | None] = mapped_column(
        String(24),
        nullable=True,
    )

    wrapped_key: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    key_nonce: Mapped[str | None] = mapped_column(
        String(24),
        nullable=True,
    )
    owner_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )