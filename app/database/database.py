"""
Database configuration.

DATABASE_URL examples:
  PostgreSQL : postgresql+psycopg2://user:password@localhost:5432/sih26237
  SQLite     : sqlite:///./sih26237.db   (default if DATABASE_URL is not set)
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sih26237.db")

# Some hosts give "postgres://..." which SQLAlchemy 2.x rejects.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)

IS_SQLITE = DATABASE_URL.startswith("sqlite")

if IS_SQLITE:
    # SQLite needs this because FastAPI uses multiple threads.
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    # PostgreSQL: connection pooling.
    engine = create_engine(
        DATABASE_URL,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        pool_timeout=30,
        pool_recycle=1800,   # recycle connections every 30 minutes
        pool_pre_ping=True,  # drop dead connections before using them
    )

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
