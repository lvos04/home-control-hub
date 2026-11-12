"""Database: SQLAlchemy 2 (sync, psycopg 3) op PostgreSQL 16."""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime

from sqlalchemy import DateTime, Engine, MetaData, create_engine, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id() -> uuid.UUID:
    return uuid.uuid4()


class Timestamps:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class Database:
    def __init__(self, url: str) -> None:
        self.url = url
        # hide_parameters: een databasefout zet de parameterwaarden (mogelijk een geheim of token) niet in de
        # foutmelding en dus niet in de app-log (V-094).
        self.engine: Engine = create_engine(
            url, pool_pre_ping=True, pool_size=5, max_overflow=5, future=True, hide_parameters=True
        )
        self.sessions = sessionmaker(self.engine, expire_on_commit=False, autoflush=False)

    def session(self) -> Iterator[Session]:
        with self.sessions() as s:
            yield s

    def ping(self) -> bool:
        try:
            with self.engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    def current_revision(self) -> str | None:
        try:
            with self.engine.connect() as conn:
                row = conn.execute(text("SELECT version_num FROM alembic_version")).first()
                return str(row[0]) if row else None
        except Exception:
            return None

    def dispose(self) -> None:
        self.engine.dispose()
