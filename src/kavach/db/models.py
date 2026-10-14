"""Postgres schema. No raw message text and no raw phone numbers or wa_ids are ever stored."""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    user_hash: Mapped[str] = mapped_column(String(64), primary_key=True)  # HMAC(wa_id)
    language: Mapped[str] = mapped_column(String(16), default="hinglish")
    consent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    checks_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Check(Base):
    __tablename__ = "checks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_hash: Mapped[str] = mapped_column(String(64), index=True)
    input_type: Mapped[str] = mapped_column(String(16))  # text | url | image | apk
    input_hash: Mapped[str] = mapped_column(String(64), index=True)
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    score: Mapped[float] = mapped_column(Float, default=0)
    reason_codes: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    # Registrable domains seen in the check (not personal data). Needed by analysts.
    domains: Mapped[list[str]] = mapped_column(ARRAY(String(253)), default=list)
    language: Mapped[str] = mapped_column(String(16))
    latency_ms: Mapped[int] = mapped_column(Integer)
    from_cache: Mapped[bool] = mapped_column(default=False)
    llm_used: Mapped[str] = mapped_column(String(32), default="template")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


class ReputationEntity(Base):
    __tablename__ = "reputation_entities"
    __table_args__ = (
        UniqueConstraint("entity_type", "sha256", name="uq_rep_type_hash"),
        Index("ix_rep_type_prefix", "entity_type", "prefix5"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    entity_type: Mapped[str] = mapped_column(String(16))  # domain | host | url | apk | phone | upi
    sha256: Mapped[str] = mapped_column(String(64))
    prefix5: Mapped[str] = mapped_column(String(5))
    # Plain value only for non-personal types (domain/host/url/apk hash); NULL for phone/upi.
    value: Mapped[str | None] = mapped_column(Text)
    verdict: Mapped[str] = mapped_column(
        String(16), default="unknown"
    )  # scam|suspicious|safe|unknown
    score: Mapped[float] = mapped_column(Float, default=0)
    sources: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list)
    report_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Label(Base):
    __tablename__ = "labels"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    check_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("checks.id", ondelete="CASCADE"), index=True
    )
    analyst: Mapped[str] = mapped_column(String(64))
    verdict: Mapped[str] = mapped_column(String(16))  # scam | safe | unsure
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
