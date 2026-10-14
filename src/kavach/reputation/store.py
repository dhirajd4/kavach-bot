"""Persistence for users, checks and the reputation DB (Postgres). Callers depend on the
`Store` protocol so tests can use an in-memory fake."""

import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol

from sqlalchemy import case, func, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from kavach.db.models import Check, ReputationEntity, User
from kavach.hashing import sha256_hex

PERSONAL_TYPES = frozenset({"phone", "upi"})


@dataclass(frozen=True, slots=True)
class EntityRef:
    entity_type: str  # domain | host | url | apk | phone | upi
    value: str

    @property
    def sha256(self) -> str:
        return sha256_hex(f"{self.entity_type}:{self.value.lower()}")


@dataclass(frozen=True, slots=True)
class RepRecord:
    entity_type: str
    sha256: str
    verdict: str
    score: float
    sources: tuple[str, ...]
    report_count: int


@dataclass(frozen=True, slots=True)
class UserInfo:
    user_hash: str
    language: str
    is_new: bool


@dataclass(slots=True)
class CheckRecord:
    user_hash: str
    input_type: str
    input_hash: str
    verdict: str
    score: float
    reason_codes: list[str]
    language: str
    latency_ms: int
    domains: list[str] = field(default_factory=list)
    from_cache: bool = False
    llm_used: str = "template"
    id: uuid.UUID = field(default_factory=uuid.uuid4)


class Store(Protocol):
    async def touch_user(self, user_hash: str, default_language: str) -> UserInfo: ...

    async def set_language(self, user_hash: str, language: str) -> None: ...

    async def save_check(self, record: CheckRecord) -> None: ...

    async def lookup(self, refs: Iterable[EntityRef]) -> dict[str, RepRecord]: ...

    async def record_sightings(self, refs: Iterable[EntityRef]) -> None: ...

    async def mark(self, ref: EntityRef, verdict: str, score: float, source: str) -> None: ...


class PgStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def touch_user(self, user_hash: str, default_language: str) -> UserInfo:
        now = datetime.now(UTC)
        async with self._sessions.begin() as s:
            stmt = (
                insert(User)
                .values(
                    user_hash=user_hash,
                    language=default_language,
                    consent_at=now,
                    checks_count=0,
                    last_seen_at=now,
                )
                .on_conflict_do_update(
                    index_elements=[User.user_hash],
                    set_={"last_seen_at": now, "checks_count": User.checks_count + 1},
                )
                .returning(User.language, User.checks_count)
            )
            row = (await s.execute(stmt)).one()
        return UserInfo(user_hash=user_hash, language=row.language, is_new=row.checks_count == 0)

    async def set_language(self, user_hash: str, language: str) -> None:
        async with self._sessions.begin() as s:
            user = await s.get(User, user_hash)
            if user is not None:
                user.language = language

    async def save_check(self, record: CheckRecord) -> None:
        async with self._sessions.begin() as s:
            s.add(
                Check(
                    id=record.id,
                    user_hash=record.user_hash,
                    input_type=record.input_type,
                    input_hash=record.input_hash,
                    verdict=record.verdict,
                    score=record.score,
                    reason_codes=record.reason_codes,
                    domains=record.domains,
                    language=record.language,
                    latency_ms=record.latency_ms,
                    from_cache=record.from_cache,
                    llm_used=record.llm_used,
                )
            )

    async def lookup(self, refs: Iterable[EntityRef]) -> dict[str, RepRecord]:
        hashes = {r.sha256 for r in refs}
        if not hashes:
            return {}
        async with self._sessions() as s:
            rows = (
                await s.execute(select(ReputationEntity).where(ReputationEntity.sha256.in_(hashes)))
            ).scalars()
            return {
                r.sha256: RepRecord(
                    r.entity_type, r.sha256, r.verdict, r.score, tuple(r.sources), r.report_count
                )
                for r in rows
            }

    async def record_sightings(self, refs: Iterable[EntityRef]) -> None:
        """A user asked about it: count it. Never changes the verdict (one phone can't
        clear or condemn anything for everyone, TDS §16.3)."""
        now = datetime.now(UTC)
        values = [_row(r) | {"report_count": 1, "last_seen_at": now} for r in refs]
        if not values:
            return
        async with self._sessions.begin() as s:
            stmt = insert(ReputationEntity).values(values)
            stmt = stmt.on_conflict_do_update(
                constraint="uq_rep_type_hash",
                set_={
                    "report_count": ReputationEntity.report_count + 1,
                    "last_seen_at": stmt.excluded.last_seen_at,
                },
            )
            await s.execute(stmt)

    async def mark(self, ref: EntityRef, verdict: str, score: float, source: str) -> None:
        now = datetime.now(UTC)
        async with self._sessions.begin() as s:
            stmt = insert(ReputationEntity).values(
                _row(ref)
                | {"verdict": verdict, "score": score, "sources": [source], "last_seen_at": now}
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_rep_type_hash",
                set_={
                    "verdict": verdict,
                    "score": func.greatest(ReputationEntity.score, score),
                    "sources": case(
                        (
                            func.array_position(ReputationEntity.sources, source).is_not(None),
                            ReputationEntity.sources,
                        ),
                        else_=func.array_append(ReputationEntity.sources, source),
                    ),
                    "last_seen_at": now,
                },
            )
            await s.execute(stmt)

    async def by_prefix(self, entity_type: str, prefix5: str) -> list[RepRecord]:
        async with self._sessions() as s:
            rows = (
                await s.execute(
                    select(ReputationEntity).where(
                        ReputationEntity.entity_type == entity_type,
                        ReputationEntity.prefix5 == prefix5,
                        ReputationEntity.verdict.in_(("scam", "suspicious", "safe")),
                    )
                )
            ).scalars()
            return [
                RepRecord(
                    r.entity_type, r.sha256, r.verdict, r.score, tuple(r.sources), r.report_count
                )
                for r in rows
            ]


def _row(ref: EntityRef) -> dict[str, object]:
    sha = ref.sha256
    return {
        "entity_type": ref.entity_type,
        "sha256": sha,
        "prefix5": sha[:5],
        "value": None if ref.entity_type in PERSONAL_TYPES else ref.value.lower(),
    }
