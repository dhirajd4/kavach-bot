"""In-memory Store: offline eval and tests. Same contract as PgStore, nothing persisted."""

from collections.abc import Iterable
from dataclasses import dataclass, field

from kavach.reputation.store import CheckRecord, EntityRef, RepRecord, UserInfo


@dataclass
class MemoryStore:
    users: dict[str, str] = field(default_factory=dict)
    checks: list[CheckRecord] = field(default_factory=list)
    reputation: dict[str, RepRecord] = field(default_factory=dict)
    sightings: list[EntityRef] = field(default_factory=list)

    async def touch_user(self, user_hash: str, default_language: str) -> UserInfo:
        is_new = user_hash not in self.users
        if is_new:
            self.users[user_hash] = default_language
        return UserInfo(user_hash, self.users[user_hash], is_new)

    async def set_language(self, user_hash: str, language: str) -> None:
        self.users[user_hash] = language

    async def save_check(self, record: CheckRecord) -> None:
        self.checks.append(record)

    async def lookup(self, refs: Iterable[EntityRef]) -> dict[str, RepRecord]:
        return {r.sha256: self.reputation[r.sha256] for r in refs if r.sha256 in self.reputation}

    async def record_sightings(self, refs: Iterable[EntityRef]) -> None:
        self.sightings.extend(refs)

    async def mark(self, ref: EntityRef, verdict: str, score: float, source: str) -> None:
        self.reputation[ref.sha256] = RepRecord(
            ref.entity_type, ref.sha256, verdict, score, (source,), 0
        )

    def seed(self, ref: EntityRef, verdict: str, source: str = "seed") -> None:
        self.reputation[ref.sha256] = RepRecord(
            ref.entity_type, ref.sha256, verdict, 10, (source,), 1
        )
