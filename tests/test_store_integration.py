"""Runs against the docker-compose Postgres (after `make up`):

.venv/bin/pytest -m integration
"""

import os
import uuid

import pytest
from sqlalchemy import text

from kavach.db.session import make_engine, make_sessionmaker
from kavach.reputation.store import CheckRecord, EntityRef, PgStore

pytestmark = pytest.mark.integration

DB_URL = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+asyncpg://kavach:kavach@localhost:5432/kavach"
)


@pytest.fixture
async def pg():  # type: ignore[no-untyped-def]
    engine = make_engine(DB_URL)
    yield PgStore(make_sessionmaker(engine)), engine
    await engine.dispose()


async def test_user_language_and_check_roundtrip(pg) -> None:  # type: ignore[no-untyped-def]
    store, engine = pg
    uh = uuid.uuid4().hex
    first = await store.touch_user(uh, "hi")
    second = await store.touch_user(uh, "en")
    assert first.is_new and not second.is_new and second.language == "hi"
    await store.set_language(uh, "en")
    assert (await store.touch_user(uh, "hi")).language == "en"
    await store.save_check(
        CheckRecord(
            user_hash=uh,
            input_type="text",
            input_hash="h" * 64,
            verdict="scam",
            score=9,
            reason_codes=["OTP_REQUEST"],
            language="en",
            latency_ms=12,
        )
    )
    async with engine.connect() as c:
        n = await c.scalar(text("select count(*) from checks where user_hash=:u"), {"u": uh})
    assert n == 1


async def test_reputation_mark_lookup_sightings(pg) -> None:  # type: ignore[no-untyped-def]
    store, engine = pg
    host = EntityRef("host", f"{uuid.uuid4().hex[:8]}.phish.xyz")
    upi = EntityRef("upi", f"{uuid.uuid4().hex[:8]}@ybl")
    await store.record_sightings([host, upi])
    await store.record_sightings([host])
    await store.mark(host, "scam", 10, "openphish")
    await store.mark(host, "scam", 8, "openphish")  # same source not duplicated
    reps = await store.lookup([host, upi])
    assert reps[host.sha256].verdict == "scam"
    assert reps[host.sha256].sources == ("openphish",)
    assert reps[host.sha256].report_count == 2
    assert reps[upi.sha256].verdict == "unknown"
    async with engine.connect() as c:
        value = await c.scalar(
            text("select value from reputation_entities where sha256=:h"), {"h": upi.sha256}
        )
    assert value is None  # personal identifiers are stored hashed only
    prefixed = await store.by_prefix("host", host.sha256[:5])
    assert any(r.sha256 == host.sha256 for r in prefixed)
