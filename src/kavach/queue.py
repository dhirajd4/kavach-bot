"""Redis Streams job queue (TDS §11: one component for cache + queue early on).

Jobs carry message content only transiently: entries are XDEL'd right after processing.
"""

from typing import Any

from redis.asyncio import Redis

STREAM = "kavach:checks"
GROUP = "workers"
MAXLEN = 10_000


async def ensure_group(redis: Redis) -> None:
    try:
        await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
    except Exception as exc:  # BUSYGROUP: already exists
        if "BUSYGROUP" not in str(exc):
            raise


async def enqueue(redis: Redis, job: dict[str, Any]) -> str:
    fields = {k: str(v) for k, v in job.items()}
    entry_id = await redis.xadd(STREAM, fields, maxlen=MAXLEN, approximate=True)  # type: ignore[arg-type]
    return entry_id.decode() if isinstance(entry_id, bytes) else str(entry_id)


async def done(redis: Redis, entry_id: str) -> None:
    async with redis.pipeline(transaction=True) as pipe:
        pipe.xack(STREAM, GROUP, entry_id)
        pipe.xdel(STREAM, entry_id)
        pipe.delete(f"attempts:{entry_id}")
        await pipe.execute()
