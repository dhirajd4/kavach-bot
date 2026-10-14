"""Reply cache by content hash: identical forwards are answered with no worker and no LLM."""

import json
from dataclasses import asdict, dataclass

from redis.asyncio import Redis


@dataclass(frozen=True, slots=True)
class CachedReply:
    body: str  # rendered reply WITHOUT the first-time welcome
    verdict: str
    score: float
    reason_codes: list[str]
    domains: list[str]
    llm_used: str


def _key(input_hash: str, language: str) -> str:
    return f"cache:reply:{input_hash}:{language}"


async def get(redis: Redis, input_hash: str, language: str) -> CachedReply | None:
    raw = await redis.get(_key(input_hash, language))
    if raw is None:
        return None
    return CachedReply(**json.loads(raw))


async def put(redis: Redis, input_hash: str, language: str, reply: CachedReply, ttl: int) -> None:
    await redis.set(
        _key(input_hash, language), json.dumps(asdict(reply), ensure_ascii=False), ex=ttl
    )
