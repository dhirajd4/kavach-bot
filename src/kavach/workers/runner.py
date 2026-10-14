"""Worker process: consume the Redis stream, run checks, sync threat intel.

python -m kavach.workers.runner
"""

import asyncio
import contextlib
import logging
import os
import socket
from typing import Any

from redis.asyncio import Redis

from kavach import queue
from kavach.deps import Deps, build_deps
from kavach.intel import openphish
from kavach.verdict.templates import ERROR
from kavach.workers.checker import Checker

log = logging.getLogger(__name__)

CONCURRENCY = 8
MAX_ATTEMPTS = 3
CLAIM_IDLE_MS = 60_000


def _decode(fields: dict[Any, Any]) -> dict[str, str]:
    return {
        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
        for k, v in fields.items()
    }


class Runner:
    def __init__(self, deps: Deps) -> None:
        self.deps = deps
        self.redis: Redis = deps.redis
        self.checker = Checker(
            deps.settings, deps.redis, deps.store, deps.messenger, deps.explainer
        )
        self.consumer = f"{socket.gethostname()}-{os.getpid()}"
        self.sem = asyncio.Semaphore(CONCURRENCY)
        self.tasks: set[asyncio.Task[None]] = set()

    async def handle(self, entry_id: str, fields: dict[str, str]) -> None:
        async with self.sem:
            try:
                await self.checker.process(fields)
                await queue.done(self.redis, entry_id)
            except Exception:
                attempts = await self.redis.incr(f"attempts:{entry_id}")
                await self.redis.expire(f"attempts:{entry_id}", 3600)
                log.exception("check failed", extra={"attempt": attempts})
                if attempts >= MAX_ATTEMPTS:
                    with contextlib.suppress(Exception):
                        lang = fields.get("language", "hinglish")
                        await self.deps.messenger.send_text(
                            fields["wa_id"],
                            ERROR.get(lang, ERROR["hinglish"]),
                            reply_to=fields.get("message_id"),
                        )
                    await queue.done(self.redis, entry_id)

    def _spawn(self, entry_id: str, fields: dict[str, str]) -> None:
        task = asyncio.create_task(self.handle(entry_id, fields))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def consume(self) -> None:
        await queue.ensure_group(self.redis)
        while True:
            resp: Any = await self.redis.xreadgroup(
                queue.GROUP, self.consumer, {queue.STREAM: ">"}, count=CONCURRENCY, block=5000
            )
            for _stream, entries in resp or []:
                for entry_id, fields in entries:
                    eid = entry_id.decode() if isinstance(entry_id, bytes) else entry_id
                    self._spawn(eid, _decode(fields))

    async def reclaim(self) -> None:
        """Pick up jobs from crashed or stuck consumers."""
        while True:
            await asyncio.sleep(30)
            try:
                claimed: Any = await self.redis.xautoclaim(
                    queue.STREAM, queue.GROUP, self.consumer, min_idle_time=CLAIM_IDLE_MS, count=20
                )
            except Exception:
                log.exception("xautoclaim failed")
                continue
            # Reply shape: [next_id, [(id, fields), ...], deleted_ids]
            for entry_id, fields in claimed[1]:
                if fields:  # empty when the entry was deleted meanwhile
                    eid = entry_id.decode() if isinstance(entry_id, bytes) else entry_id
                    self._spawn(eid, _decode(fields))

    async def intel_sync(self) -> None:
        s = self.deps.settings
        while True:
            # One worker syncs per interval (Redis lock), the rest skip.
            if await self.redis.set(
                "lock:openphish", self.consumer, nx=True, ex=max(60, s.openphish_sync_seconds - 60)
            ):
                try:
                    await openphish.sync(self.redis, self.deps.http, s.openphish_feed_url)
                except Exception:
                    log.exception("openphish sync failed")
                    await self.redis.delete("lock:openphish")
            await asyncio.sleep(s.openphish_sync_seconds)


async def main() -> None:
    deps = await build_deps()
    runner = Runner(deps)
    log.info("worker started", extra={"consumer": runner.consumer})
    try:
        await asyncio.gather(runner.consume(), runner.reclaim(), runner.intel_sync())
    finally:
        await deps.close()


if __name__ == "__main__":
    asyncio.run(main())
