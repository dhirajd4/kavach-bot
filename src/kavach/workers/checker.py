"""Process one queued check: analyse → decide → explain → ONE reply → persist hashes/verdict."""

import logging
import time
from dataclasses import dataclass

from redis.asyncio import Redis

from kavach.config import Settings
from kavach.llm.base import ExplanationProvider
from kavach.orchestrator import cache
from kavach.pipeline import analyse_text
from kavach.reputation.store import CheckRecord, Store
from kavach.verdict.composer import explain, render
from kavach.verdict.rules import Verdict
from kavach.verdict.templates import WELCOME
from kavach.whatsapp.client import Messenger

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Checker:
    settings: Settings
    redis: Redis
    store: Store
    messenger: Messenger
    explainer: ExplanationProvider | None = None

    async def process(self, job: dict[str, str]) -> None:
        lang = job["language"]
        first_time = job.get("first_time") == "1"
        result = await analyse_text(job["text"], self.redis, self.store)
        decision = result.decision

        explanation = await explain(decision, lang, self.explainer)
        body = render(decision, explanation, lang, first_time=False)
        reply = (
            WELCOME[lang] + "\n\n━━━━━━━━━━\n\n" + body
            if (first_time and decision.verdict is not Verdict.NOTHING_TO_CHECK)
            else body
        )
        # A retry after a later failure must not send a second (billed) reply.
        replied_key = f"replied:{job['message_id']}"
        if not await self.redis.exists(replied_key):
            await self.messenger.send_text(job["wa_id"], reply, reply_to=job["message_id"])
            await self.redis.set(replied_key, 1, ex=self.settings.idempotency_ttl_seconds)

        latency_ms = int((time.time() - float(job["received_at"])) * 1000)
        if decision.verdict is not Verdict.NOTHING_TO_CHECK:
            await cache.put(
                self.redis,
                job["input_hash"],
                lang,
                cache.CachedReply(
                    body=body,
                    verdict=decision.verdict.value,
                    score=decision.score,
                    reason_codes=list(decision.reason_codes),
                    domains=result.domains,
                    llm_used=explanation.provider,
                ),
                ttl=self.settings.reply_cache_ttl_seconds,
            )
            await self.store.record_sightings(result.refs)
        await self.store.save_check(
            CheckRecord(
                user_hash=job["user_hash"],
                input_type="url" if result.domains else "text",
                input_hash=job["input_hash"],
                verdict=decision.verdict.value,
                score=decision.score,
                reason_codes=list(decision.reason_codes),
                domains=result.domains,
                language=lang,
                latency_ms=latency_ms,
                llm_used=explanation.provider,
            )
        )
        log.info(
            "check done",
            extra={
                "verdict": decision.verdict.value,
                "score": decision.score,
                "latency_ms": latency_ms,
                "reasons": decision.reason_codes,
            },
        )
