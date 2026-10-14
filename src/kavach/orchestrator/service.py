"""Webhook-side orchestration: idempotency → rate limit → commands → cache → enqueue.

Runs right after the webhook has returned 200 to Meta, so nothing here delays the ack.
"""

import logging
import time
from dataclasses import dataclass

from redis.asyncio import Redis

from kavach import queue
from kavach.config import Settings
from kavach.hashing import content_hash, normalise_text, user_hash
from kavach.orchestrator import cache
from kavach.reputation.store import CheckRecord, Store
from kavach.verdict.language import detect_language, language_command
from kavach.verdict.templates import LANG_SET, RATE_LIMITED, UNSUPPORTED, WELCOME
from kavach.whatsapp.client import Messenger
from kavach.whatsapp.payloads import InboundKind, InboundMessage

log = logging.getLogger(__name__)

SUPPORTED_NOW = frozenset({InboundKind.TEXT, InboundKind.BUTTON})


@dataclass(slots=True)
class Orchestrator:
    settings: Settings
    redis: Redis
    store: Store
    messenger: Messenger

    async def handle(self, msg: InboundMessage) -> None:
        started = time.monotonic()
        if not await self._first_delivery(msg.message_id):
            return  # Meta retries webhooks; process each message once
        uhash = user_hash(msg.wa_id, self.settings.user_hash_key.get_secret_value())
        if not await self._within_rate_limit(uhash, msg):
            return

        lang_cmd = language_command(msg.text) if msg.kind is InboundKind.TEXT else None
        user = await self.store.touch_user(uhash, lang_cmd or detect_language(msg.text))
        lang = user.language
        if lang_cmd:
            await self.store.set_language(uhash, lang_cmd)
            await self.messenger.send_text(msg.wa_id, LANG_SET[lang_cmd], reply_to=msg.message_id)
            return

        await self.messenger.mark_read(msg.message_id)
        if msg.kind not in SUPPORTED_NOW:
            body = UNSUPPORTED[lang]
            if user.is_new:
                body = WELCOME[lang] + "\n\n" + body
            await self.messenger.send_text(msg.wa_id, body, reply_to=msg.message_id)
            return

        input_hash = content_hash("text", normalise_text(msg.text))
        hit = await cache.get(self.redis, input_hash, lang)
        if hit is not None:
            body = hit.body if not user.is_new else WELCOME[lang] + "\n\n━━━━━━━━━━\n\n" + hit.body
            await self.messenger.send_text(msg.wa_id, body, reply_to=msg.message_id)
            await self.store.save_check(
                CheckRecord(
                    user_hash=uhash,
                    input_type="text",
                    input_hash=input_hash,
                    verdict=hit.verdict,
                    score=hit.score,
                    reason_codes=hit.reason_codes,
                    domains=hit.domains,
                    language=lang,
                    from_cache=True,
                    llm_used=hit.llm_used,
                    latency_ms=int((time.monotonic() - started) * 1000),
                )
            )
            log.info("cache hit", extra={"verdict": hit.verdict})
            return

        await queue.enqueue(
            self.redis,
            {
                "kind": msg.kind.value,
                "message_id": msg.message_id,
                "wa_id": msg.wa_id,
                "user_hash": uhash,
                "text": msg.text,
                "media_id": msg.media_id,
                "language": lang,
                "first_time": int(user.is_new),
                "input_hash": input_hash,
                "received_at": time.time(),
            },
        )

    async def _first_delivery(self, message_id: str) -> bool:
        return bool(
            await self.redis.set(
                f"seen:msg:{message_id}", 1, nx=True, ex=self.settings.idempotency_ttl_seconds
            )
        )

    async def _within_rate_limit(self, uhash: str, msg: InboundMessage) -> bool:
        key = f"rl:{uhash}:{int(time.time() // 3600)}"
        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, 3700)
            count, _ = await pipe.execute()
        limit = self.settings.rate_limit_per_hour
        if count <= limit:
            return True
        if count == limit + 1:  # tell them once, then stay silent (every reply costs money)
            await self.messenger.send_text(
                msg.wa_id, RATE_LIMITED[detect_language(msg.text)], reply_to=msg.message_id
            )
        log.info("rate limited")
        return False
