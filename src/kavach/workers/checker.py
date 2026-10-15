"""Process one queued check: analyse → decide → explain → ONE reply → persist hashes/verdict."""

import logging
import time
from dataclasses import dataclass

from redis.asyncio import Redis

from kavach.apk.check import analyse_apk
from kavach.config import Settings
from kavach.detectors.url.analyse import DeepContext
from kavach.llm.base import ExplanationProvider
from kavach.media.image import analyse_image
from kavach.media.ocr import OcrEngine, TesseractOcr
from kavach.orchestrator import cache
from kavach.pipeline import analyse_text
from kavach.reputation.store import CheckRecord, Store
from kavach.verdict.composer import explain, render
from kavach.verdict.rules import Verdict
from kavach.verdict.templates import APK_ADVICE, IMAGE_UNREADABLE, WELCOME
from kavach.whatsapp.client import MAX_CAPTION, Messenger

log = logging.getLogger(__name__)


@dataclass(slots=True)
class Checker:
    settings: Settings
    redis: Redis
    store: Store
    messenger: Messenger
    explainer: ExplanationProvider | None = None
    deep: DeepContext | None = None  # sandbox / RDAP / Web Risk; None = cheap checks only
    ocr: OcrEngine | None = None

    async def process(self, job: dict[str, str]) -> None:
        lang = job["language"]
        first_time = job.get("first_time") == "1"
        kind = job.get("kind", "text")
        if kind == "image":
            data = await self.messenger.download_media(
                job["media_id"], self.settings.max_image_bytes
            )
            ocr = self.ocr or TesseractOcr(
                self.settings.ocr_langs, self.settings.ocr_timeout_seconds
            )
            image = await analyse_image(data, job["text"], ocr, self.redis, self.store, self.deep)
            del data  # the photo is never kept
            result = image.result
        elif kind == "apk":
            data = await self.messenger.download_media(job["media_id"], self.settings.max_apk_bytes)
            result = await analyse_apk(
                data, job["text"], job.get("filename", ""), self.redis, self.store, self.deep
            )
            del data  # the file is never kept
        else:
            result = await analyse_text(job["text"], self.redis, self.store, self.deep)
        decision = result.decision
        nothing = decision.verdict is Verdict.NOTHING_TO_CHECK

        explanation = await explain(decision, lang, self.explainer)
        if kind == "image" and nothing:
            body = IMAGE_UNREADABLE[lang]
        else:
            body = render(
                decision,
                explanation,
                lang,
                first_time=False,
                extra_advice=APK_ADVICE[lang] if kind == "apk" else "",
            )
        reply = (
            WELCOME[lang] + "\n\n━━━━━━━━━━\n\n" + body
            if first_time and (not nothing or kind == "image")
            else body
        )
        # A retry after a later failure must not send a second (billed) reply.
        replied_key = f"replied:{job['message_id']}"
        if not await self.redis.exists(replied_key):
            if self._with_screenshot(decision.verdict, result.screenshot, reply):
                await self.messenger.send_image(
                    job["wa_id"], result.screenshot, reply, reply_to=job["message_id"]
                )
            else:
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
                input_type=kind
                if kind in ("image", "apk")
                else "url"
                if result.domains
                else "text",
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

    def _with_screenshot(self, verdict: Verdict, shot: bytes, caption: str) -> bool:
        """Evidence screenshot (TDS ch. 8) as ONE image message, caption = the verdict."""
        return (
            self.settings.send_screenshots
            and bool(shot)
            and verdict in (Verdict.SCAM, Verdict.SUSPICIOUS)
            and len(caption) <= MAX_CAPTION
        )
