"""Image check: OCR (Hindi + English) + QR decode → the same text/URL/UPI pipeline.

Typical inputs: fake FIR / arrest-warrant / ID-card images (digital arrest), screenshots of
scam SMS, "scan to receive money" UPI QRs, fake payment screenshots. The image and its OCR
text live only in memory for the duration of the check.
"""

import asyncio
import logging
from dataclasses import dataclass

from redis.asyncio import Redis

from kavach.detectors.url.analyse import DeepContext
from kavach.media.ocr import BadImage, OcrEngine, load_image
from kavach.media.qr import decode_qr, qr_findings, qr_text
from kavach.pipeline import TextResult, analyse_text
from kavach.reputation.store import Store

log = logging.getLogger(__name__)

MIN_OCR_CHARS = 12  # below this, OCR output is noise


@dataclass
class ImageResult:
    result: TextResult
    readable: bool  # found text or a QR code
    ocr_chars: int
    qr_count: int


async def analyse_image(
    data: bytes,
    caption: str,
    ocr: OcrEngine,
    redis: Redis,
    store: Store,
    deep: DeepContext | None = None,
) -> ImageResult:
    try:
        img = await asyncio.to_thread(load_image, data)
    except BadImage as exc:
        log.info("unreadable image", extra={"error": str(exc)})
        empty = await analyse_text(caption, redis, store, deep)
        return ImageResult(empty, readable=bool(caption.strip()), ocr_chars=0, qr_count=0)

    text, payloads = await asyncio.gather(ocr.read(img), asyncio.to_thread(decode_qr, img))
    text = text.strip() if len(text.strip()) >= MIN_OCR_CHARS else ""
    combined = "\n".join(p for p in (caption, text, qr_text(payloads)) if p)
    extra = qr_findings(payloads, f"{caption}\n{text}")
    result = await analyse_text(
        combined, redis, store, deep, extra_findings=extra, force_content=bool(payloads)
    )
    return ImageResult(
        result,
        readable=bool(text or payloads or caption.strip()),
        ocr_chars=len(text),
        qr_count=len(payloads),
    )
