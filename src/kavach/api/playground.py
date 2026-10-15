"""Local playground: chat with the bot in a browser. Only active when WHATSAPP_DRY_RUN=true.

The message goes through the real path (orchestrator → Redis stream → worker → reply), with
the dry-run messenger standing in for Meta. A debug panel shows the score and reasons.
"""

import asyncio
import base64
import time
import uuid
from importlib import resources

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, model_validator

from kavach.apk.check import analyse_apk
from kavach.deps import Deps
from kavach.hashing import sha256_hex
from kavach.media.image import analyse_image
from kavach.media.ocr import TesseractOcr
from kavach.orchestrator.service import Orchestrator
from kavach.pipeline import analyse_text
from kavach.whatsapp.payloads import InboundKind, InboundMessage

router = APIRouter()


class SimulateIn(BaseModel):
    text: str = Field(default="", max_length=4000)  # message text, or the photo's caption
    sender: str = Field(default="910000000001", pattern=r"^\d{6,15}$")
    image_b64: str | None = Field(default=None, max_length=8_000_000)
    # Any other file (APKs): sent like a WhatsApp document.
    file_b64: str | None = Field(default=None, max_length=85_000_000)
    filename: str = Field(default="", max_length=200)

    @model_validator(mode="after")
    def _something(self) -> "SimulateIn":
        if not self.text.strip() and not self.image_b64 and not self.file_b64:
            raise ValueError("send text, an image or a file")
        return self


def _enabled(request: Request) -> Deps:
    deps: Deps = request.app.state.deps
    if not deps.settings.whatsapp_dry_run:
        raise HTTPException(status_code=404)
    return deps


@router.get("/playground", response_class=HTMLResponse)
async def playground(request: Request) -> str:
    _enabled(request)
    return resources.files("kavach.api").joinpath("playground.html").read_text("utf-8")


@router.post("/dev/simulate")
async def simulate(body: SimulateIn, request: Request) -> dict[str, object]:
    deps = _enabled(request)
    orchestrator: Orchestrator = request.app.state.orchestrator
    msg_id = f"wamid.play.{uuid.uuid4().hex[:16]}"
    started = time.monotonic()
    photo = base64.b64decode(body.image_b64) if body.image_b64 else b""
    document = base64.b64decode(body.file_b64) if body.file_b64 else b""
    if document:
        media_id = f"play-{uuid.uuid4().hex[:16]}"
        await deps.redis.set(f"dryrun:media:{media_id}", document, ex=600)
        is_apk = body.filename.lower().endswith((".apk", ".apks", ".xapk"))
        msg = InboundMessage(
            message_id=msg_id,
            wa_id=body.sender,
            kind=InboundKind.DOCUMENT,
            text=body.text,
            media_id=media_id,
            media_mime="application/vnd.android.package-archive" if is_apk else "",
            media_sha256=sha256_hex(document),
            filename=body.filename,
        )
    elif photo:
        # Park the upload where the dry-run messenger's download_media() will find it,
        # exactly like a WhatsApp media id.
        media_id = f"play-{uuid.uuid4().hex[:16]}"
        await deps.redis.set(f"dryrun:media:{media_id}", photo, ex=600)
        msg = InboundMessage(
            message_id=msg_id,
            wa_id=body.sender,
            kind=InboundKind.IMAGE,
            text=body.text,
            media_id=media_id,
            media_mime="image/jpeg",
            media_sha256=sha256_hex(photo),
        )
    else:
        msg = InboundMessage(
            message_id=msg_id, wa_id=body.sender, kind=InboundKind.TEXT, text=body.text
        )
    await orchestrator.handle(msg)
    reply = None
    while reply is None and time.monotonic() - started < 20:
        reply = await deps.redis.get(f"dryrun:reply:{msg_id}")
        if reply is None:
            await asyncio.sleep(0.1)
    elapsed_ms = int((time.monotonic() - started) * 1000)

    image = await deps.redis.get(f"dryrun:image:{msg_id}")
    # Debug panel: same checks again; the deep ones hit the sandbox/RDAP caches.
    image_debug: dict[str, object] | None = None
    apk_debug: dict[str, object] | None = None
    if document:
        raw = (
            await deps.deep.sandbox.inspect_apk(document)
            if deps.deep and deps.deep.sandbox
            else None
        )
        analysis = await analyse_apk(
            document, body.text, body.filename, deps.redis, deps.store, deps.deep
        )
        if raw:
            apk_debug = {
                k: raw.get(k) for k in ("package", "label", "signed", "signers", "has_dex", "error")
            }
            apk_debug["permissions"] = len(raw.get("permissions") or [])
    elif photo:
        s = deps.settings
        img = await analyse_image(
            photo,
            body.text,
            TesseractOcr(s.ocr_langs, s.ocr_timeout_seconds),
            deps.redis,
            deps.store,
            deps.deep,
        )
        analysis = img.result
        image_debug = {
            "ocr_chars": img.ocr_chars,
            "qr_count": img.qr_count,
            "readable": img.readable,
        }
    else:
        analysis = await analyse_text(body.text, deps.redis, deps.store, deps.deep)
    d = analysis.decision
    return {
        "reply": reply.decode() if isinstance(reply, bytes) else reply,
        "ms": elapsed_ms,
        "image_b64": base64.b64encode(image).decode() if isinstance(image, bytes) else None,
        "debug": {
            "verdict": d.verdict.value,
            "score": d.score,
            "reasons": [
                {
                    "code": f.reason.value,
                    "weight": f.weight,
                    "evidence": f.evidence,
                    "decisive": f.decisive,
                }
                for f in sorted(d.top, key=lambda f: -f.weight)
            ],
            "all_codes": list(d.reason_codes),
            "domains": analysis.domains,
            "image": image_debug,
            "apk": apk_debug,
        },
    }
