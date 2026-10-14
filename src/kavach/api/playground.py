"""Local playground: chat with the bot in a browser. Only active when WHATSAPP_DRY_RUN=true.

The message goes through the real path (orchestrator → Redis stream → worker → reply), with
the dry-run messenger standing in for Meta. A debug panel shows the score and reasons.
"""

import asyncio
import time
import uuid
from importlib import resources

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from kavach.deps import Deps
from kavach.orchestrator.service import Orchestrator
from kavach.pipeline import analyse_text
from kavach.whatsapp.payloads import InboundKind, InboundMessage

router = APIRouter()


class SimulateIn(BaseModel):
    text: str = Field(min_length=1, max_length=4000)
    sender: str = Field(default="910000000001", pattern=r"^\d{6,15}$")


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
    await orchestrator.handle(
        InboundMessage(message_id=msg_id, wa_id=body.sender, kind=InboundKind.TEXT, text=body.text)
    )
    reply = None
    while reply is None and time.monotonic() - started < 20:
        reply = await deps.redis.get(f"dryrun:reply:{msg_id}")
        if reply is None:
            await asyncio.sleep(0.1)
    elapsed_ms = int((time.monotonic() - started) * 1000)

    analysis = await analyse_text(body.text, deps.redis, deps.store)
    d = analysis.decision
    return {
        "reply": reply.decode() if isinstance(reply, bytes) else reply,
        "ms": elapsed_ms,
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
        },
    }
