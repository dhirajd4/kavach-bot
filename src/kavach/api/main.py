"""HTTP entrypoint: Meta webhook + health.

uvicorn kavach.api.main:app --host 0.0.0.0 --port 8000
"""

import json
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import PlainTextResponse

from kavach import queue
from kavach.api.playground import router as playground_router
from kavach.deps import Deps, build_deps
from kavach.orchestrator.service import Orchestrator
from kavach.whatsapp.payloads import InboundMessage, parse_webhook
from kavach.whatsapp.signature import verify_signature

log = logging.getLogger(__name__)

MAX_WEBHOOK_BYTES = 1_000_000


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    deps = await build_deps()
    await queue.ensure_group(deps.redis)
    app.state.deps = deps
    app.state.orchestrator = Orchestrator(deps.settings, deps.redis, deps.store, deps.messenger)
    yield
    await deps.close()


app = FastAPI(title="Kavach bot", lifespan=lifespan, docs_url=None, redoc_url=None)
app.include_router(playground_router)  # 404s unless WHATSAPP_DRY_RUN=true


@app.get("/healthz")
async def healthz(request: Request) -> dict[str, str]:
    deps: Deps = request.app.state.deps
    await deps.redis.ping()
    return {"status": "ok"}


@app.get("/webhook", response_class=PlainTextResponse)
async def verify(
    request: Request,
    mode: str = Query("", alias="hub.mode"),
    token: str = Query("", alias="hub.verify_token"),
    challenge: str = Query("", alias="hub.challenge"),
) -> str:
    expected = request.app.state.deps.settings.whatsapp_verify_token.get_secret_value()
    if mode == "subscribe" and expected and token == expected:
        return challenge
    raise HTTPException(status_code=403)


@app.post("/webhook")
async def receive(request: Request, background: BackgroundTasks) -> Response:
    deps: Deps = request.app.state.deps
    raw = await request.body()
    if len(raw) > MAX_WEBHOOK_BYTES:
        raise HTTPException(status_code=413)
    secret = deps.settings.meta_app_secret.get_secret_value()
    if not verify_signature(raw, request.headers.get("x-hub-signature-256"), secret):
        log.warning("bad webhook signature")
        raise HTTPException(status_code=401)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400) from exc

    orchestrator: Orchestrator = request.app.state.orchestrator
    for msg in parse_webhook(payload):
        background.add_task(_safe_handle, orchestrator, msg)
    # Ack fast; Meta retries anything that isn't a quick 200.
    return Response(status_code=200)


async def _safe_handle(orchestrator: Orchestrator, msg: InboundMessage) -> None:
    try:
        await orchestrator.handle(msg)
    except Exception:
        log.exception("orchestrator failed")
