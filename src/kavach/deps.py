"""Wire up shared clients once per process."""

from dataclasses import dataclass

import httpx
from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine

from kavach.config import Settings, get_settings
from kavach.db.session import make_engine, make_sessionmaker
from kavach.detectors.url.analyse import DeepContext
from kavach.llm.base import ExplanationProvider
from kavach.logs import setup_logging
from kavach.reputation.store import PgStore
from kavach.sandbox.client import SandboxClient
from kavach.whatsapp.client import DryRunMessenger, Messenger, WhatsAppClient


@dataclass(slots=True)
class Deps:
    settings: Settings
    redis: Redis
    http: httpx.AsyncClient
    engine: AsyncEngine
    store: PgStore
    messenger: Messenger
    explainer: ExplanationProvider | None = None
    deep: DeepContext | None = None

    async def close(self) -> None:
        await self.http.aclose()
        await self.redis.aclose()
        await self.engine.dispose()


async def build_deps(settings: Settings | None = None) -> Deps:
    settings = settings or get_settings()
    setup_logging(settings.log_level)
    # Socket timeout must exceed the worker's XREADGROUP block time (5 s).
    redis = Redis.from_url(settings.redis_url, socket_timeout=30, socket_connect_timeout=5)
    http = httpx.AsyncClient(timeout=settings.http_timeout_seconds, follow_redirects=False)
    engine = make_engine(settings.database_url)
    store = PgStore(make_sessionmaker(engine))
    sandbox = SandboxClient(settings.sandbox_url, http, redis) if settings.sandbox_enabled else None
    return Deps(
        settings=settings,
        redis=redis,
        http=http,
        engine=engine,
        store=store,
        messenger=(
            DryRunMessenger(redis) if settings.whatsapp_dry_run else WhatsAppClient(settings, http)
        ),
        deep=DeepContext(settings=settings, http=http, sandbox=sandbox),
    )
