"""Worker-side client for the sandbox container. Every failure degrades to None."""

import base64
import json
import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

import httpx
from redis.asyncio import Redis

from kavach.hashing import sha256_hex

log = logging.getLogger(__name__)

CACHE_TTL = 24 * 3600
APK_CACHE_TTL = 7 * 24 * 3600


@dataclass
class Expansion:
    chain: list[str]
    final_url: str
    apk_download: bool = False
    error: str = ""


@dataclass
class PageInput:
    type: str = ""
    name: str = ""
    id: str = ""
    placeholder: str = ""
    autocomplete: str = ""
    label: str = ""


@dataclass
class PageFacts:
    final_url: str
    title: str = ""
    text: str = ""
    inputs: list[PageInput] = field(default_factory=list)
    forms: list[str] = field(default_factory=list)
    apk_download: bool = False
    screenshot: bytes = b""
    error: str = ""
    ms: int = 0


class Sandbox(Protocol):
    async def expand(self, url: str) -> Expansion | None: ...

    async def visit(self, url: str) -> PageFacts | None: ...

    async def inspect_apk(self, data: bytes) -> dict[str, Any] | None: ...


class SandboxClient:
    def __init__(self, base_url: str, http: httpx.AsyncClient, redis: Redis) -> None:
        self._base = base_url.rstrip("/")
        self._http = http
        self._redis = redis

    async def _post(self, path: str, url: str, budget_s: float) -> dict[str, Any] | None:
        try:
            resp = await self._http.post(f"{self._base}{path}", json={"url": url}, timeout=budget_s)
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            return data
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("sandbox call failed", extra={"path": path, "error": type(exc).__name__})
            return None

    async def expand(self, url: str) -> Expansion | None:
        key = f"sbx:expand:{sha256_hex(url)}"
        if cached := await self._redis.get(key):
            return Expansion(**json.loads(cached))
        data = await self._post("/expand", url, budget_s=8)
        if data is None:
            return None
        exp = Expansion(
            chain=data["chain"],
            final_url=data["final_url"],
            apk_download=bool(data.get("apk_download")),
            error=data.get("error", ""),
        )
        await self._redis.set(key, json.dumps(asdict(exp)), ex=CACHE_TTL)
        return exp

    async def inspect_apk(self, data: bytes) -> dict[str, Any] | None:
        """Facts are cached by file hash: the same APK forwarded by many people is parsed once."""
        key = f"sbx:apk:{sha256_hex(data)}"
        if cached := await self._redis.get(key):
            cached_facts: dict[str, Any] = json.loads(cached)
            return cached_facts
        try:
            resp = await self._http.post(
                f"{self._base}/apk",
                content=data,
                timeout=45,
                headers={"content-type": "application/octet-stream"},
            )
            resp.raise_for_status()
            facts: dict[str, Any] = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("sandbox apk check failed", extra={"error": type(exc).__name__})
            return None
        if facts.get("error") != "parse: timeout":  # don't cache transient failures
            await self._redis.set(key, json.dumps(facts), ex=APK_CACHE_TTL)
        return facts

    async def visit(self, url: str) -> PageFacts | None:
        key = f"sbx:visit:{sha256_hex(url)}"
        if cached := await self._redis.get(key):
            return _facts(json.loads(cached))
        data = await self._post("/visit", url, budget_s=14)
        if data is None:
            return None
        if not data.get("error", "").startswith("visit"):  # don't cache transient failures
            await self._redis.set(key, json.dumps(data), ex=CACHE_TTL)
        return _facts(data)


def _facts(data: dict[str, Any]) -> PageFacts:
    shot = data.get("screenshot_b64") or ""
    return PageFacts(
        final_url=data.get("final_url", ""),
        title=data.get("title", ""),
        text=data.get("text", ""),
        inputs=[
            PageInput(**{k: str(v) for k, v in i.items() if k in PageInput.__dataclass_fields__})
            for i in data.get("inputs", [])
        ],
        forms=list(data.get("forms", [])),
        apk_download=bool(data.get("apk_download")),
        screenshot=base64.b64decode(shot) if shot else b"",
        error=data.get("error", ""),
        ms=int(data.get("ms", 0)),
    )
