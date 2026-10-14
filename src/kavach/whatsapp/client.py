"""Thin client for the Meta WhatsApp Cloud API (direct, no BSP)."""

import logging
from typing import Any, Protocol

import httpx
from redis.asyncio import Redis

from kavach.config import Settings

log = logging.getLogger(__name__)

MAX_BODY = 4096  # WhatsApp text body limit


class WhatsAppError(RuntimeError):
    pass


class Messenger(Protocol):
    async def send_text(self, to: str, body: str, reply_to: str | None = None) -> None: ...

    async def mark_read(self, message_id: str, typing: bool = True) -> None: ...


class DryRunMessenger:
    """Local testing without Meta: replies go to Redis (10 min TTL) for the replay tool."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def send_text(self, to: str, body: str, reply_to: str | None = None) -> None:
        await self._redis.set(f"dryrun:reply:{reply_to}", body, ex=600)
        log.info("dry-run reply stored", extra={"reply_to": reply_to})

    async def mark_read(self, message_id: str, typing: bool = True) -> None:
        return None


class WhatsAppClient:
    def __init__(self, settings: Settings, http: httpx.AsyncClient) -> None:
        self._s = settings
        self._http = http
        self._url = (
            f"{settings.graph_api_base}/{settings.graph_api_version}/"
            f"{settings.whatsapp_phone_number_id}/messages"
        )

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._s.whatsapp_access_token.get_secret_value()}"}

    async def _post(self, payload: dict[str, Any]) -> None:
        resp = await self._http.post(self._url, json=payload, headers=self._headers())
        if resp.status_code >= 400:
            # Body holds Meta's error code/message; it never echoes user content back.
            raise WhatsAppError(f"graph api {resp.status_code}: {resp.text[:300]}")

    async def send_text(self, to: str, body: str, reply_to: str | None = None) -> None:
        payload: dict[str, Any] = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": to,
            "type": "text",
            "text": {"body": body[:MAX_BODY], "preview_url": False},
        }
        if reply_to:
            payload["context"] = {"message_id": reply_to}
        await self._post(payload)

    async def mark_read(self, message_id: str, typing: bool = True) -> None:
        """Blue ticks + 'typing…' while we work. Not billed."""
        payload: dict[str, Any] = {
            "messaging_product": "whatsapp",
            "status": "read",
            "message_id": message_id,
        }
        if typing:
            payload["typing_indicator"] = {"type": "text"}
        try:
            await self._post(payload)
        except (WhatsAppError, httpx.HTTPError) as exc:
            log.warning("mark_read failed", extra={"error": str(exc)[:200]})

    async def download_media(self, media_id: str, max_bytes: int) -> bytes:
        base = f"{self._s.graph_api_base}/{self._s.graph_api_version}/{media_id}"
        meta = await self._http.get(base, headers=self._headers())
        if meta.status_code >= 400:
            raise WhatsAppError(f"media lookup {meta.status_code}")
        info = meta.json()
        if int(info.get("file_size", 0)) > max_bytes:
            raise WhatsAppError("media too large")
        chunks: list[bytes] = []
        size = 0
        async with self._http.stream("GET", info["url"], headers=self._headers()) as resp:
            if resp.status_code >= 400:
                raise WhatsAppError(f"media download {resp.status_code}")
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise WhatsAppError("media too large")
                chunks.append(chunk)
        return b"".join(chunks)
