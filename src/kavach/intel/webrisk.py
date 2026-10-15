"""Google Web Risk Lookup API (optional; commercial use allowed, 100k lookups/month free).
Disabled when WEBRISK_API_KEY is empty. Results cached 1 h."""

import logging

import httpx
from redis.asyncio import Redis

from kavach.hashing import sha256_hex

log = logging.getLogger(__name__)

ENDPOINT = "https://webrisk.googleapis.com/v1/uris:search"
THREATS = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")
CACHE_TTL = 3600


async def lookup(url: str, api_key: str, redis: Redis, http: httpx.AsyncClient) -> str | None:
    """Threat type if listed, '' if clean, None if unknown / disabled."""
    if not api_key:
        return None
    key = f"webrisk:{sha256_hex(url)}"
    cached = await redis.get(key)
    if cached is not None:
        return cached.decode() if isinstance(cached, bytes) else str(cached)
    params = httpx.QueryParams({"uri": url, "key": api_key, "threatTypes": list(THREATS)})
    try:
        resp = await http.get(ENDPOINT, params=params, timeout=4)
        resp.raise_for_status()
        threat = resp.json().get("threat") or {}
        verdict = ",".join(threat.get("threatTypes") or [])
    except (httpx.HTTPError, ValueError) as exc:
        log.warning("webrisk lookup failed", extra={"error": type(exc).__name__})
        return None
    await redis.set(key, verdict, ex=CACHE_TTL)
    return verdict
