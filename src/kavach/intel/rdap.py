"""Domain age via RDAP (the structured successor of WHOIS; free, no key).

rdap.org bootstraps to the right registry. Results are cached in Redis for 7 days.
"""

import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from redis.asyncio import Redis

from kavach.detectors.types import Finding, Reason

log = logging.getLogger(__name__)

CACHE_TTL = 7 * 24 * 3600
UNKNOWN_TTL = 24 * 3600


def registration_date(data: dict[str, Any]) -> datetime | None:
    for event in data.get("events") or []:
        if event.get("eventAction") == "registration" and event.get("eventDate"):
            try:
                return datetime.fromisoformat(str(event["eventDate"]).replace("Z", "+00:00"))
            except ValueError:
                return None
    return None


async def domain_age_days(
    domain: str, redis: Redis, http: httpx.AsyncClient, base: str = "https://rdap.org"
) -> int | None:
    key = f"rdap:created:{domain}"
    cached = await redis.get(key)
    if cached is not None:
        value = cached.decode() if isinstance(cached, bytes) else str(cached)
        created = None if value == "unknown" else datetime.fromisoformat(value)
    else:
        created = None
        try:
            # Fixed, trusted bootstrap host; it redirects to the registry's RDAP server.
            resp = await http.get(
                f"{base}/domain/{domain}",
                follow_redirects=True,
                timeout=6,
                headers={"Accept": "application/rdap+json"},
            )
            if resp.status_code == 200:
                created = registration_date(resp.json())
        except (httpx.HTTPError, ValueError) as exc:
            log.info("rdap lookup failed", extra={"error": type(exc).__name__})
        await redis.set(
            key,
            created.isoformat() if created else "unknown",
            ex=CACHE_TTL if created else UNKNOWN_TTL,
        )
    if created is None:
        return None
    return max(0, (datetime.now(UTC) - created).days)


def age_findings(domain: str, age_days: int | None) -> list[Finding]:
    if age_days is None:
        return []
    if age_days < 7:
        return [Finding(Reason.NEW_DOMAIN, 4, str(age_days))]
    if age_days < 30:
        return [Finding(Reason.NEW_DOMAIN, 3, str(age_days))]
    if age_days < 90:
        return [Finding(Reason.NEW_DOMAIN, 1, str(age_days))]
    return []
