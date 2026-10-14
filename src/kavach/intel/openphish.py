"""OpenPhish community feed (free, commercial use allowed per its terms; TDS §9.2).

Stored in Redis as two sets, swapped in atomically on every sync:
  intel:openphish:urls   sha256 of normalised URLs
  intel:openphish:hosts  hostnames, excluding shared hosting platforms
"""

import logging

import httpx
from redis.asyncio import Redis

from kavach.detectors.url.extract import ParsedUrl, parse_url
from kavach.hashing import sha256_hex
from kavach.intel.allowlist import is_official, is_shared_host

log = logging.getLogger(__name__)

URLS_KEY = "intel:openphish:urls"
HOSTS_KEY = "intel:openphish:hosts"
META_KEY = "intel:openphish:meta"


def url_key(pu: ParsedUrl) -> str:
    return sha256_hex(pu.url.lower())


def build_sets(feed_text: str) -> tuple[set[str], set[str]]:
    urls: set[str] = set()
    hosts: set[str] = set()
    for line in feed_text.splitlines():
        pu = parse_url(line)
        if pu is None or is_official(pu.host, pu.registered_domain):
            continue
        urls.add(url_key(pu))
        if not is_shared_host(pu.registered_domain) and not is_shared_host(pu.host):
            hosts.add(pu.host)
    return urls, hosts


async def sync(redis: Redis, http: httpx.AsyncClient, feed_url: str) -> int:
    # The shared client never follows redirects (user links); the feed host does redirect
    # (openphish.com → raw.githubusercontent.com), and it is a fixed, trusted URL.
    resp = await http.get(
        feed_url, headers={"User-Agent": "kavach-bot/0.1 (+threat-intel)"}, follow_redirects=True
    )
    resp.raise_for_status()
    urls, hosts = build_sets(resp.text)
    if not urls:
        log.warning("openphish feed empty; keeping previous sets")
        return 0
    async with redis.pipeline(transaction=True) as pipe:
        pipe.delete(URLS_KEY + ":new", HOSTS_KEY + ":new")
        pipe.sadd(URLS_KEY + ":new", *urls)
        if hosts:
            pipe.sadd(HOSTS_KEY + ":new", *hosts)
            pipe.rename(HOSTS_KEY + ":new", HOSTS_KEY)
        pipe.rename(URLS_KEY + ":new", URLS_KEY)
        pipe.hset(META_KEY, mapping={"count": len(urls), "hosts": len(hosts)})
        await pipe.execute()
    log.info("openphish synced", extra={"urls": len(urls), "hosts": len(hosts)})
    return len(urls)


async def check(redis: Redis, pu: ParsedUrl) -> bool:
    async with redis.pipeline(transaction=False) as pipe:
        pipe.sismember(URLS_KEY, url_key(pu))
        pipe.sismember(HOSTS_KEY, pu.host)
        url_hit, host_hit = await pipe.execute()
    return bool(url_hit or host_hit)
