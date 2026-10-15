"""SSRF guard for fetching user-supplied URLs.

Every host is resolved first and must resolve ONLY to public (globally routable) addresses.
Blocks loopback, private ranges, link-local and cloud metadata (169.254.169.254), CGNAT,
the Docker host gateway, IPv6 ULA and so on, plus non-web schemes and ports.
"""

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from urllib.parse import urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({None, 80, 443, 8080, 8443})

Resolver = Callable[[str], Awaitable[list[str]]]


class BlockedURL(ValueError):
    pass


async def resolve(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


async def check_url(url: str, resolver: Resolver = resolve) -> str:
    """Return the hostname if the URL is safe to fetch, else raise BlockedURL."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise BlockedURL("malformed url") from exc
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise BlockedURL(f"scheme {parts.scheme!r} not allowed")
    if port not in ALLOWED_PORTS:
        raise BlockedURL(f"port {port} not allowed")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host or host == "localhost" or host.endswith((".local", ".internal", ".localhost")):
        raise BlockedURL("internal host")
    try:
        ips = [host] if _is_ip_literal(host) else await resolver(host)
    except OSError as exc:
        raise BlockedURL("dns failure") from exc
    if not ips or not all(is_public_ip(ip) for ip in ips):
        raise BlockedURL("resolves to a non-public address")
    return host


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
