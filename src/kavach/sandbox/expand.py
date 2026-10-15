"""Follow HTTP redirects hop by hop (unshortening), checking every hop with the SSRF guard.
Runs inside the isolated sandbox container, never in the worker."""

from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from kavach.sandbox.netguard import BlockedURL, Resolver, check_url, resolve

MAX_HOPS = 5
UA = (
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Mobile Safari/537.36"
)


@dataclass
class ExpandResult:
    chain: list[str] = field(default_factory=list)  # first entry is the input URL
    final_url: str = ""
    status: int = 0
    apk_download: bool = False
    error: str = ""


async def expand(
    url: str, http: httpx.AsyncClient, resolver: Resolver = resolve, max_hops: int = MAX_HOPS
) -> ExpandResult:
    result = ExpandResult(chain=[url], final_url=url)
    current = url
    for _ in range(max_hops + 1):
        try:
            await check_url(current, resolver)
        except BlockedURL as exc:
            result.error = f"blocked: {exc}"
            return result
        try:
            async with http.stream(
                "GET", current, headers={"User-Agent": UA}, follow_redirects=False
            ) as resp:
                result.status = resp.status_code
                result.apk_download = result.apk_download or _is_apk(resp)
                location = resp.headers.get("location")
        except httpx.HTTPError as exc:
            result.error = f"fetch: {type(exc).__name__}"
            return result
        if resp.status_code in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            result.chain.append(current)
            result.final_url = current
            continue
        return result
    result.error = "too many redirects"
    return result


def _is_apk(resp: httpx.Response) -> bool:
    ctype = resp.headers.get("content-type", "").lower()
    disp = resp.headers.get("content-disposition", "").lower()
    return "android.package-archive" in ctype or ".apk" in disp
