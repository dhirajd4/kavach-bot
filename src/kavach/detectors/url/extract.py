"""Pull URLs, UPI IDs and Indian phone numbers out of free text."""

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

import tldextract

# Bundled public-suffix snapshot only: no network fetch at runtime.
_TLD = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

MAX_URLS = 5

_URL_RE = re.compile(
    r"(?<![@\w.])(?:(?:https?://)|(?:www\.))[^\s<>\"'`]+"
    r"|(?<![@\w.\-/])(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?:/[^\s<>\"'`]*)?",
    re.IGNORECASE,
)
_TRAILING = ".,;:!?)]}>'\"`…।"
_UPI_RE = re.compile(r"(?<![\w.\-])([a-z0-9][\w.\-]{1,255}@[a-z][a-z0-9]{1,63})(?![\w.@])", re.I)
_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[\s\-]?|0)?([6-9]\d{4}[\s\-]?\d{5})(?!\d)")


@dataclass(frozen=True, slots=True)
class ParsedUrl:
    url: str  # normalised, with scheme
    host: str
    registered_domain: str  # e.g. sbi.co.in
    subdomain: str
    suffix: str
    scheme: str
    explicit_scheme: bool  # False for bare "sbi-kyc.xyz/abc" style mentions


def parse_url(raw: str) -> ParsedUrl | None:
    candidate = raw.strip().rstrip(_TRAILING)
    explicit = bool(re.match(r"^https?://", candidate, re.I))
    if not explicit:
        candidate = "http://" + candidate
    try:
        parts = urlsplit(candidate)
    except ValueError:
        return None
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return None
    ext = _TLD(host)
    if not ext.suffix and not _is_ip(host):
        return None  # "file.txt", "e.g." and other non-domains
    registered = ext.top_domain_under_public_suffix or host
    netloc = host + (f":{parts.port}" if parts.port else "")
    path = parts.path or "/"
    url = f"{parts.scheme.lower()}://{netloc}{path}" + (f"?{parts.query}" if parts.query else "")
    return ParsedUrl(
        url=url,
        host=host,
        registered_domain=registered,
        subdomain=ext.subdomain,
        suffix=ext.suffix,
        scheme=parts.scheme.lower(),
        explicit_scheme=explicit,
    )


def extract_urls(text: str) -> list[ParsedUrl]:
    seen: set[str] = set()
    out: list[ParsedUrl] = []
    for m in _URL_RE.finditer(text):
        parsed = parse_url(m.group(0))
        if parsed and parsed.url not in seen:
            seen.add(parsed.url)
            out.append(parsed)
        if len(out) >= MAX_URLS:
            break
    return out


def extract_upi_ids(text: str) -> list[str]:
    return sorted({m.group(1).lower() for m in _UPI_RE.finditer(text)})


def extract_phones(text: str) -> list[str]:
    """Normalised to +91XXXXXXXXXX. Only ever stored hashed."""
    return sorted({"+91" + re.sub(r"\D", "", m.group(1)) for m in _PHONE_RE.finditer(text)})


_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _is_ip(host: str) -> bool:
    return bool(_IPV4.match(host)) or ":" in host
