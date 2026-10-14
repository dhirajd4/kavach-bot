"""Hashing helpers. Raw identifiers and content never leave these functions."""

import hashlib
import hmac
import re

_WS = re.compile(r"\s+")


def sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def user_hash(wa_id: str, key: str) -> str:
    """Pseudonymous, stable user id: HMAC(key, wa_id). Not reversible without the key."""
    if not key:
        raise ValueError("USER_HASH_KEY is not set")
    return hmac.new(key.encode(), wa_id.encode(), hashlib.sha256).hexdigest()


def normalise_text(text: str) -> str:
    """Normalisation used for cache keys: forwarded copies of one scam hash the same."""
    return _WS.sub(" ", text).strip().casefold()


def content_hash(kind: str, payload: str) -> str:
    return sha256_hex(f"{kind}:{payload}")
