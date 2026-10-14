"""Meta webhook signature check.

X-Hub-Signature-256 = 'sha256=' + HMAC-SHA256(app_secret, raw_body)
"""

import hashlib
import hmac


def verify_signature(raw_body: bytes, header: str | None, app_secret: str) -> bool:
    if not header or not app_secret or not header.startswith("sha256="):
        return False
    expected = hmac.new(app_secret.encode(), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


def sign(raw_body: bytes, app_secret: str) -> str:
    """Build a header value. Used by tests and the replay harness."""
    return "sha256=" + hmac.new(app_secret.encode(), raw_body, hashlib.sha256).hexdigest()
