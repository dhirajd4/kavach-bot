"""Fingerprint of everything that can change a verdict or reply text.

Part of the reply-cache key: deploying any rule, weight, template or allowlist change makes
old cached replies unreachable at once, instead of serving stale verdicts for hours.
"""

import hashlib
from functools import lru_cache
from pathlib import Path

_PKG = Path(__file__).resolve().parent
_PARTS = ("detectors", "verdict", "intel", "media", "sandbox/analyse.py", "pipeline.py", "data")


@lru_cache(maxsize=1)
def rules_version() -> str:
    h = hashlib.sha256()
    for part in _PARTS:
        path = _PKG / part
        files = sorted(path.rglob("*")) if path.is_dir() else [path]
        for f in files:
            if f.is_file() and f.suffix in {".py", ".txt"}:
                h.update(str(f.relative_to(_PKG)).encode())
                h.update(f.read_bytes())
    return h.hexdigest()[:12]
