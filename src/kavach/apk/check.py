"""APK check: file-hash reputation → static facts from the sandbox → rules → same verdict path.

The APK bytes go only to the isolated sandbox; the worker never parses them. Nothing is
installed or executed anywhere.
"""

import logging

from redis.asyncio import Redis

from kavach.apk.analyse import ApkFacts, apk_findings
from kavach.detectors.types import Finding, Reason
from kavach.detectors.url.analyse import DeepContext
from kavach.hashing import sha256_hex
from kavach.pipeline import TextResult, analyse_text
from kavach.reputation.store import EntityRef, Store

log = logging.getLogger(__name__)

MARK_SUSPICIOUS_AT = 12.0  # our own static analysis: mark 'suspicious' (never 'scam')


async def analyse_apk(
    data: bytes,
    caption: str,
    filename: str,
    redis: Redis,
    store: Store,
    deep: DeepContext | None,
) -> TextResult:
    sha = sha256_hex(data)
    ref = EntityRef("apk", sha)
    findings: list[Finding] = []

    rep = (await store.lookup([ref])).get(ref.sha256)
    if rep is not None and rep.verdict == "scam":
        findings.append(Finding(Reason.REPUTATION_SCAM, 10, f"APK {sha[:12]}…", decisive=True))

    raw = await deep.sandbox.inspect_apk(data) if deep and deep.sandbox else None
    if raw is not None:
        findings += apk_findings(ApkFacts.from_dict(raw))
    else:
        # Sandbox unavailable: still never call an app file safe.
        findings.append(Finding(Reason.APK_FILE, 3, filename or "app file"))

    result = await analyse_text(
        caption, redis, store, deep, extra_findings=findings, force_content=True
    )
    result.refs.append(ref)
    if result.decision.score >= MARK_SUSPICIOUS_AT and not (rep and rep.verdict == "scam"):
        await store.mark(ref, "suspicious", result.decision.score, "static")
    log.info("apk checked", extra={"score": result.decision.score, "parsed": raw is not None})
    return result
