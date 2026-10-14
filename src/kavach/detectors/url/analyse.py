"""URL pipeline (cheap first, TDS §8.1): allowlist → OpenPhish → own reputation DB → lexical.
M2 adds unshortening, domain age and the sandbox for whatever is still unknown."""

from redis.asyncio import Redis

from kavach.detectors.types import Finding, Reason
from kavach.detectors.url.extract import ParsedUrl
from kavach.detectors.url.lexical import lexical_findings
from kavach.intel import openphish
from kavach.intel.allowlist import is_shared_host
from kavach.reputation.store import EntityRef, Store


def url_refs(pu: ParsedUrl) -> list[EntityRef]:
    refs = [EntityRef("url", pu.url), EntityRef("host", pu.host)]
    if not is_shared_host(pu.registered_domain):
        refs.append(EntityRef("domain", pu.registered_domain))
    return refs


async def analyse_urls(urls: list[ParsedUrl], redis: Redis, store: Store) -> list[Finding]:
    findings: list[Finding] = []
    reps = await store.lookup(ref for pu in urls for ref in url_refs(pu))
    for pu in urls:
        lexical = lexical_findings(pu)
        if any(f.reason is Reason.OFFICIAL_DOMAIN for f in lexical):
            findings.extend(lexical)
            continue
        if await openphish.check(redis, pu):
            findings.append(Finding(Reason.OPENPHISH_LISTED, 10, pu.host, decisive=True))
            await store.mark(EntityRef("host", pu.host), "scam", 10, "openphish")
        verdicts = [reps[r.sha256].verdict for r in url_refs(pu) if r.sha256 in reps]
        if "scam" in verdicts:
            findings.append(Finding(Reason.REPUTATION_SCAM, 10, pu.host, decisive=True))
        elif "suspicious" in verdicts:
            findings.append(Finding(Reason.REPUTATION_SUSPICIOUS, 4, pu.host))
        findings.extend(lexical)
    return findings
