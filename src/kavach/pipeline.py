"""Text analysis pipeline shared by the text, image (OCR) and caption paths."""

from dataclasses import dataclass, field

from redis.asyncio import Redis

from kavach.detectors.text.intents import detect_intents
from kavach.detectors.types import Finding, Reason
from kavach.detectors.url.analyse import analyse_urls, url_refs
from kavach.detectors.url.extract import extract_phones, extract_upi_ids, extract_urls
from kavach.reputation.store import EntityRef, Store
from kavach.verdict.rules import Decision, decide


@dataclass(slots=True)
class TextResult:
    decision: Decision
    domains: list[str] = field(default_factory=list)
    refs: list[EntityRef] = field(default_factory=list)


async def analyse_text(text: str, redis: Redis, store: Store) -> TextResult:
    findings: list[Finding] = detect_intents(text)
    urls = extract_urls(text)
    findings += await analyse_urls(urls, redis, store)

    contact_refs = [EntityRef("upi", u) for u in extract_upi_ids(text)]
    contact_refs += [EntityRef("phone", p) for p in extract_phones(text)]
    if contact_refs:
        reps = await store.lookup(contact_refs)
        for ref in contact_refs:
            rep = reps.get(ref.sha256)
            if rep and rep.verdict == "scam":
                label = "UPI ID" if ref.entity_type == "upi" else "number"
                findings.append(
                    Finding(
                        Reason.REPUTATION_SCAM, 10, f"{label} {_mask(ref.value)}", decisive=True
                    )
                )

    has_content = bool(text.strip()) and (bool(urls) or len(text.split()) >= 4 or bool(findings))
    decision = decide(findings, had_content=has_content, urls_checked=len(urls))
    refs = [r for pu in urls for r in url_refs(pu)] + contact_refs
    domains = sorted({pu.registered_domain for pu in urls})
    return TextResult(decision=decision, domains=domains, refs=refs)


def _mask(value: str) -> str:
    return value[:3] + "…" + value[-3:] if len(value) > 8 else value
