"""URL pipeline, cheap first (TDS §8.1).

Cheap (no network, every link): allowlist → OpenPhish → own reputation DB → lexical →
look-alike → URL features.
Deep (only for links still unresolved, at most `max_deep_urls`, within a time budget):
unshorten in the sandbox → re-check the final URL → domain age (RDAP) + Web Risk + sandbox
page visit, run concurrently.
"""

import asyncio
import logging
from dataclasses import dataclass, field

import httpx
from redis.asyncio import Redis

from kavach.config import Settings
from kavach.detectors.types import Finding, Reason
from kavach.detectors.url.extract import ParsedUrl, parse_url
from kavach.detectors.url.features import feature_findings
from kavach.detectors.url.lexical import lexical_findings
from kavach.detectors.url.lookalike import lookalike_findings
from kavach.intel import openphish, rdap, webrisk
from kavach.intel.allowlist import is_official, is_shared_host
from kavach.reputation.store import EntityRef, RepRecord, Store
from kavach.sandbox.analyse import page_findings
from kavach.sandbox.client import Sandbox

log = logging.getLogger(__name__)


@dataclass
class DeepContext:
    """Network-backed checks. None → cheap checks only (offline eval, unit tests)."""

    settings: Settings
    http: httpx.AsyncClient
    sandbox: Sandbox | None


@dataclass
class UrlAnalysis:
    findings: list[Finding] = field(default_factory=list)
    final_urls: list[ParsedUrl] = field(default_factory=list)  # where links really lead
    screenshot: bytes = b""


def url_refs(pu: ParsedUrl) -> list[EntityRef]:
    refs = [EntityRef("url", pu.url), EntityRef("host", pu.host)]
    if not is_shared_host(pu.registered_domain):
        refs.append(EntityRef("domain", pu.registered_domain))
    return refs


async def _cheap(
    pu: ParsedUrl, redis: Redis, store: Store, reps: dict[str, RepRecord]
) -> list[Finding]:
    lexical = lexical_findings(pu)
    if any(f.reason is Reason.OFFICIAL_DOMAIN for f in lexical):
        return lexical
    out: list[Finding] = []
    if await openphish.check(redis, pu):
        out.append(Finding(Reason.OPENPHISH_LISTED, 10, pu.host, decisive=True))
        await store.mark(EntityRef("host", pu.host), "scam", 10, "openphish")
    verdicts = [reps[r.sha256].verdict for r in url_refs(pu) if r.sha256 in reps]
    if "scam" in verdicts:
        out.append(Finding(Reason.REPUTATION_SCAM, 10, pu.host, decisive=True))
    elif "suspicious" in verdicts:
        out.append(Finding(Reason.REPUTATION_SUSPICIOUS, 4, pu.host))
    return out + lexical + lookalike_findings(pu) + feature_findings(pu)


def _official(findings: list[Finding]) -> bool:
    return any(f.reason is Reason.OFFICIAL_DOMAIN for f in findings)


def _decisive(findings: list[Finding]) -> bool:
    return any(f.decisive for f in findings)


async def analyse_urls(
    urls: list[ParsedUrl], redis: Redis, store: Store, deep: DeepContext | None = None
) -> UrlAnalysis:
    reps = await store.lookup(ref for pu in urls for ref in url_refs(pu))
    per_url = [await _cheap(pu, redis, store, reps) for pu in urls]
    result = UrlAnalysis(final_urls=list(urls))

    if deep is not None:
        todo = [i for i, f in enumerate(per_url) if not _official(f) and not _decisive(f)]
        todo = todo[: deep.settings.max_deep_urls]
        if todo:
            try:
                deep_results = await asyncio.wait_for(
                    asyncio.gather(*(_deep(urls[i], redis, store, deep) for i in todo)),
                    timeout=deep.settings.deep_check_budget_seconds,
                )
            except TimeoutError:
                log.warning("deep checks over budget; replying with cheap findings")
                deep_results = []
            for i, (findings, final, shot) in zip(todo, deep_results, strict=False):
                if _official(findings):
                    per_url[i] = findings  # e.g. a bit.ly that lands on hdfcbank.com
                else:
                    per_url[i] = per_url[i] + findings
                result.final_urls[i] = final
                if shot and not result.screenshot:
                    result.screenshot = shot

    result.findings = [f for fs in per_url for f in fs]
    return result


async def _deep(
    pu: ParsedUrl, redis: Redis, store: Store, ctx: DeepContext
) -> tuple[list[Finding], ParsedUrl, bytes]:
    out: list[Finding] = []
    final = pu
    sandbox = ctx.sandbox

    # 1. Where does the link really go? (HTTP redirects, fetched inside the sandbox)
    if sandbox is not None:
        exp = await sandbox.expand(pu.url)
        if exp is not None:
            if exp.apk_download:
                out.append(Finding(Reason.PAGE_DOWNLOADS_APK, 5, pu.host))
            landed = parse_url(exp.final_url) if exp.final_url else None
            if landed is not None and landed.registered_domain != pu.registered_domain:
                final = landed
                findings, stop = await _hop(pu, landed, redis, store)
                out += findings
                if stop:
                    return out, final, b""

    # 2. Domain age, Web Risk and the page itself, concurrently.
    age_task = (
        rdap.domain_age_days(final.registered_domain, redis, ctx.http, ctx.settings.rdap_base)
        if not is_shared_host(final.registered_domain)
        else _none()
    )
    wr_key = ctx.settings.webrisk_api_key.get_secret_value()
    wr_task = webrisk.lookup(final.url, wr_key, redis, ctx.http) if wr_key else _none()
    page_task = sandbox.visit(final.url) if sandbox is not None else _none()
    age, threat, page = await asyncio.gather(age_task, wr_task, page_task)

    out += rdap.age_findings(final.registered_domain, age)
    if threat:
        out.append(Finding(Reason.WEBRISK_LISTED, 10, final.host, decisive=True))
    shot = b""
    if page is not None and not page.error:
        # JavaScript redirects only show up in the real browser visit.
        js_landed = parse_url(page.final_url)
        if js_landed is not None and js_landed.registered_domain != final.registered_domain:
            findings, stop = await _hop(final, js_landed, redis, store)
            out += findings
            final = js_landed
            if stop:
                return out, final, b""
        found = page_findings(page)
        out += found
        if any(f.weight > 0 for f in found):
            shot = page.screenshot
        if any(f.reason is Reason.PAGE_IMPERSONATES_BRAND for f in found):
            # Our own analysis, not a user report: mark suspicious (never 'scam') so the next
            # lookup is instant; analysts confirm before it becomes a scam verdict.
            await store.mark(EntityRef("host", final.host), "suspicious", 9, "sandbox")
    elif page is not None and page.apk_download:
        out.append(Finding(Reason.PAGE_DOWNLOADS_APK, 5, final.host))
    return out, final, shot


async def _hop(
    src: ParsedUrl, dst: ParsedUrl, redis: Redis, store: Store
) -> tuple[list[Finding], bool]:
    """Findings for a redirect src → dst. Returns (findings, stop_further_checks)."""
    if is_official(dst.host, dst.registered_domain):
        return [Finding(Reason.OFFICIAL_DOMAIN, 0, dst.registered_domain)], True
    reps = await store.lookup(url_refs(dst))
    findings = [Finding(Reason.REDIRECT_CHAIN, 1, f"{src.host} → {dst.host}")]
    findings += await _cheap(dst, redis, store, reps)
    return findings, _decisive(findings)


async def _none() -> None:
    return None
