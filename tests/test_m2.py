"""M2: URL depth: SSRF guard, unshortening, look-alikes, features, RDAP, Web Risk, sandbox."""

import asyncio
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from kavach.config import Settings
from kavach.detectors.types import Finding, Reason
from kavach.detectors.url.analyse import DeepContext, analyse_urls
from kavach.detectors.url.extract import extract_urls, parse_url
from kavach.detectors.url.features import feature_findings
from kavach.detectors.url.lookalike import lookalike_of
from kavach.intel import rdap, webrisk
from kavach.pipeline import analyse_text
from kavach.sandbox.analyse import page_findings, secrets_requested
from kavach.sandbox.client import Expansion, PageFacts, PageInput
from kavach.sandbox.expand import expand
from kavach.sandbox.netguard import BlockedURL, check_url, is_public_ip
from kavach.verdict.rules import Verdict, decide
from kavach.workers.checker import Checker


def pu(url: str):  # type: ignore[no-untyped-def]
    parsed = parse_url(url)
    assert parsed is not None
    return parsed


async def public_resolver(host: str) -> list[str]:
    return {"internal.evil": ["10.0.0.5"], "meta.evil": ["169.254.169.254"]}.get(
        host, ["93.184.216.34"]
    )


# --- SSRF guard -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.17.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fd00::1",
        "0.0.0.0",
        "::ffff:127.0.0.1",
        "224.0.0.1",
    ],
)
def test_non_public_ips_blocked(ip: str) -> None:
    assert not is_public_ip(ip)


def test_public_ip_allowed() -> None:
    assert is_public_ip("93.184.216.34") and is_public_ip("2606:4700::1111")


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://x.com/a",
        "http://localhost/",
        "http://127.0.0.1/",
        "http://internal.evil/",
        "http://meta.evil/latest/meta-data",
        "http://x.com:6379/",
        "http://redis.internal/",
        "gopher://x.com/",
    ],
)
async def test_check_url_blocks(url: str) -> None:
    with pytest.raises(BlockedURL):
        await check_url(url, public_resolver)


async def test_check_url_allows_public() -> None:
    assert await check_url("https://example.com/login", public_resolver) == "example.com"


# --- unshortening ----------------------------------------------------------------------


@respx.mock
async def test_expand_follows_redirect_chain() -> None:
    respx.get("https://bit.ly/abc").mock(
        return_value=httpx.Response(301, headers={"location": "https://t.co/x"})
    )
    respx.get("https://t.co/x").mock(
        return_value=httpx.Response(302, headers={"location": "/landing"})
    )
    respx.get("https://t.co/landing").mock(
        return_value=httpx.Response(302, headers={"location": "http://sbi-kyc.xyz/login"})
    )
    respx.get("http://sbi-kyc.xyz/login").mock(return_value=httpx.Response(200, text="hi"))
    async with httpx.AsyncClient() as http:
        r = await expand("https://bit.ly/abc", http, public_resolver)
    assert r.final_url == "http://sbi-kyc.xyz/login" and len(r.chain) == 4 and not r.error


@respx.mock
async def test_expand_stops_at_internal_hop() -> None:
    respx.get("https://bit.ly/ssrf").mock(
        return_value=httpx.Response(302, headers={"location": "http://meta.evil/latest"})
    )
    async with httpx.AsyncClient() as http:
        r = await expand("https://bit.ly/ssrf", http, public_resolver)
    assert r.error.startswith("blocked") and r.final_url == "http://meta.evil/latest"
    assert len(respx.calls) == 1  # never fetched the internal address


@respx.mock
async def test_expand_detects_apk_and_loops() -> None:
    respx.get("https://dl.example/app").mock(
        return_value=httpx.Response(
            200, headers={"content-type": "application/vnd.android.package-archive"}
        )
    )
    respx.get("https://loop.example/").mock(
        return_value=httpx.Response(302, headers={"location": "https://loop.example/"})
    )
    async with httpx.AsyncClient() as http:
        apk = await expand("https://dl.example/app", http, public_resolver)
        loop = await expand("https://loop.example/", http, public_resolver)
    assert apk.apk_download and loop.error == "too many redirects"


# --- look-alikes & features ------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "target"),
    [
        ("hdfcbnak.com", "hdfcbank.com"),
        ("hdfcbank.co", "hdfcbank.com"),
        ("paytrn.com", "paytm.com"),
        ("flipkarrt.com", "flipkart.com"),
        ("icicbank.com", "icicibank.com"),
    ],
)
def test_lookalike_hits(url: str, target: str) -> None:
    assert lookalike_of(pu(url)) == target


@pytest.mark.parametrize(
    "url", ["hdfcbank.com", "twiggy.com", "amazing.com", "example.com", "sites.google.com"]
)
def test_lookalike_misses(url: str) -> None:
    assert lookalike_of(pu(url)) == ""


def test_url_features() -> None:
    risky = feature_findings(pu("http://secure-login-verify-account.xyz/kyc/update"))
    assert risky and risky[0].reason is Reason.URL_LEXICAL_RISK
    assert feature_findings(pu("https://www.example.com/blog/post")) == []
    assert feature_findings(pu("https://www.hdfcbank.com/login/verify/update")) == []


# --- RDAP & Web Risk ------------------------------------------------------------------


@respx.mock
async def test_rdap_age_and_cache(redis) -> None:  # type: ignore[no-untyped-def]
    created = (datetime.now(UTC) - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    route = respx.get("https://rdap.org/domain/new-scam.xyz").mock(
        return_value=httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": created}]}
        )
    )
    async with httpx.AsyncClient() as http:
        assert await rdap.domain_age_days("new-scam.xyz", redis, http) == 3
        assert await rdap.domain_age_days("new-scam.xyz", redis, http) == 3
    assert route.call_count == 1
    (f,) = rdap.age_findings("new-scam.xyz", 3)
    assert f.reason is Reason.NEW_DOMAIN and f.weight == 4
    assert rdap.age_findings("old.com", 400) == []


@respx.mock
async def test_rdap_unknown_is_neutral(redis) -> None:  # type: ignore[no-untyped-def]
    respx.get("https://rdap.org/domain/x.in").mock(return_value=httpx.Response(404))
    async with httpx.AsyncClient() as http:
        assert await rdap.domain_age_days("x.in", redis, http) is None


@respx.mock
async def test_webrisk(redis) -> None:  # type: ignore[no-untyped-def]
    respx.get(url__startswith=webrisk.ENDPOINT).mock(
        return_value=httpx.Response(200, json={"threat": {"threatTypes": ["SOCIAL_ENGINEERING"]}})
    )
    async with httpx.AsyncClient() as http:
        assert await webrisk.lookup("http://bad.xyz/", "", redis, http) is None  # disabled
        assert await webrisk.lookup("http://bad.xyz/", "k", redis, http) == "SOCIAL_ENGINEERING"


# --- page classification --------------------------------------------------------------


LOGIN = [
    PageInput(type="text", name="userid", placeholder="customer id"),
    PageInput(type="password", name="pwd"),
    PageInput(type="tel", name="otp", placeholder="enter otp"),
]


def test_phishing_page_findings() -> None:
    facts = PageFacts(
        final_url="https://sbi-yono-kyc.xyz/login",
        title="State Bank of India - YONO Login",
        inputs=LOGIN,
    )
    reasons = {f.reason: f for f in page_findings(facts)}
    assert Reason.PAGE_ASKS_CREDENTIALS in reasons and Reason.PAGE_IMPERSONATES_BRAND in reasons
    assert "OTP" in reasons[Reason.PAGE_ASKS_CREDENTIALS].evidence
    assert reasons[Reason.PAGE_IMPERSONATES_BRAND].evidence == "SBI"


def test_brand_without_form_is_not_impersonation() -> None:
    facts = PageFacts(
        final_url="https://newsblog.example/sbi-results",
        title="SBI announces quarterly results",
        text="State Bank of India...",
    )
    assert page_findings(facts) == []


def test_official_page_is_official() -> None:
    facts = PageFacts(
        final_url="https://retail.onlinesbi.sbi/retail/login.htm",
        title="State Bank of India",
        inputs=LOGIN,
    )
    assert [f.reason for f in page_findings(facts)] == [Reason.OFFICIAL_DOMAIN]


def test_secret_fields_detection() -> None:
    inputs = [
        PageInput(autocomplete="cc-number"),
        PageInput(name="cvv"),
        PageInput(label="aadhaar number"),
        PageInput(name="email"),
    ]
    assert secrets_requested(inputs) == ["card number", "CVV", "Aadhaar"]


# --- deep pipeline with a fake sandbox ------------------------------------------------


class FakeSandbox:
    def __init__(
        self, expansions: dict[str, str], pages: dict[str, PageFacts], delay: float = 0
    ) -> None:
        self.expansions, self.pages, self.delay = expansions, pages, delay
        self.visits: list[str] = []

    async def expand(self, url: str) -> Expansion | None:
        await asyncio.sleep(self.delay)
        final = self.expansions.get(url, url)
        return Expansion(chain=[url, final] if final != url else [url], final_url=final)

    async def visit(self, url: str) -> PageFacts | None:
        self.visits.append(url)
        return self.pages.get(url, PageFacts(final_url=url))


def deep_ctx(sandbox: FakeSandbox, **overrides) -> DeepContext:  # type: ignore[no-untyped-def]
    settings = Settings(_env_file=None, **overrides)  # type: ignore[call-arg]
    return DeepContext(settings=settings, http=httpx.AsyncClient(), sandbox=sandbox)


@respx.mock
async def test_short_link_to_official_site_is_safe(redis, store) -> None:  # type: ignore[no-untyped-def]
    respx.get(url__startswith="https://rdap.org/").mock(return_value=httpx.Response(404))
    sb = FakeSandbox({"https://bit.ly/hdfc": "https://www.hdfcbank.com/personal"}, {})
    result = await analyse_text("Offer details: https://bit.ly/hdfc", redis, store, deep_ctx(sb))
    assert result.decision.verdict is Verdict.LOOKS_SAFE or result.decision.score < 3
    assert sb.visits == []  # official landing: no page visit needed
    assert "hdfcbank.com" in result.domains


@respx.mock
async def test_short_link_to_phishing_page_is_scam_with_screenshot(redis, store) -> None:  # type: ignore[no-untyped-def]
    respx.get(url__startswith="https://rdap.org/").mock(return_value=httpx.Response(404))
    landing = "https://yono-update.online/login"
    sb = FakeSandbox(
        {"https://bit.ly/yono": landing},
        {landing: PageFacts(final_url=landing, title="SBI YONO", inputs=LOGIN, screenshot=b"JPEG")},
    )
    result = await analyse_text("Aapka YONO band: https://bit.ly/yono", redis, store, deep_ctx(sb))
    codes = set(result.decision.reason_codes)
    assert result.decision.verdict is Verdict.SCAM
    assert {"REDIRECT_CHAIN", "PAGE_ASKS_CREDENTIALS", "PAGE_IMPERSONATES_BRAND"} <= codes
    assert result.screenshot == b"JPEG"
    # our own analysis marks the host suspicious for next time (never 'scam')
    assert any(r.verdict == "suspicious" for r in store.reputation.values())


@respx.mock
async def test_new_domain_raises_score(redis, store) -> None:  # type: ignore[no-untyped-def]
    created = (datetime.now(UTC) - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    respx.get("https://rdap.org/domain/fresh-offer.shop").mock(
        return_value=httpx.Response(
            200, json={"events": [{"eventAction": "registration", "eventDate": created}]}
        )
    )
    sb = FakeSandbox({}, {})
    result = await analyse_text("dekho https://fresh-offer.shop/deal", redis, store, deep_ctx(sb))
    assert "NEW_DOMAIN" in result.decision.reason_codes
    assert result.decision.verdict is Verdict.SUSPICIOUS


@respx.mock
async def test_deep_budget_exceeded_falls_back_to_cheap(redis, store) -> None:  # type: ignore[no-untyped-def]
    sb = FakeSandbox({}, {}, delay=2)
    ctx = deep_ctx(sb, deep_check_budget_seconds=0.2)
    result = await analyse_text("http://sbi-kyc-update.xyz/login", redis, store, ctx)
    assert result.decision.verdict is Verdict.SCAM  # cheap findings alone are enough here
    assert "NEW_DOMAIN" not in result.decision.reason_codes


async def test_official_and_decisive_links_skip_deep(redis, store) -> None:  # type: ignore[no-untyped-def]
    sb = FakeSandbox({}, {})
    urls = extract_urls("https://www.hdfcbank.com/a and https://www.irctc.co.in/b")
    await analyse_urls(urls, redis, store, deep_ctx(sb))
    assert sb.visits == []


def test_same_reason_counted_once() -> None:
    f = [
        Finding(Reason.RISKY_TLD, 1, "a.xyz"),
        Finding(Reason.RISKY_TLD, 1, "b.xyz"),
        Finding(Reason.BRAND_IMPERSONATION, 4, "x"),
        Finding(Reason.BRAND_IMPERSONATION, 4, "y"),
    ]
    assert decide(f, had_content=True, urls_checked=2).score == 5


# --- one rich reply ------------------------------------------------------------------


@respx.mock
async def test_checker_sends_screenshot_as_single_image_message(  # type: ignore[no-untyped-def]
    settings, redis, store, messenger
) -> None:
    respx.get(url__startswith="https://rdap.org/").mock(return_value=httpx.Response(404))
    landing = "https://sbi-rewards.top/claim"
    sb = FakeSandbox(
        {},
        {
            landing: PageFacts(
                final_url=landing, title="SBI Rewards", inputs=LOGIN, screenshot=b"JPEG"
            )
        },
    )
    checker = Checker(settings, redis, store, messenger, deep=deep_ctx(sb))
    job = {
        "kind": "text",
        "message_id": "wamid.s",
        "wa_id": "91980",
        "user_hash": "u",
        "text": f"Claim points {landing}",
        "media_id": "",
        "language": "en",
        "first_time": "0",
        "input_hash": "h1",
        "received_at": "0",
    }
    await checker.process(job)
    assert messenger.sent == [] and len(messenger.images) == 1
    (_, image, caption, reply_to) = messenger.images[0]
    assert image == b"JPEG" and "SCAM" in caption and reply_to == "wamid.s"
    assert len(caption) <= 1024


@respx.mock
async def test_checker_falls_back_to_text_when_caption_too_long(  # type: ignore[no-untyped-def]
    settings, redis, store, messenger, monkeypatch
) -> None:
    monkeypatch.setattr("kavach.workers.checker.MAX_CAPTION", 100)
    respx.get(url__startswith="https://rdap.org/").mock(return_value=httpx.Response(404))
    landing = "https://sbi-rewards.top/claim"
    sb = FakeSandbox(
        {},
        {
            landing: PageFacts(
                final_url=landing, title="SBI Rewards", inputs=LOGIN, screenshot=b"JPEG"
            )
        },
    )
    checker = Checker(settings, redis, store, messenger, deep=deep_ctx(sb))
    job = {
        "kind": "text",
        "message_id": "wamid.t",
        "wa_id": "91980",
        "user_hash": "u",
        "text": f"Claim points {landing}",
        "media_id": "",
        "language": "hinglish",
        "first_time": "1",
        "input_hash": "h2",
        "received_at": "0",
    }  # welcome makes it long
    await checker.process(job)
    assert len(messenger.sent) == 1 and messenger.images == []


def test_plain_login_is_weak_financial_secrets_strong() -> None:
    plain = PageFacts(
        final_url="https://github.com/login",
        inputs=[PageInput(name="login"), PageInput(type="password")],
    )
    (f,) = page_findings(plain)
    assert f.reason is Reason.PAGE_ASKS_CREDENTIALS and f.weight == 2
    money = PageFacts(final_url="https://pay-verify.example/x", inputs=[PageInput(name="cvv")])
    assert page_findings(money)[0].weight == 4


def test_radio_buttons_and_one_time_donations_are_not_otp() -> None:
    wiki = [
        PageInput(type="radio", name="frequency", label="one time"),
        PageInput(type="search", name="search", placeholder="search wikipedia"),
    ]
    assert secrets_requested(wiki) == []
    assert secrets_requested([PageInput(label="one-time password")]) == ["OTP"]
