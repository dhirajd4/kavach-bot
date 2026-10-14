from kavach.detectors.types import Finding, Reason
from kavach.llm.base import Explanation
from kavach.verdict.composer import explain, render
from kavach.verdict.language import detect_language, language_command
from kavach.verdict.rules import Verdict, decide


def test_decisive_finding_is_scam() -> None:
    d = decide(
        [Finding(Reason.OPENPHISH_LISTED, 10, "x.xyz", decisive=True)],
        had_content=True,
        urls_checked=1,
    )
    assert d.verdict is Verdict.SCAM


def test_thresholds() -> None:
    weak = [Finding(Reason.URGENCY, 1, "turant")]
    mid = [Finding(Reason.KYC_BLOCK, 2), Finding(Reason.URGENCY, 1)]
    high = [
        Finding(Reason.OTP_REQUEST, 4),
        Finding(Reason.KYC_BLOCK, 2),
        Finding(Reason.URGENCY, 1),
    ]
    assert decide(weak, had_content=True, urls_checked=0).verdict is Verdict.NO_RISK_FOUND
    assert decide(mid, had_content=True, urls_checked=0).verdict is Verdict.SUSPICIOUS
    assert decide(high, had_content=True, urls_checked=0).verdict is Verdict.SCAM


def test_looks_safe_only_when_all_links_official() -> None:
    off = [Finding(Reason.OFFICIAL_DOMAIN, 0, "hdfcbank.com")]
    assert decide(off, had_content=True, urls_checked=1).verdict is Verdict.LOOKS_SAFE
    assert decide(off, had_content=True, urls_checked=2).verdict is Verdict.NO_RISK_FOUND


def test_nothing_to_check() -> None:
    assert decide([], had_content=False, urls_checked=0).verdict is Verdict.NOTHING_TO_CHECK


async def test_render_one_message_with_reasons_and_1930() -> None:
    d = decide(
        [Finding(Reason.OTP_REQUEST, 4), Finding(Reason.KYC_BLOCK, 3)],
        had_content=True,
        urls_checked=0,
    )
    for lang in ("hi", "hinglish", "en"):
        exp = await explain(d, lang, None)
        body = render(d, exp, lang, first_time=False)
        assert "1930" in body and len(exp.lines) == 2 and len(body) < 4096


async def test_llm_failure_falls_back_to_templates() -> None:
    class Broken:
        name = "broken"

        async def explain(self, decision, language):  # type: ignore[no-untyped-def]
            raise RuntimeError("down")

    d = decide([Finding(Reason.OTP_REQUEST, 4)], had_content=True, urls_checked=0)
    exp = await explain(d, "en", Broken())
    assert exp.provider == "template" and exp.lines


async def test_llm_used_when_it_answers() -> None:
    class Good:
        name = "good"

        async def explain(self, decision, language):  # type: ignore[no-untyped-def]
            return Explanation(["custom line"], "good")

    d = decide([Finding(Reason.OTP_REQUEST, 4)], had_content=True, urls_checked=0)
    assert (await explain(d, "en", Good())).lines == ["custom line"]


def test_language_detection_and_commands() -> None:
    assert detect_language("आप डिजिटल अरेस्ट में हैं") == "hi"
    assert detect_language("aap ka account band ho jayega") == "hinglish"
    assert detect_language("Your account will be blocked") == "en"
    assert language_command(" English ") == "en"
    assert language_command("हिंदी") == "hi"
    assert language_command("hello") is None
