"""M4: APK files: zip safety, static facts (Androguard), rules, end-to-end reply.
Every APK here is generated in memory by tests/apkgen.py: code-free, nothing downloaded."""

import io
import zipfile

import pytest

from kavach.apk.analyse import ApkFacts, apk_findings
from kavach.apk.check import analyse_apk
from kavach.apk.extract import UnsafeArchive, check_zip, extract_facts, run_isolated
from kavach.detectors.types import Reason
from kavach.detectors.url.analyse import DeepContext
from kavach.orchestrator.service import Orchestrator
from kavach.reputation.store import EntityRef
from kavach.verdict.rules import Verdict
from kavach.whatsapp.payloads import InboundKind, InboundMessage
from kavach.workers.checker import Checker
from tests.apkgen import SPECS, ApkSpec, build_apk

APK_MIME = "application/vnd.android.package-archive"
APKS = {name: build_apk(spec) for name, spec in SPECS.items()}


def reasons(name: str) -> set[Reason]:
    return {f.reason for f in apk_findings(ApkFacts.from_dict(extract_facts(APKS[name])))}


# --- archive safety ----------------------------------------------------------------------


def test_not_a_zip_rejected() -> None:
    with pytest.raises(UnsafeArchive, match="not a zip"):
        check_zip(b"MZ\x90\x00 definitely not an apk")


def test_zip_without_manifest_rejected() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("hello.txt", "hi")
    with pytest.raises(UnsafeArchive, match="AndroidManifest"):
        check_zip(buf.getvalue())


def test_zip_bomb_rejected_before_parsing() -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", b"x")
        z.writestr("assets/bomb.bin", b"\x00" * (20 * 1024 * 1024))  # ~1000x ratio
    facts = extract_facts(buf.getvalue())
    assert facts["error"].startswith("unsafe") and "zip bomb" in facts["error"]


# --- facts --------------------------------------------------------------------------------


def test_extract_facts_from_generated_trojan() -> None:
    f = extract_facts(APKS["scam_sbi_kyc_update"])
    assert f["error"] == "" and f["package"] == "com.sbi.kycupdate.online"
    assert f["label"] == "SBI YONO KYC Update" and f["signed"]
    assert "android.permission.READ_SMS" in f["permissions"]
    assert any(c["permission"].endswith("BIND_ACCESSIBILITY_SERVICE") for c in f["components"])
    assert not f["has_dex"]  # our fixtures contain no code at all


async def test_run_isolated_uses_a_child_process() -> None:
    f = await run_isolated(APKS["warn_simple_calculator"])
    assert f["package"] == "org.example.calculator" and f["error"] == ""
    garbage = await run_isolated(b"not an apk")
    assert garbage["error"].startswith("unsafe")


# --- rules --------------------------------------------------------------------------------


def test_banking_trojan_pattern() -> None:
    r = reasons("scam_sbi_kyc_update")
    assert {
        Reason.APK_IMPERSONATES,
        Reason.APK_READS_SMS,
        Reason.APK_ACCESSIBILITY,
        Reason.APK_NOTIFICATION_ACCESS,
        Reason.APK_OVERLAY,
        Reason.APK_OTP_STEALER,
        Reason.APK_DEBUG_SIGNED,
    } <= r


def test_wedding_invite_lure() -> None:
    r = reasons("scam_wedding_invite")
    assert {
        Reason.APK_KNOWN_LURE,
        Reason.APK_READS_SMS,
        Reason.APK_SENDS_SMS,
        Reason.APK_OTP_STEALER,
    } <= r


def test_fake_government_app() -> None:
    r = reasons("scam_pm_kisan")
    assert {
        Reason.APK_IMPERSONATES,
        Reason.APK_DEVICE_ADMIN,
        Reason.APK_CALL_CONTROL,
        Reason.APK_INSTALLS_APPS,
    } <= r


def test_plain_app_only_gets_the_baseline() -> None:
    assert reasons("warn_simple_calculator") == {Reason.APK_FILE}


def test_unsigned_and_unreadable() -> None:
    unsigned = build_apk(ApkSpec(package="org.x.y", label="Notes"), signed=False)
    assert Reason.APK_UNSIGNED in {
        f.reason for f in apk_findings(ApkFacts.from_dict(extract_facts(unsigned)))
    }
    broken = apk_findings(ApkFacts(sha256="x", error="unsafe: not a zip archive"))
    assert {f.reason for f in broken} == {Reason.APK_FILE, Reason.APK_UNREADABLE}


# --- check flow with a fake sandbox --------------------------------------------------------


class ApkSandbox:
    def __init__(self, available: bool = True) -> None:
        self.available = available
        self.calls = 0

    async def expand(self, url: str):  # type: ignore[no-untyped-def]
        return None

    async def visit(self, url: str):  # type: ignore[no-untyped-def]
        return None

    async def inspect_apk(self, data: bytes):  # type: ignore[no-untyped-def]
        self.calls += 1
        return extract_facts(data) if self.available else None


def ctx(sandbox: ApkSandbox, settings) -> DeepContext:  # type: ignore[no-untyped-def]
    import httpx

    return DeepContext(settings=settings, http=httpx.AsyncClient(), sandbox=sandbox)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("scam_sbi_kyc_update", Verdict.SCAM),
        ("scam_wedding_invite", Verdict.SCAM),
        ("scam_pm_kisan", Verdict.SCAM),
        ("warn_simple_calculator", Verdict.SUSPICIOUS),
    ],
)
async def test_verdicts(name: str, expected: Verdict, settings, redis, store) -> None:  # type: ignore[no-untyped-def]
    r = await analyse_apk(APKS[name], "", f"{name}.apk", redis, store, ctx(ApkSandbox(), settings))
    assert r.decision.verdict is expected


async def test_known_bad_apk_hash_is_decisive(settings, redis, store) -> None:  # type: ignore[no-untyped-def]
    from kavach.hashing import sha256_hex

    data = APKS["warn_simple_calculator"]
    store.seed(EntityRef("apk", sha256_hex(data)), "scam")
    r = await analyse_apk(data, "", "calc.apk", redis, store, ctx(ApkSandbox(), settings))
    assert r.decision.verdict is Verdict.SCAM and "REPUTATION_SCAM" in r.decision.reason_codes


async def test_sandbox_down_is_never_safe(settings, redis, store) -> None:  # type: ignore[no-untyped-def]
    r = await analyse_apk(
        APKS["warn_simple_calculator"],
        "",
        "x.apk",
        redis,
        store,
        ctx(ApkSandbox(available=False), settings),
    )
    assert r.decision.verdict is Verdict.SUSPICIOUS


async def test_trojan_hash_marked_suspicious_not_scam(settings, redis, store) -> None:  # type: ignore[no-untyped-def]
    await analyse_apk(
        APKS["scam_sbi_kyc_update"], "", "x.apk", redis, store, ctx(ApkSandbox(), settings)
    )
    assert [r.verdict for r in store.reputation.values()] == ["suspicious"]


async def test_caption_adds_to_the_evidence(settings, redis, store) -> None:  # type: ignore[no-untyped-def]
    r = await analyse_apk(
        APKS["warn_simple_calculator"],
        "Aapka account block hai, KYC ke liye yeh app install karein turant",
        "kyc.apk",
        redis,
        store,
        ctx(ApkSandbox(), settings),
    )
    assert r.decision.verdict is Verdict.SCAM


# --- end to end ---------------------------------------------------------------------------


async def test_apk_end_to_end_one_reply(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    from tests.test_flow import drain

    messenger.media["APK1"] = APKS["scam_wedding_invite"]
    sandbox = ApkSandbox()
    orch = Orchestrator(settings, redis, store, messenger)
    checker = Checker(settings, redis, store, messenger, deep=ctx(sandbox, settings))
    msg = InboundMessage(
        "wamid.apk",
        "919800000001",
        InboundKind.DOCUMENT,
        media_id="APK1",
        media_mime=APK_MIME,
        media_sha256="file-sha",
        filename="Wedding Card.apk",
    )
    await orch.handle(msg)
    assert await drain(redis, checker) == 1
    (_, body, reply_to) = messenger.sent[0]
    assert reply_to == "wamid.apk" and "SCAM" in body and "Install na karein" in body
    (check,) = store.checks
    assert check.input_type == "apk" and check.verdict == "scam"

    # The same file forwarded again: cached reply, no download, no second parse.
    await orch.handle(
        InboundMessage(
            "wamid.apk2",
            "919800000002",
            InboundKind.DOCUMENT,
            media_id="APK9",
            media_mime=APK_MIME,
            media_sha256="file-sha",
            filename="Wedding Card.apk",
        )
    )
    assert sandbox.calls == 1 and store.checks[-1].from_cache


async def test_apk_by_filename_without_mime(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    orch = Orchestrator(settings, redis, store, messenger)
    await orch.handle(
        InboundMessage(
            "wamid.f",
            "91980",
            InboundKind.DOCUMENT,
            media_id="M",
            media_mime="application/octet-stream",
            filename="PM_Kisan.APK",
        )
    )
    entries = await redis.xrange("kavach:checks")
    assert entries and entries[0][1][b"kind"] == b"apk"
