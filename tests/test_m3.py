"""M3: images: QR decoding, UPI QR tricks, OCR pipeline (OCR faked; real Tesseract runs in
Docker, see `make image-eval`), untrusted-image handling, checker image path."""

import io
from dataclasses import asdict
from pathlib import Path

import pytest
import segno
from PIL import Image

from kavach.detectors.types import Reason
from kavach.media.image import analyse_image
from kavach.media.ocr import BadImage, load_image, prepare_for_ocr
from kavach.media.qr import decode_qr, parse_upi, qr_findings
from kavach.orchestrator.service import Orchestrator
from kavach.verdict.rules import Verdict
from kavach.whatsapp.payloads import InboundKind, InboundMessage
from kavach.workers.checker import Checker

IMAGES = Path(__file__).parent / "fixtures" / "images"


class FakeOcr:
    def __init__(self, text: str = "") -> None:
        self.text = text
        self.calls = 0

    async def read(self, image: Image.Image) -> str:
        self.calls += 1
        return self.text


def png(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def qr_png(payload: str) -> bytes:
    buf = io.BytesIO()
    segno.make(payload).save(buf, kind="png", scale=6, border=2)
    return buf.getvalue()


# --- QR ---------------------------------------------------------------------------------


def test_decode_qr_from_fixture() -> None:
    img = load_image((IMAGES / "scam_qr_cashback.png").read_bytes())
    (payload,) = decode_qr(img)
    upi = parse_upi(payload)
    assert upi is not None and upi.payee == "cashback.offer@ybl" and upi.amount == "4999"


def test_parse_upi_rejects_non_upi() -> None:
    assert parse_upi("https://example.com") is None
    assert parse_upi("upi://pay?pn=NoPayee") is None


def test_receive_money_qr_is_a_trick() -> None:
    payload = ["upi://pay?pa=x@ybl&am=4999"]
    reasons = {f.reason for f in qr_findings(payload, "Scan this QR to receive money")}
    assert {Reason.QR_UPI_PAYMENT, Reason.QR_RECEIVE_TRICK} <= reasons
    shop = {f.reason for f in qr_findings(["upi://pay?pa=shop@okicici"], "Pay here for groceries")}
    assert shop == {Reason.QR_UPI_PAYMENT}


# --- untrusted images ----------------------------------------------------------------------


def test_garbage_bytes_rejected() -> None:
    with pytest.raises(BadImage):
        load_image(b"not an image at all")


def test_decompression_bomb_rejected() -> None:
    # 1-bit PNG claiming ~100M pixels: tiny file, huge decode.
    bomb = png(Image.new("1", (10_000, 10_000)))
    with pytest.raises(BadImage):
        load_image(bomb)


def test_small_screenshots_are_upscaled_for_ocr() -> None:
    out = Image.open(io.BytesIO(prepare_for_ocr(Image.new("RGB", (400, 300), "white"))))
    assert out.width == 1000 and out.mode == "L"


# --- pipeline ------------------------------------------------------------------------------


async def test_ocr_text_runs_through_scam_detectors(redis, store) -> None:  # type: ignore[no-untyped-def]
    ocr = FakeOcr("गिरफ्तारी वारंट\nआप डिजिटल अरेस्ट में हैं। मनी लॉन्ड्रिंग का केस।")
    data = (IMAGES / "scam_fake_fir_hi.png").read_bytes()
    r = await analyse_image(data, "", ocr, redis, store)
    assert r.readable and r.ocr_chars > 0
    assert r.result.decision.verdict is Verdict.SCAM
    assert "DIGITAL_ARREST" in r.result.decision.reason_codes


async def test_qr_receive_trick_is_scam_even_with_weak_ocr(redis, store) -> None:  # type: ignore[no-untyped-def]
    ocr = FakeOcr("Congratulations! You have won Rs 25,000 cashback. Scan this QR to receive money")
    data = (IMAGES / "scam_qr_cashback.png").read_bytes()
    r = await analyse_image(data, "", ocr, redis, store)
    codes = set(r.result.decision.reason_codes)
    assert r.qr_count == 1 and {"QR_UPI_PAYMENT", "QR_RECEIVE_TRICK"} <= codes
    assert r.result.decision.verdict is Verdict.SCAM


async def test_shop_qr_is_not_flagged(redis, store) -> None:  # type: ignore[no-untyped-def]
    ocr = FakeOcr("Sharma General Store\nPay here for groceries")
    r = await analyse_image((IMAGES / "safe_shop_qr.png").read_bytes(), "", ocr, redis, store)
    assert r.result.decision.verdict not in (Verdict.SCAM, Verdict.SUSPICIOUS)


async def test_known_scam_upi_in_qr_is_decisive(redis, store) -> None:  # type: ignore[no-untyped-def]
    from kavach.reputation.store import EntityRef

    store.seed(EntityRef("upi", "sharmastore@okicici"), "scam")
    r = await analyse_image(
        (IMAGES / "safe_shop_qr.png").read_bytes(), "", FakeOcr(""), redis, store
    )
    assert r.result.decision.verdict is Verdict.SCAM


async def test_blank_photo_is_unreadable(redis, store) -> None:  # type: ignore[no-untyped-def]
    r = await analyse_image(
        (IMAGES / "blank_photo.png").read_bytes(), "", FakeOcr("  ~ ."), redis, store
    )
    assert not r.readable and r.result.decision.verdict is Verdict.NOTHING_TO_CHECK


async def test_caption_is_checked_with_the_image(redis, store) -> None:  # type: ignore[no-untyped-def]
    r = await analyse_image(
        (IMAGES / "blank_photo.png").read_bytes(),
        "OTP share karein jaldi",
        FakeOcr(""),
        redis,
        store,
    )
    assert "OTP_REQUEST" in r.result.decision.reason_codes


async def test_bad_image_still_checks_caption(redis, store) -> None:  # type: ignore[no-untyped-def]
    r = await analyse_image(
        b"garbage", "KBC lottery jeeta, fee Rs 500 pay karein", FakeOcr(""), redis, store
    )
    assert r.result.decision.verdict in (Verdict.SCAM, Verdict.SUSPICIOUS)


# --- end to end through orchestrator + checker ------------------------------------------


async def test_photo_end_to_end_one_reply_and_nothing_stored(  # type: ignore[no-untyped-def]
    settings, redis, store, messenger
) -> None:
    from tests.test_flow import drain

    data = (IMAGES / "scam_qr_cashback.png").read_bytes()
    messenger.media["MEDIA1"] = data
    orch = Orchestrator(settings, redis, store, messenger)
    ocr = FakeOcr("You have won Rs 25,000 cashback. Scan this QR to receive money")
    checker = Checker(settings, redis, store, messenger, ocr=ocr)
    msg = InboundMessage(
        "wamid.img",
        "919800000001",
        InboundKind.IMAGE,
        media_id="MEDIA1",
        media_sha256="sha-of-file",
    )
    await orch.handle(msg)
    assert await drain(redis, checker) == 1
    (_, body, reply_to) = messenger.sent[0]
    assert reply_to == "wamid.img" and "SCAM" in body and "QR" in body
    (check,) = store.checks
    assert check.input_type == "image" and check.verdict == "scam"
    assert "cashback.offer" not in str(asdict(check))  # QR payee never persisted raw

    # Same image forwarded by someone else → cache, no download, no OCR.
    msg2 = InboundMessage(
        "wamid.img2",
        "919800000002",
        InboundKind.IMAGE,
        media_id="MEDIA9",
        media_sha256="sha-of-file",
    )
    await orch.handle(msg2)
    assert await redis.xlen("kavach:checks") == 0 and ocr.calls == 1
    assert store.checks[-1].from_cache


async def test_unreadable_photo_gets_helpful_reply(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    messenger.media["M"] = (IMAGES / "blank_photo.png").read_bytes()
    checker = Checker(settings, redis, store, messenger, ocr=FakeOcr(""))
    job = {
        "kind": "image",
        "message_id": "wamid.b",
        "wa_id": "91980",
        "user_hash": "u",
        "text": "",
        "media_id": "M",
        "language": "en",
        "first_time": "0",
        "input_hash": "hb",
        "received_at": "0",
    }
    await checker.process(job)
    assert "couldn't find any text" in messenger.sent[0][1]


async def test_oversized_photo_is_refused(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    messenger.media["BIG"] = b"x" * (settings.max_image_bytes + 1)
    checker = Checker(settings, redis, store, messenger, ocr=FakeOcr(""))
    job = {
        "kind": "image",
        "message_id": "wamid.big",
        "wa_id": "91980",
        "user_hash": "u",
        "text": "",
        "media_id": "BIG",
        "language": "en",
        "first_time": "0",
        "input_hash": "hbig",
        "received_at": "0",
    }
    with pytest.raises(ValueError):
        await checker.process(job)  # runner retries, then sends the polite error reply
