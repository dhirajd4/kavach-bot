"""Webhook → orchestrator → queue → worker → one reply, with fakes for Meta and Postgres."""

import json

import httpx
import pytest
import respx

from kavach import queue
from kavach.intel import openphish
from kavach.orchestrator.service import Orchestrator
from kavach.reputation.store import EntityRef
from kavach.whatsapp.payloads import InboundKind, InboundMessage, parse_webhook
from kavach.whatsapp.signature import sign, verify_signature
from kavach.workers.checker import Checker
from tests.conftest import APP_SECRET, webhook_payload


def msg(text: str, msg_id: str = "wamid.1", wa_id: str = "919800000001") -> InboundMessage:
    return InboundMessage(message_id=msg_id, wa_id=wa_id, kind=InboundKind.TEXT, text=text)


async def drain(redis, checker: Checker) -> int:  # type: ignore[no-untyped-def]
    await queue.ensure_group(redis)
    resp = await redis.xreadgroup(queue.GROUP, "t", {queue.STREAM: ">"}, count=100)
    n = 0
    for _s, entries in resp or []:
        for entry_id, fields in entries:
            await checker.process({k.decode(): v.decode() for k, v in fields.items()})
            await queue.done(redis, entry_id.decode())
            n += 1
    return n


# --- signature & parsing -------------------------------------------------------------


def test_signature_roundtrip() -> None:
    body = b'{"a":1}'
    assert verify_signature(body, sign(body, APP_SECRET), APP_SECRET)
    assert not verify_signature(body, sign(body, "other"), APP_SECRET)
    assert not verify_signature(body, None, APP_SECRET)
    assert not verify_signature(body, sign(body, APP_SECRET), "")


def test_parse_text_and_document() -> None:
    (m,) = parse_webhook(webhook_payload("hello", extra={"context": {"forwarded": True}}))
    assert m.kind is InboundKind.TEXT and m.text == "hello" and m.forwarded
    doc = webhook_payload(
        mtype="document",
        extra={
            "document": {
                "id": "MEDIA1",
                "mime_type": "application/vnd.android.package-archive",
                "filename": "app.apk",
                "sha256": "abc",
            }
        },
    )
    (d,) = parse_webhook(doc)
    assert d.kind is InboundKind.DOCUMENT and d.media_id == "MEDIA1" and d.filename == "app.apk"


def test_parse_ignores_statuses() -> None:
    payload = {"entry": [{"changes": [{"value": {"statuses": [{"id": "x", "status": "read"}]}}]}]}
    assert parse_webhook(payload) == []


# --- orchestrator + worker -----------------------------------------------------------


async def test_scam_text_gets_exactly_one_reply(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    orch = Orchestrator(settings, redis, store, messenger)
    checker = Checker(settings, redis, store, messenger)
    await orch.handle(
        msg("CBI officer: aap digital arrest mein hain, turant video call par aayiye")
    )
    assert messenger.sent == []  # webhook side only enqueues
    assert await drain(redis, checker) == 1
    (to, body, reply_to) = messenger.sent[0]
    assert len(messenger.sent) == 1 and to == "919800000001" and reply_to == "wamid.1"
    assert "SCAM" in body and "Kavach" in body  # first-time users also get the welcome
    (check,) = store.checks
    assert check.verdict == "scam" and "DIGITAL_ARREST" in check.reason_codes


async def test_privacy_no_raw_text_or_number_persisted(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    orch = Orchestrator(settings, redis, store, messenger)
    checker = Checker(settings, redis, store, messenger)
    text = "Pay Rs 5000 registration fee to winner@okaxis, KBC lottery jeeta hai"
    await orch.handle(msg(text))
    await drain(redis, checker)
    dumped = json.dumps(
        [
            vars(c) if not hasattr(c, "__slots__") else {s: str(getattr(c, s)) for s in c.__slots__}
            for c in store.checks
        ]
    )
    assert "okaxis" not in dumped and "919800000001" not in dumped and "lottery" not in dumped
    assert list(store.users) != ["919800000001"]  # user stored only as HMAC
    assert await redis.xlen(queue.STREAM) == 0  # job content deleted after processing
    upi = [r for r in store.sightings if r.entity_type == "upi"]
    assert upi  # counted for reputation, stored hashed (value dropped for personal types)


async def test_duplicate_webhook_delivery_processed_once(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    orch = Orchestrator(settings, redis, store, messenger)
    await orch.handle(msg("KYC update karein turant, account block ho jayega"))
    await orch.handle(msg("KYC update karein turant, account block ho jayega"))
    assert await redis.xlen(queue.STREAM) == 1


async def test_second_identical_forward_served_from_cache(
    settings, redis, store, messenger
) -> None:  # type: ignore[no-untyped-def]
    orch = Orchestrator(settings, redis, store, messenger)
    checker = Checker(settings, redis, store, messenger)
    text = "Your SBI account will be blocked, update KYC: http://sbi-kyc-update.xyz/login"
    await orch.handle(msg(text, "wamid.a", "919800000001"))
    await drain(redis, checker)
    await orch.handle(msg(text.upper(), "wamid.b", "919800000002"))  # other user, same content
    assert await redis.xlen(queue.STREAM) == 0  # no worker needed
    assert len(messenger.sent) == 2 and store.checks[-1].from_cache


async def test_language_command(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    orch = Orchestrator(settings, redis, store, messenger)
    await orch.handle(msg("English"))
    assert "Language set to English" in messenger.sent[0][1]
    assert list(store.users.values()) == ["en"]


async def test_rate_limit_notifies_once(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    orch = Orchestrator(settings, redis, store, messenger)
    for i in range(settings.rate_limit_per_hour + 3):
        await orch.handle(msg(f"message number {i} hello there friend", f"wamid.{i}"))
    notices = [b for _, b, _ in messenger.sent if "try again" in b.lower() or "try karein" in b]
    assert len(notices) == 1
    assert await redis.xlen(queue.STREAM) == settings.rate_limit_per_hour


async def test_image_gets_coming_soon_reply(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    orch = Orchestrator(settings, redis, store, messenger)
    await orch.handle(InboundMessage("wamid.i", "919800000001", InboundKind.IMAGE, media_id="M"))
    assert len(messenger.sent) == 1 and await redis.xlen(queue.STREAM) == 0


async def test_greeting_gets_welcome_not_verdict(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    orch = Orchestrator(settings, redis, store, messenger)
    checker = Checker(settings, redis, store, messenger)
    await orch.handle(msg("hi"))
    await drain(redis, checker)
    (_, body, _) = messenger.sent[0]
    assert "Kavach" in body and "SCAM" not in body


async def test_retry_after_send_does_not_double_reply(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    checker = Checker(settings, redis, store, messenger)
    job = {
        "kind": "text",
        "message_id": "wamid.r",
        "wa_id": "91980",
        "user_hash": "u",
        "text": "OTP share karein abhi turant",
        "media_id": "",
        "language": "en",
        "first_time": "0",
        "input_hash": "h",
        "received_at": "0",
    }

    async def boom(record):  # type: ignore[no-untyped-def]
        raise RuntimeError("db down")

    store.save_check = boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await checker.process(job)
    with pytest.raises(RuntimeError):
        await checker.process(job)
    assert len(messenger.sent) == 1


# --- threat intel --------------------------------------------------------------------


async def test_openphish_listed_link_is_scam(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    feed = "https://evil-login.example-phish.com/a/b\nhttps://sites.google.com/view/fake-sbi\n"
    with respx.mock:
        respx.get(settings.openphish_feed_url).mock(return_value=httpx.Response(200, text=feed))
        async with httpx.AsyncClient() as http:
            assert await openphish.sync(redis, http, settings.openphish_feed_url) == 2
    # shared host (sites.google.com) is matched by exact URL only, never the whole host
    assert not await redis.sismember(openphish.HOSTS_KEY, "sites.google.com")

    orch = Orchestrator(settings, redis, store, messenger)
    checker = Checker(settings, redis, store, messenger)
    await orch.handle(msg("dekho yeh link https://evil-login.example-phish.com/other"))
    await drain(redis, checker)
    assert store.checks[-1].verdict == "scam"
    assert "OPENPHISH_LISTED" in store.checks[-1].reason_codes


async def test_reputation_scam_upi(settings, redis, store, messenger) -> None:  # type: ignore[no-untyped-def]
    store.seed(EntityRef("upi", "fraud.king@ybl"), "scam")
    checker = Checker(settings, redis, store, messenger)
    orch = Orchestrator(settings, redis, store, messenger)
    await orch.handle(msg("Bhai is UPI par 500 bhej do fraud.king@ybl jaldi"))
    await drain(redis, checker)
    assert store.checks[-1].verdict == "scam"
