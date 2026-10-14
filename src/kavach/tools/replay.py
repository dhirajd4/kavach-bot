"""Replay harness: post signed, Meta-shaped webhooks to a running bot and print its replies.

Needs the stack running with WHATSAPP_DRY_RUN=true (replies are parked in Redis, nothing is
sent to Meta). Usage:

    python -m kavach.tools.replay                       # built-in samples
    python -m kavach.tools.replay "OTP batao jaldi"     # your own text(s)
"""

import argparse
import asyncio
import json
import time
import uuid

import httpx
from redis.asyncio import Redis

from kavach.config import get_settings
from kavach.whatsapp.signature import sign

SAMPLES = [
    "Main CBI officer bol raha hoon, aap digital arrest mein hain. Video call par rahiye.",
    "Dear customer your SBI account will be blocked today. Update KYC: http://sbi-kyc-update.xyz/a",
    "KBC lucky draw mein aapne 25 lakh jeete hain, registration fee Rs 12500 pay karein",
    "Kal shaam 6 baje mandir chalenge, mummy ko bhi le aana.",
    "https://www.hdfcbank.com/personal/pay/cards",
]


def payload(text: str, msg_id: str, wa_id: str) -> dict[str, object]:
    message = {
        "from": wa_id,
        "id": msg_id,
        "timestamp": str(int(time.time())),
        "type": "text",
        "text": {"body": text},
    }
    value = {"messaging_product": "whatsapp", "messages": [message]}
    return {
        "object": "whatsapp_business_account",
        "entry": [{"id": "replay", "changes": [{"field": "messages", "value": value}]}],
    }


async def run(texts: list[str], base_url: str, wa_id: str, wait_s: float) -> None:
    s = get_settings()
    secret = s.meta_app_secret.get_secret_value()
    redis = Redis.from_url(s.redis_url)
    async with httpx.AsyncClient(base_url=base_url, timeout=10) as http:
        for text in texts:
            msg_id = f"wamid.replay.{uuid.uuid4().hex[:12]}"
            body = json.dumps(payload(text, msg_id, wa_id)).encode()
            started = time.monotonic()
            resp = await http.post(
                "/webhook",
                content=body,
                headers={
                    "content-type": "application/json",
                    "x-hub-signature-256": sign(body, secret),
                },
            )
            resp.raise_for_status()
            reply = None
            while time.monotonic() - started < wait_s and reply is None:
                reply = await redis.get(f"dryrun:reply:{msg_id}")
                if reply is None:
                    await asyncio.sleep(0.2)
            took = time.monotonic() - started
            print("=" * 72)
            print(f"IN  : {text}")
            print(f"TIME: {took:.2f}s")
            if isinstance(reply, bytes):
                reply = reply.decode()
            print(reply or "(no reply within timeout)")
    await redis.aclose()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("texts", nargs="*")
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--wa-id", default="910000000000", help="fake sender id")
    ap.add_argument("--timeout", type=float, default=20)
    args = ap.parse_args()
    asyncio.run(run(args.texts or SAMPLES, args.url, args.wa_id, args.timeout))


if __name__ == "__main__":
    main()
