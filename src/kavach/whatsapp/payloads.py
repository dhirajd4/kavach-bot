"""Parse Meta webhook payloads into flat inbound messages.

Reference shape: entry[].changes[].value.{messages[], statuses[], contacts[]}.
Profile names in `contacts` are deliberately ignored (personal data we don't need).
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class InboundKind(StrEnum):
    TEXT = "text"
    IMAGE = "image"
    DOCUMENT = "document"
    BUTTON = "button"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class InboundMessage:
    message_id: str
    wa_id: str
    kind: InboundKind
    text: str = ""  # text body, caption, or button title
    media_id: str = ""
    media_mime: str = ""
    media_sha256: str = ""
    filename: str = ""
    button_id: str = ""
    forwarded: bool = False


def _media(msg: dict[str, Any], key: str) -> dict[str, Any]:
    value = msg.get(key)
    return value if isinstance(value, dict) else {}


def parse_webhook(payload: dict[str, Any]) -> list[InboundMessage]:
    out: list[InboundMessage] = []
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            value = change.get("value") or {}
            for msg in value.get("messages") or []:
                parsed = _parse_message(msg)
                if parsed is not None:
                    out.append(parsed)
    return out


def _parse_message(msg: dict[str, Any]) -> InboundMessage | None:
    message_id = msg.get("id")
    wa_id = msg.get("from")
    if not isinstance(message_id, str) or not isinstance(wa_id, str):
        return None
    mtype = msg.get("type")
    context = msg.get("context") or {}
    forwarded = bool(context.get("forwarded") or context.get("frequently_forwarded"))
    base: dict[str, Any] = {"message_id": message_id, "wa_id": wa_id, "forwarded": forwarded}

    if mtype == "text":
        body = _media(msg, "text").get("body", "")
        return InboundMessage(kind=InboundKind.TEXT, text=str(body), **base)
    if mtype == "image":
        img = _media(msg, "image")
        return InboundMessage(
            kind=InboundKind.IMAGE,
            text=str(img.get("caption", "")),
            media_id=str(img.get("id", "")),
            media_mime=str(img.get("mime_type", "")),
            media_sha256=str(img.get("sha256", "")),
            **base,
        )
    if mtype == "document":
        doc = _media(msg, "document")
        return InboundMessage(
            kind=InboundKind.DOCUMENT,
            text=str(doc.get("caption", "")),
            media_id=str(doc.get("id", "")),
            media_mime=str(doc.get("mime_type", "")),
            media_sha256=str(doc.get("sha256", "")),
            filename=str(doc.get("filename", "")),
            **base,
        )
    if mtype == "interactive":
        reply = _media(msg, "interactive").get("button_reply") or {}
        return InboundMessage(
            kind=InboundKind.BUTTON,
            text=str(reply.get("title", "")),
            button_id=str(reply.get("id", "")),
            **base,
        )
    if mtype == "button":  # quick-reply on a template
        btn = _media(msg, "button")
        return InboundMessage(
            kind=InboundKind.BUTTON,
            text=str(btn.get("text", "")),
            button_id=str(btn.get("payload", "")),
            **base,
        )
    return InboundMessage(kind=InboundKind.UNSUPPORTED, **base)
