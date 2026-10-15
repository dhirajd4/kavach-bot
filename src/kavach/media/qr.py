"""QR codes in images. A UPI QR always SENDS money from whoever scans it, so
"scan this QR to receive money / your prize / your refund" is always a scam."""

import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import zxingcpp
from PIL import Image

from kavach.detectors.types import Finding, Reason

_RECEIVE_BAIT = re.compile(
    r"receiv|recieve|credit(ed)?|milenge|milega|aayenge|aa jayenge|prize|reward|refund|"
    r"cash\s*back|lottery|jeet|inaa?m|won\b|claim|प्राप्त|मिलेंगे|इनाम|रिफंड",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class UpiQr:
    payee: str  # pa=
    name: str  # pn=
    amount: str  # am=


def decode_qr(img: Image.Image) -> list[str]:
    try:
        results = zxingcpp.read_barcodes(img)
    except (ValueError, RuntimeError):
        return []
    return [r.text for r in results if r.text][:5]


def parse_upi(payload: str) -> UpiQr | None:
    if not payload.lower().startswith("upi://"):
        return None
    q = parse_qs(urlsplit(payload).query)

    def first(key: str) -> str:
        return (q.get(key) or [""])[0][:80]

    payee = first("pa")
    return UpiQr(payee=payee, name=first("pn"), amount=first("am")) if payee else None


def qr_findings(payloads: list[str], surrounding_text: str) -> list[Finding]:
    out: list[Finding] = []
    for payload in payloads:
        upi = parse_upi(payload)
        if upi is None:
            continue
        amount = f"₹{upi.amount} " if upi.amount else ""
        out.append(Finding(Reason.QR_UPI_PAYMENT, 2, f"{amount}→ {upi.payee}"))
        bait = _RECEIVE_BAIT.search(surrounding_text)
        if bait:
            out.append(Finding(Reason.QR_RECEIVE_TRICK, 6, bait.group(0)))
        break  # one UPI QR is enough evidence
    return out


def qr_text(payloads: list[str]) -> str:
    """What the QR points to, as text for the URL / UPI detectors."""
    parts: list[str] = []
    for payload in payloads:
        upi = parse_upi(payload)
        parts.append(upi.payee if upi else payload)
    return "\n".join(parts)
