"""Judge APK facts (pure, unit-testable). Explainable permission/behaviour rules in the
spirit of TDS §10.2 (Drebin-style permission features); a trained model comes later.

Baseline: ANY app file arriving on WhatsApp skips Play Store checks, so it is never "safe".
"""

import re
from dataclasses import dataclass, field
from typing import Any

from kavach.detectors.types import Finding, Reason

P = "android.permission."

_IMPERSONATED = re.compile(
    r"\b(sbi|yono|hdfc|icici|axis|kotak|pnb|canara|bank|paytm|phonepe|g\s?pay|google\s?pay|"
    r"bhim|npci|upi|aadh?aa?r|uidai|pan\s?card|income\s?tax|pm[\s_-]?kisan|kisan|rto|"
    r"e?-?challan|parivahan|electricity|bijli|kyc|customer\s?(care|support)|reward\s?points?|"
    r"credit\s?card|airtel|jio|epfo|india\s?post|courier|fedex|blue\s?dart|digilocker|"
    r"cyber\s?crime|police|government|sarkari|yojana)\b",
    re.IGNORECASE,
)
_LURES = re.compile(
    r"wedding|shaadi|invitation|invite|card\s?view|photo\s?(viewer|album)|video\s?call|"
    r"invoice|bill\s?pdf|document\s?viewer|apk\s?installer|lucky|lottery|prize",
    re.IGNORECASE,
)
_SMS_PERMS = {P + "RECEIVE_SMS", P + "READ_SMS"}
_CALL_PERMS = {
    P + "CALL_PHONE",
    P + "PROCESS_OUTGOING_CALLS",
    P + "ANSWER_PHONE_CALLS",
    P + "READ_CALL_LOG",
}


@dataclass
class ApkFacts:
    sha256: str
    size: int = 0
    error: str = ""
    package: str = ""
    label: str = ""
    permissions: list[str] = field(default_factory=list)
    components: list[dict[str, Any]] = field(default_factory=list)
    signed: bool = False
    signers: list[str] = field(default_factory=list)
    has_dex: bool = False
    native_libs: int = 0

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ApkFacts":
        known = cls.__dataclass_fields__
        return cls(**{k: v for k, v in d.items() if k in known})

    def bound_services(self, permission: str) -> list[str]:
        return [c.get("name", "") for c in self.components if c.get("permission") == permission]

    def listens_for(self, action: str) -> bool:
        return any(action in (c.get("actions") or []) for c in self.components)


def _words(text: str) -> str:
    """'com.sbi.kycupdate.online' → 'com sbi kycupdate online' so \\b matching works."""
    return re.sub(r"[._\-]+", " ", text)


def apk_findings(f: ApkFacts) -> list[Finding]:
    name = f.label or f.package or "app"
    out = [Finding(Reason.APK_FILE, 3, f"{name} ({f.package})" if f.package else name)]
    if f.error:
        out.append(Finding(Reason.APK_UNREADABLE, 3, f.error.split(":", 1)[0]))
        return out

    perms = set(f.permissions)
    identity = f"{f.label} {_words(f.package)}"
    if m := _IMPERSONATED.search(identity):
        out.append(Finding(Reason.APK_IMPERSONATES, 5, f"{f.label or f.package} · '{m.group(0)}'"))
    elif m := _LURES.search(identity):
        out.append(Finding(Reason.APK_KNOWN_LURE, 3, f.label or f.package))

    reads_sms = bool(perms & _SMS_PERMS) or f.listens_for("android.provider.Telephony.SMS_RECEIVED")
    if reads_sms:
        out.append(Finding(Reason.APK_READS_SMS, 4, "SMS / OTP"))
    accessibility = f.bound_services(P + "BIND_ACCESSIBILITY_SERVICE")
    if accessibility:
        out.append(Finding(Reason.APK_ACCESSIBILITY, 4, "accessibility"))
    notifications = f.bound_services(P + "BIND_NOTIFICATION_LISTENER_SERVICE")
    if notifications:
        out.append(Finding(Reason.APK_NOTIFICATION_ACCESS, 3, "notifications"))
    if f.bound_services(P + "BIND_DEVICE_ADMIN") or f.listens_for(
        "android.app.action.DEVICE_ADMIN_ENABLED"
    ):
        out.append(Finding(Reason.APK_DEVICE_ADMIN, 3, "device admin"))
    if P + "SYSTEM_ALERT_WINDOW" in perms:
        out.append(Finding(Reason.APK_OVERLAY, 2, "draw over other apps"))
    if P + "SEND_SMS" in perms:
        spread = " + contacts" if P + "READ_CONTACTS" in perms else ""
        out.append(Finding(Reason.APK_SENDS_SMS, 2, "send SMS" + spread))
    if perms & _CALL_PERMS:
        out.append(Finding(Reason.APK_CALL_CONTROL, 2, "calls"))
    if P + "REQUEST_INSTALL_PACKAGES" in perms:
        out.append(Finding(Reason.APK_INSTALLS_APPS, 2, "install other apps"))

    # Banking-trojan pattern: it can read your OTPs AND get them out (or watch your screen).
    if reads_sms and (accessibility or notifications or perms & {P + "INTERNET", P + "SEND_SMS"}):
        out.append(Finding(Reason.APK_OTP_STEALER, 3, "reads OTP + can send it out"))

    if not f.signed:
        out.append(Finding(Reason.APK_UNSIGNED, 1, "unsigned"))
    elif any("android debug" in s.lower() for s in f.signers):
        out.append(Finding(Reason.APK_DEBUG_SIGNED, 1, "debug certificate"))
    return out
