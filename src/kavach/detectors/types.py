"""Shared detector output. Detectors are pure: input in, findings out, no I/O side effects."""

from dataclasses import dataclass, field
from enum import StrEnum


class Reason(StrEnum):
    # Lists / reputation (strong)
    OPENPHISH_LISTED = "OPENPHISH_LISTED"
    REPUTATION_SCAM = "REPUTATION_SCAM"
    REPUTATION_SUSPICIOUS = "REPUTATION_SUSPICIOUS"
    OFFICIAL_DOMAIN = "OFFICIAL_DOMAIN"
    # URL lexical (weak, cheap)
    BRAND_IMPERSONATION = "BRAND_IMPERSONATION"
    IP_ADDRESS_HOST = "IP_ADDRESS_HOST"
    PUNYCODE_HOST = "PUNYCODE_HOST"
    RISKY_TLD = "RISKY_TLD"
    SHORTENED_URL = "SHORTENED_URL"
    NO_HTTPS = "NO_HTTPS"
    APK_LINK = "APK_LINK"
    # Text intent
    DIGITAL_ARREST = "DIGITAL_ARREST"
    AUTHORITY_CLAIM = "AUTHORITY_CLAIM"
    FEAR_THREAT = "FEAR_THREAT"
    URGENCY = "URGENCY"
    KYC_BLOCK = "KYC_BLOCK"
    OTP_REQUEST = "OTP_REQUEST"
    LOTTERY_PRIZE = "LOTTERY_PRIZE"
    JOB_TASK = "JOB_TASK"
    INVESTMENT_RETURNS = "INVESTMENT_RETURNS"
    REFUND_BILL = "REFUND_BILL"
    PAYMENT_ASK = "PAYMENT_ASK"
    REMOTE_ACCESS_APP = "REMOTE_ACCESS_APP"
    SEXTORTION = "SEXTORTION"
    ADVANCE_FEE = "ADVANCE_FEE"


@dataclass(frozen=True, slots=True)
class Finding:
    reason: Reason
    weight: float
    # Short, user-facing evidence (a domain, a matched phrase). Shown in the reply,
    # never persisted: the DB stores reason codes only.
    evidence: str = ""
    decisive: bool = False  # a single decisive finding is enough for a SCAM verdict


@dataclass(slots=True)
class Analysis:
    findings: list[Finding] = field(default_factory=list)
    urls_checked: int = 0
    all_urls_official: bool = False

    def extend(self, items: list[Finding]) -> None:
        self.findings.extend(items)
