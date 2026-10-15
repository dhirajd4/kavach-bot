"""Seed intent detector for Hindi / Hinglish / English scam text.

Per TDS §10.1 keywords are the *seed* only (explainable, instant, but brittle). The char
n-gram + LR classifier (M5) is layered on top; these rules stay as guard-rails and
explanations.
"""

import re
import unicodedata
from dataclasses import dataclass

from kavach.detectors.types import Finding, Reason

_ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿"))


@dataclass(frozen=True, slots=True)
class _Intent:
    reason: Reason
    weight: float
    latin: tuple[str, ...]  # regex fragments, matched with word boundaries
    devanagari: tuple[str, ...] = ()  # plain substrings


_INTENTS: tuple[_Intent, ...] = (
    _Intent(
        Reason.DIGITAL_ARREST,
        5,
        (
            r"digital(ly)?\s*arrest(ed)?",
            r"video\s*call\s*(par\s*)?(verification|statement|enquiry)",
            r"house\s*arrest",
            r"skype\s*(call|statement|verification)",
        ),
        ("डिजिटल अरेस्ट", "डिजिटल गिरफ्तार"),
    ),
    _Intent(
        Reason.AUTHORITY_CLAIM,
        2,
        (
            r"cbi",
            r"police",
            r"cyber\s*(cell|crime\s*branch)",
            r"crime\s*branch",
            r"enforcement\s*directorate",
            r"narcotics",
            r"ncb",
            r"customs",
            r"trai",
            r"rbi",
            r"income\s*tax\s*(department|officer)",
            r"supreme\s*court",
            r"high\s*court",
            r"judge",
            r"ips\s*officer",
            r"mumbai\s*police",
            r"fedex",
            r"dhl",
        ),
        ("सीबीआई", "पुलिस", "साइबर सेल", "क्राइम ब्रांच", "कस्टम", "आरबीआई", "न्यायालय", "अदालत"),
    ),
    _Intent(
        Reason.FEAR_THREAT,
        2,
        (
            r"arrest(ed)?",
            r"gira?f?ta+r(i)?",
            r"warrant",
            r"fir\b",
            r"case\s*(darj|registered|file)",
            r"money\s*laundering",
            r"drugs?",
            r"illegal\s*parcel",
            r"parcel\s*(seized|me\s*drugs)",
            r"jail",
            r"legal\s*action",
            r"kanooni\s*karyawahi",
            r"sim\s*(will\s*be\s*)?(block|band)",
        ),
        ("गिरफ्तार", "वारंट", "एफआईआर", "मनी लॉन्ड्रिंग", "ड्रग्स", "जेल", "कानूनी कार्रवाई"),
    ),
    _Intent(
        Reason.URGENCY,
        1,
        (
            r"turant",
            r"abhi\s*ke\s*abhi",
            r"immediately",
            r"urgent(ly)?",
            r"within\s*\d+\s*(hours?|hrs?|minutes?|mins?)",
            r"\d+\s*(ghante|minute)\s*(me|mein|ke\s*andar)",
            r"aaj\s*hi",
            r"last\s*(chance|date|warning)",
            r"expire[sd]?\s*today",
        ),
        ("तुरंत", "अभी के अभी", "आज ही", "अंतिम चेतावनी"),
    ),
    _Intent(
        Reason.KYC_BLOCK,
        2,
        (
            r"kyc",
            r"pan\s*(card\s*)?(update|link)",
            r"aadhaa?r\s*(update|link)",
            r"account\s*(will\s*be\s*)?(block|suspend|band|freeze|deactivat)\w*",
            r"(block|band|suspend)\s*ho\s*(jayega|jaega|gaya)",
            r"electricity\s*(connection|bill)",
            r"bijli\s*(ka\s*)?(connection|bill)",
        ),
        ("केवाईसी", "खाता बंद", "अकाउंट ब्लॉक", "बिजली कनेक्शन"),
    ),
    _Intent(
        Reason.OTP_REQUEST,
        4,
        (
            r"otp\s*(share|bata\w*|bhej\w*|send|de\s*do|dijiye|batayein|forward)",
            r"(share|send|bata\w*|bhej\w*)\s*(the\s*|your\s*|apna\s*)?otp",
            r"(upi\s*)?pin\s*(dal\w*|enter|bata\w*)",
            r"cvv",
        ),
        ("ओटीपी बताएं", "ओटीपी भेजें", "ओटीपी शेयर", "पिन डालें"),
    ),
    _Intent(
        Reason.LOTTERY_PRIZE,
        3,
        (
            r"lottery",
            r"kbc",
            r"kaun\s*banega\s*crorepati",
            r"lucky\s*(draw|winner)",
            r"(you\s*have\s*)?won\s*(rs|₹|inr|a\s*prize|\d)",
            r"jeet(a|e)\s*(hai|ho)",
            r"inaa?m",
            r"prize\s*money",
            r"gift\s*(card|voucher)\s*(won|jeet)",
        ),
        ("लॉटरी", "इनाम", "केबीसी", "लकी ड्रा"),
    ),
    _Intent(
        Reason.JOB_TASK,
        2,
        (
            r"part[\s-]*time\s*job",
            r"work\s*from\s*home",
            r"daily\s*(earn|income|payment)",
            r"earn\s*(rs|₹)?\s*\d+\s*(daily|per\s*day|/day)",
            r"(like|subscribe)\s*(youtube|videos?)",
            r"hotel\s*review\s*task",
            r"telegram\s*task",
            r"prepaid\s*task",
        ),
        ("पार्ट टाइम जॉब", "घर बैठे कमाएं", "रोज़ कमाई"),
    ),
    _Intent(
        Reason.INVESTMENT_RETURNS,
        2,
        (
            r"guarantee[d]?\s*(return|profit)",
            r"double\s*(your\s*)?(money|paisa)",
            r"paisa\s*double",
            r"\d+\s*%\s*(daily|weekly|monthly)\s*(return|profit)",
            r"stock\s*tips",
            r"ipo\s*allotment",
            r"vip\s*(trading|stock)\s*group",
            r"crypto\s*(investment|trading)",
            r"institutional\s*account",
        ),
        ("पैसा डबल", "गारंटीड रिटर्न", "शेयर टिप्स"),
    ),
    _Intent(
        Reason.REFUND_BILL,
        2,
        (
            r"refund",
            r"cash\s*back\s*(pending|credited)",
            r"tax\s*refund",
            r"(bill|connection)\s*(will\s*be\s*)?(disconnect|cut|kat)\w*",
            r"recharge\s*(failed|pending)",
            # "I sent extra by mistake, please return it" (fake payment screenshot scam)
            r"(sent|bhej\w*|transfer\w*)\s*(extra|zyada|jyada|galti\s*se)",
            r"(galti\s*se|by\s*mistake|accidentally)\W+(?:\w+\W+){0,4}?(bhej|sent|transfer|credit)\w*",
            r"\d[\d,]*\s*(rs\.?|₹|rupees?)?\s*(extra|zyada|jyada|excess)",
            r"return\s*the\s*(extra|excess|balance)\s*(amount|money)?",
            r"(wapas|vapas|return|refund)\s*(kar|bhej)\s*(do|dijiye|de|dena)",
        ),
        ("रिफंड", "कनेक्शन कट"),
    ),
    _Intent(
        Reason.PAYMENT_ASK,
        1,
        (
            r"(pay|transfer|send|bhej\w*|jama\s*kar\w*)\s*(rs\.?|₹|inr)?\s*\d[\d,]*",
            r"(rs\.?|₹|inr)\s*\d[\d,]*\s*(pay|transfer|bhej\w*|jama)",
            r"scan\s*(the\s*)?qr",
            r"processing\s*fee",
            r"registration\s*fee",
            r"security\s*deposit",
            r"verification\s*fee",
        ),
        ("भुगतान करें", "पैसे भेजें", "शुल्क जमा"),
    ),
    _Intent(
        Reason.REMOTE_ACCESS_APP,
        4,
        (
            r"any\s*desk",
            r"team\s*viewer",
            r"quick\s*support",
            r"rust\s*desk",
            r"screen\s*shar(e|ing)",
            r"install\s*(this\s*)?(app|apk)",
            r"download\s*(this\s*)?apk",
            r"[\w\-]+\.apk",  # "shaadi-card.apk" (wedding-invite / PM-Kisan malware)
            r"apk\s*(file\s*)?(download|install|open)\w*",
        ),
        ("स्क्रीन शेयर", "ऐप इंस्टॉल"),
    ),
    _Intent(
        Reason.SEXTORTION,
        4,
        (
            r"(nude|obscene|private|personal)\s*(video|photo|pic)s?\b.{0,30}?\b(viral|leak|upload|send)\w*",
            r"video\s*viral\s*kar\s*(denge|dunga|doonga)",
        ),
        ("वीडियो वायरल",),
    ),
)


def _compile(fragment: str) -> re.Pattern[str]:
    return re.compile(r"(?<![\w])(?:" + fragment + r")(?![\w])", re.IGNORECASE)


_COMPILED = [(intent, [_compile(f) for f in intent.latin]) for intent in _INTENTS]

# Each extra distinct cue of the same intent adds this much, up to MAX_EXTRA (TDS §6.2:
# weights are capped per signal type so one long message can't run away with the score).
EXTRA_CUE_WEIGHT = 1.0
MAX_EXTRA = 2


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFC", text).translate(_ZERO_WIDTH)
    return text.casefold()


def detect_intents(text: str) -> list[Finding]:
    """One finding per intent; more distinct cues of that intent add a capped bonus."""
    norm = normalise(text)
    findings: list[Finding] = []
    for intent, patterns in _COMPILED:
        hits = [m.group(0).strip() for p in patterns if (m := p.search(norm))]
        hits += [d for d in intent.devanagari if d in norm]
        if hits:
            extra = min(len(hits) - 1, MAX_EXTRA) * EXTRA_CUE_WEIGHT
            findings.append(Finding(intent.reason, intent.weight + extra, hits[0][:40]))
    return _with_combos(findings)


def _with_combos(findings: list[Finding]) -> list[Finding]:
    """Order/combination bonus: authority + fear is the digital-arrest / impersonation script."""
    reasons = {f.reason for f in findings}
    if {
        Reason.AUTHORITY_CLAIM,
        Reason.FEAR_THREAT,
    } <= reasons and Reason.DIGITAL_ARREST not in reasons:
        findings.append(Finding(Reason.DIGITAL_ARREST, 3, "authority + threat"))
    # Bait (prize / job / returns / refund) followed by "pay a fee first" = advance-fee fraud.
    if reasons & _BAIT and Reason.PAYMENT_ASK in reasons:
        findings.append(Finding(Reason.ADVANCE_FEE, 3, "bait + pay first"))
    return findings


_BAIT = frozenset(
    {Reason.LOTTERY_PRIZE, Reason.JOB_TASK, Reason.INVESTMENT_RETURNS, Reason.REFUND_BILL}
)
