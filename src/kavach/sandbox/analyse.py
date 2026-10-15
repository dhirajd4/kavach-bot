"""Turn sandbox page facts into findings (pure, unit-testable)."""

import re

from kavach.detectors.types import Finding, Reason
from kavach.detectors.url.extract import parse_url
from kavach.intel.allowlist import is_official
from kavach.sandbox.client import PageFacts, PageInput

_SECRET_FIELDS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("password", re.compile(r"pass(word|wd)?|पासवर्ड|current-password|new-password")),
    ("OTP", re.compile(r"\botp\b|one[\s-]?time[\s-]?(password|code|pin)|ओटीपी|verification code")),
    ("card number", re.compile(r"card[\s_-]?(no|num|number)|cc-number|debit card|credit card")),
    ("CVV", re.compile(r"\bcvv\b|\bcvc\b|cc-csc|security code")),
    ("card expiry", re.compile(r"expir|cc-exp|valid thru")),
    ("PIN", re.compile(r"\bm?pin\b|atm pin|upi pin")),
    ("Aadhaar", re.compile(r"aadh?aa?r|आधार")),
    ("PAN", re.compile(r"\bpan\b(?!el)")),
    ("account number", re.compile(r"account[\s_-]?(no|num|number)|a/c")),
    ("net-banking login", re.compile(r"user[\s_-]?id|customer[\s_-]?id|login id|net[\s-]?banking")),
)

FINANCIAL_SECRETS = frozenset(
    {"OTP", "card number", "CVV", "card expiry", "PIN", "Aadhaar", "PAN", "account number"}
)

# Brands as they appear in page titles / text (lower-case).
_PAGE_BRANDS: tuple[tuple[str, str], ...] = (
    ("state bank", "SBI"),
    ("sbi", "SBI"),
    ("yono", "SBI YONO"),
    ("hdfc", "HDFC Bank"),
    ("icici", "ICICI Bank"),
    ("axis bank", "Axis Bank"),
    ("kotak", "Kotak"),
    ("punjab national", "PNB"),
    ("bank of baroda", "Bank of Baroda"),
    ("canara", "Canara Bank"),
    ("paytm", "Paytm"),
    ("phonepe", "PhonePe"),
    ("google pay", "Google Pay"),
    ("bhim", "BHIM"),
    ("npci", "NPCI"),
    ("income tax", "Income Tax Dept"),
    ("aadhaar", "UIDAI/Aadhaar"),
    ("uidai", "UIDAI/Aadhaar"),
    ("india post", "India Post"),
    ("epfo", "EPFO"),
    ("irctc", "IRCTC"),
    ("amazon", "Amazon"),
    ("flipkart", "Flipkart"),
    ("whatsapp", "WhatsApp"),
    ("reserve bank", "RBI"),
    ("electricity", "Electricity board"),
    ("pm kisan", "PM-Kisan"),
)


def _field_text(i: PageInput) -> str:
    return " ".join((i.type, i.name, i.id, i.placeholder, i.autocomplete, i.label)).lower()


# Only fields a person types into; radios/checkboxes/buttons ("one time" donation) don't count.
TYPABLE = frozenset({"", "text", "tel", "number", "password", "email", "search", "textarea"})


def secrets_requested(inputs: list[PageInput]) -> list[str]:
    asked: list[str] = []
    for i in inputs:
        if i.type not in TYPABLE:
            continue
        blob = _field_text(i)
        labels = [
            label
            for label, pattern in _SECRET_FIELDS
            if (label == "password" and i.type == "password") or pattern.search(blob)
        ]
        if "OTP" in labels and "password" in labels and i.type != "password":
            labels.remove("password")  # a "one-time password" field is an OTP field
        asked.extend(label for label in labels if label not in asked)
    return asked


def brand_on_page(title: str, text: str) -> str:
    blob = f"{title}\n{text[:1500]}".lower()
    return next((name for needle, name in _PAGE_BRANDS if re.search(rf"\b{needle}\b", blob)), "")


def page_findings(facts: PageFacts) -> list[Finding]:
    pu = parse_url(facts.final_url)
    if pu is not None and is_official(pu.host, pu.registered_domain):
        return [Finding(Reason.OFFICIAL_DOMAIN, 0, pu.registered_domain)]
    host = pu.host if pu else facts.final_url[:60]
    out: list[Finding] = []
    if facts.apk_download:
        out.append(Finding(Reason.PAGE_DOWNLOADS_APK, 5, host))
    asked = secrets_requested(facts.inputs)
    if asked:
        # Ordinary logins are everywhere on the web; asking for money secrets on a landing
        # page is not.
        weight = 4 if FINANCIAL_SECRETS & set(asked) else 2
        out.append(Finding(Reason.PAGE_ASKS_CREDENTIALS, weight, ", ".join(asked[:4])))
    brand = brand_on_page(facts.title, facts.text)
    # A brand name alone is weak (news, reviews); with a login/OTP form it's impersonation.
    if brand and asked:
        out.append(Finding(Reason.PAGE_IMPERSONATES_BRAND, 5, brand))
    return out
