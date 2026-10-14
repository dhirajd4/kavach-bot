"""Cheap lexical URL checks (no network). Weak signals; lists and reputation are decisive."""

import re

from kavach.detectors.types import Finding, Reason
from kavach.detectors.url.extract import ParsedUrl, _is_ip
from kavach.intel.allowlist import is_official, is_shared_host

# Brands scammers impersonate in India. Short tokens must match a whole label part.
_BRANDS_LONG = (
    "hdfc",
    "icici",
    "axisbank",
    "kotak",
    "paytm",
    "phonepe",
    "googlepay",
    "gpay",
    "bhim",
    "npci",
    "aadhaar",
    "aadhar",
    "uidai",
    "incometax",
    "epfo",
    "irctc",
    "amazon",
    "flipkart",
    "meesho",
    "indiapost",
    "speedpost",
    "bluedart",
    "fedex",
    "airtel",
    "bsnl",
    "mahadiscom",
    "msedcl",
    "bescom",
    "tneb",
    "yono",
    "netbanking",
    "customs",
    "cybercrime",
    "digilocker",
)
_BRANDS_SHORT = ("sbi", "pnb", "rbi", "upi", "kyc", "jio", "boi", "trai", "ncb", "cbi")

_RISKY_TLDS = frozenset(
    {
        "xyz",
        "top",
        "icu",
        "shop",
        "live",
        "click",
        "link",
        "online",
        "site",
        "buzz",
        "cfd",
        "sbs",
        "rest",
        "quest",
        "monster",
        "cyou",
        "lol",
        "vip",
        "fun",
        "support",
        "help",
        "loan",
        "work",
        "cam",
        "bond",
        "today",
        "store",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
    }
)
_SHORTENERS = frozenset(
    {
        "bit.ly",
        "bitly.com",
        "tinyurl.com",
        "t.co",
        "cutt.ly",
        "is.gd",
        "rb.gy",
        "shorturl.at",
        "tiny.cc",
        "ow.ly",
        "s.id",
        "v.gd",
        "rebrand.ly",
        "t.ly",
        "goo.su",
        "shrtco.de",
        "short.gy",
        "surl.li",
        "wa.link",
        "tny.sh",
        "u.to",
    }
)
_SPLIT = re.compile(r"[.\-_]")


def _brand_hit(pu: ParsedUrl) -> str:
    labels = f"{pu.subdomain}.{pu.registered_domain}".lower()
    for brand in _BRANDS_LONG:
        if brand in labels:
            return brand
    parts = set(_SPLIT.split(labels))
    return next((b for b in _BRANDS_SHORT if b in parts), "")


def lexical_findings(pu: ParsedUrl) -> list[Finding]:
    if is_official(pu.host, pu.registered_domain):
        return [Finding(Reason.OFFICIAL_DOMAIN, 0, pu.registered_domain)]
    out: list[Finding] = []
    if _is_ip(pu.host):
        out.append(Finding(Reason.IP_ADDRESS_HOST, 3, pu.host))
    if "xn--" in pu.host:
        out.append(Finding(Reason.PUNYCODE_HOST, 3, pu.host))
    brand = _brand_hit(pu)
    if brand:
        out.append(Finding(Reason.BRAND_IMPERSONATION, 4, f"{brand} → {pu.host}"))
    last_label = pu.suffix.rsplit(".", 1)[-1] if pu.suffix else ""
    if last_label in _RISKY_TLDS:
        out.append(Finding(Reason.RISKY_TLD, 1, f".{pu.suffix}"))
    if pu.registered_domain in _SHORTENERS or pu.host in _SHORTENERS:
        out.append(Finding(Reason.SHORTENED_URL, 1, pu.host))
    if pu.explicit_scheme and pu.scheme == "http" and not is_shared_host(pu.registered_domain):
        out.append(Finding(Reason.NO_HTTPS, 0.5, pu.host))
    if pu.url.lower().split("?", 1)[0].endswith(".apk"):
        out.append(Finding(Reason.APK_LINK, 4, pu.host))
    return out
