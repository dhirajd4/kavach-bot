"""Explainable lexical URL features (TDS §10.2: entropy and character-pattern features).

Hand-weighted for now; these same features feed a trained GBDT once labelled data exists.
"""

import math
import re
from collections import Counter
from dataclasses import dataclass

from kavach.detectors.types import Finding, Reason
from kavach.detectors.url.extract import ParsedUrl
from kavach.intel.allowlist import is_official, is_shared_host

_PATH_BAIT = re.compile(
    r"login|log-in|signin|verify|verification|update|secure|account|kyc|reward|claim|bonus|"
    r"gift|refund|unlock|suspend|confirm|wallet|otp|aadhaar|pan-?card|netbanking",
    re.IGNORECASE,
)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


@dataclass(frozen=True)
class UrlFeatures:
    length: int
    host_entropy: float
    host_digits: int
    hyphens: int
    subdomain_depth: int
    bait_words: tuple[str, ...]
    has_at: bool


def features(pu: ParsedUrl) -> UrlFeatures:
    label = pu.registered_domain.split(".")[0]
    return UrlFeatures(
        length=len(pu.url),
        host_entropy=round(entropy(label), 2),
        host_digits=sum(ch.isdigit() for ch in pu.host),
        hyphens=pu.host.count("-"),
        subdomain_depth=len([p for p in pu.subdomain.split(".") if p and p != "www"]),
        bait_words=tuple(sorted({m.lower() for m in _PATH_BAIT.findall(pu.url)}))[:4],
        has_at="@" in pu.url.split("://", 1)[-1].split("/", 1)[0],
    )


def feature_findings(pu: ParsedUrl) -> list[Finding]:
    if is_official(pu.host, pu.registered_domain):
        return []
    f = features(pu)
    reasons: list[str] = []
    if f.host_entropy >= 3.6 and len(pu.registered_domain.split(".")[0]) >= 12:
        reasons.append("random-looking name")
    if f.host_digits >= 4:
        reasons.append("many digits")
    if f.hyphens >= 3:
        reasons.append("many hyphens")
    if f.subdomain_depth >= 3 and not is_shared_host(pu.registered_domain):
        reasons.append("deep subdomains")
    if len(f.bait_words) >= 2:
        reasons.append("words: " + "/".join(f.bait_words[:3]))
    if f.length > 120:
        reasons.append("very long")
    if f.has_at:
        reasons.append("hidden '@' trick")
    if len(reasons) < 2 and not f.has_at:
        return []  # one odd feature is normal on the web
    weight = min(2.0, 0.75 * len(reasons))
    return [Finding(Reason.URL_LEXICAL_RISK, weight, ", ".join(reasons[:3]))]
