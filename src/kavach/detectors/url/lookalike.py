"""Look-alike (typosquat / homoglyph) detection against official Indian domains.

hdfcbnak.com ≈ hdfcbank.com · icicibank.co ≈ icicibank.com · paytrn.com ≈ paytm.com (rn → m)
"""

from functools import lru_cache

from kavach.detectors.types import Finding, Reason
from kavach.detectors.url.extract import _TLD, ParsedUrl
from kavach.intel.allowlist import OFFICIAL_DOMAINS, is_official, is_shared_host

MIN_LABEL = 5  # shorter brand labels (sbi, jio) are too collision-prone for edit distance

_HOMOGLYPHS = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
    ("0", "o"),
    ("1", "l"),
    ("3", "e"),
    ("5", "s"),
    ("8", "b"),
    ("@", "a"),
    ("$", "s"),
)


@lru_cache(maxsize=1)
def _official_labels() -> dict[str, str]:
    out: dict[str, str] = {}
    for domain in OFFICIAL_DOMAINS:
        label = _TLD(domain).domain
        if len(label) >= MIN_LABEL:
            out.setdefault(label, domain)
    return out


def _skeleton(label: str) -> str:
    s = label.lower().replace("-", "")
    for a, b in _HOMOGLYPHS:
        s = s.replace(a, b)
    return s


def _distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment)."""
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def lookalike_of(pu: ParsedUrl) -> str:
    """Official domain this URL imitates, or ''."""
    registered = pu.registered_domain.lower()
    if (
        is_official(pu.host, registered)
        or registered in OFFICIAL_DOMAINS
        or is_shared_host(registered)
    ):
        return ""  # sites.google.com is Google's own (shared) platform, not a look-alike
    label = _TLD(pu.registered_domain).domain.lower()
    if len(label) < MIN_LABEL - 1:
        return ""
    skel = _skeleton(label)
    for official_label, official_domain in _official_labels().items():
        if label == official_label:
            return official_domain  # same name, different ending: hdfcbank.co
        # Short names collide with real sites (swiggy/twiggy), so they must match exactly after
        # homoglyph folding (paytrn → paytm); longer names allow typos (hdfcbnak → hdfcbank).
        n = len(official_label)
        max_d = 0 if n <= 6 else 1 if n <= 10 else 2
        if abs(len(skel) - len(official_label)) <= max_d and (
            skel == official_label or _distance(skel, official_label) <= max_d
        ):
            return official_domain
    return ""


def lookalike_findings(pu: ParsedUrl) -> list[Finding]:
    target = lookalike_of(pu)
    if not target:
        return []
    return [Finding(Reason.LOOKALIKE_DOMAIN, 5, f"{pu.registered_domain} ≈ {target}")]
