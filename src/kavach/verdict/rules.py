"""Deterministic verdict. Rules decide; the LLM (M5) only explains (TDS §8, §10.1)."""

from dataclasses import dataclass
from enum import StrEnum

from kavach.detectors.types import Finding, Reason

SCAM_THRESHOLD = 7.0
SUSPICIOUS_THRESHOLD = 3.0
MAX_REASONS_SHOWN = 4


class Verdict(StrEnum):
    SCAM = "scam"
    SUSPICIOUS = "suspicious"
    LOOKS_SAFE = "looks_safe"  # only when every link is an official domain and text is clean
    NO_RISK_FOUND = "no_risk_found"  # nothing known-bad; not a guarantee
    NOTHING_TO_CHECK = "nothing_to_check"


@dataclass(frozen=True, slots=True)
class Decision:
    verdict: Verdict
    score: float
    top: tuple[Finding, ...]  # strongest reasons first, for the explanation
    reason_codes: tuple[str, ...]


def decide(findings: list[Finding], *, had_content: bool, urls_checked: int) -> Decision:
    # Each signal type counts once, at its strongest (TDS §6.2: weights capped per signal type),
    # so three links with the same weakness don't triple the score.
    strongest: dict[str, Finding] = {}
    for f in findings:
        if f.weight > 0:
            cur = strongest.get(f.reason.value)
            if cur is None or (f.decisive, f.weight) > (cur.decisive, cur.weight):
                strongest[f.reason.value] = f
    risky = list(strongest.values())
    score = round(sum(f.weight for f in risky), 2)
    top = tuple(
        sorted(risky, key=lambda f: (f.decisive, f.weight), reverse=True)[:MAX_REASONS_SHOWN]
    )
    codes = tuple(sorted({f.reason.value for f in findings}))

    if any(f.decisive for f in risky) or score >= SCAM_THRESHOLD:
        verdict = Verdict.SCAM
    elif score >= SUSPICIOUS_THRESHOLD:
        verdict = Verdict.SUSPICIOUS
    elif not had_content:
        verdict = Verdict.NOTHING_TO_CHECK
    elif urls_checked and score == 0 and _all_official(findings, urls_checked):
        verdict = Verdict.LOOKS_SAFE
    else:
        verdict = Verdict.NO_RISK_FOUND
    return Decision(verdict, score, top, codes)


def _all_official(findings: list[Finding], urls_checked: int) -> bool:
    return sum(1 for f in findings if f.reason is Reason.OFFICIAL_DOMAIN) >= urls_checked
