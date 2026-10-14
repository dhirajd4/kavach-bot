"""Golden corpus: every seed scam must be caught, no benign message may be flagged."""

import pytest

from kavach.pipeline import analyse_text
from kavach.verdict.rules import Verdict
from tests.fixtures.corpus import BENIGN, SCAMS

FLAGGED = {Verdict.SCAM, Verdict.SUSPICIOUS}


@pytest.mark.parametrize(("scenario", "text"), SCAMS, ids=[s for s, _ in SCAMS])
async def test_scam_flagged(scenario: str, text: str, redis, store) -> None:  # type: ignore[no-untyped-def]
    result = await analyse_text(text, redis, store)
    assert result.decision.verdict in FLAGGED, (scenario, result.decision)


@pytest.mark.parametrize("text", BENIGN)
async def test_benign_not_flagged(text: str, redis, store) -> None:  # type: ignore[no-untyped-def]
    result = await analyse_text(text, redis, store)
    assert result.decision.verdict not in FLAGGED, (text, result.decision)


async def test_corpus_report(redis, store) -> None:  # type: ignore[no-untyped-def]
    """Prints per-scenario precision/recall so regressions are visible in CI logs."""
    caught = [
        s for s, t in SCAMS if (await analyse_text(t, redis, store)).decision.verdict in FLAGGED
    ]
    false_alarms = [
        t for t in BENIGN if (await analyse_text(t, redis, store)).decision.verdict in FLAGGED
    ]
    tp, fp = len(caught), len(false_alarms)
    recall = tp / len(SCAMS)
    precision = tp / (tp + fp) if tp + fp else 1.0
    print(
        f"\ncorpus: recall={recall:.2f} precision={precision:.2f} "
        f"({tp}/{len(SCAMS)} scams, {fp} false alarms on {len(BENIGN)} benign)"
    )
    assert recall >= 0.9 and precision >= 0.95
