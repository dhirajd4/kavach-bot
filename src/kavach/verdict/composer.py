"""Compose exactly ONE WhatsApp reply per check (cost guardrail, TDS §8.1)."""

import logging

from kavach.llm.base import Explanation, ExplanationProvider
from kavach.llm.template import TemplateProvider
from kavach.verdict.rules import Decision, Verdict
from kavach.verdict.templates import ADVICE, FOOTER, HEADLINE, WELCOME

log = logging.getLogger(__name__)

_template = TemplateProvider()


async def explain(
    decision: Decision, language: str, provider: ExplanationProvider | None
) -> Explanation:
    if provider is not None and decision.top:
        try:
            result = await provider.explain(decision, language)
            if result is not None and result.lines:
                return result
        except Exception as exc:  # noqa: BLE001 - any provider failure falls back to templates
            log.warning(
                "llm explain failed", extra={"provider": provider.name, "error": str(exc)[:200]}
            )
    return await _template.explain(decision, language)


def render(
    decision: Decision,
    explanation: Explanation,
    language: str,
    *,
    first_time: bool,
    extra_advice: str = "",
) -> str:
    if decision.verdict is Verdict.NOTHING_TO_CHECK:
        return WELCOME[language]
    parts = [HEADLINE[decision.verdict][language]]
    if explanation.lines:
        parts.append("\n".join(f"• {line}" for line in explanation.lines))
    parts.append(ADVICE[decision.verdict][language])
    if extra_advice:
        parts.append(extra_advice)
    parts.append(FOOTER[language])
    body = "\n\n".join(parts)
    if first_time:
        body = WELCOME[language] + "\n\n━━━━━━━━━━\n\n" + body
    return body
