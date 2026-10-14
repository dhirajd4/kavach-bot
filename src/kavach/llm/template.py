"""Deterministic template explanations. Always available; the fallback for every LLM provider."""

from kavach.llm.base import Explanation
from kavach.verdict.rules import Decision
from kavach.verdict.templates import REASON


class TemplateProvider:
    name = "template"

    async def explain(self, decision: Decision, language: str) -> Explanation:
        lines: list[str] = []
        seen: set[str] = set()
        for f in decision.top:
            copy = REASON.get(f.reason, {}).get(language)
            if not copy:
                continue
            line = copy.format(e=f.evidence) if "{e}" in copy else copy
            if line not in seen:
                seen.add(line)
                lines.append(line)
        return Explanation(lines=lines, provider=self.name)
