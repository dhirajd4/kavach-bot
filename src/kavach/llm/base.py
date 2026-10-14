"""Explanation provider interface. The LLM only *phrases* an explanation from reason codes
and short evidence; it never sees the user's message and never changes the verdict."""

from dataclasses import dataclass
from typing import Protocol

from kavach.verdict.rules import Decision


@dataclass(frozen=True, slots=True)
class Explanation:
    lines: list[str]
    provider: str


class ExplanationProvider(Protocol):
    name: str

    async def explain(self, decision: Decision, language: str) -> Explanation | None:
        """Return None to fall back to templates."""
        ...
