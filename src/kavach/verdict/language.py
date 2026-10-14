"""Pick the reply language from the user's own words (stored as their preference)."""

import re

from kavach.verdict.templates import DEFAULT_LANG

_DEVANAGARI = re.compile(r"[ऀ-ॿ]")
_LATIN = re.compile(r"[A-Za-z]")
_HINGLISH_WORDS = re.compile(
    r"\b(hai|hain|kya|nahi|nahin|aap|aapka|apna|karo|karein|kijiye|mein|mai|hum|yeh|ye|"
    r"kaise|kyun|bhai|bhej|paisa|paise|kar|ka|ki|ke|ko|se|ho|tha|thi|raha|rahi)\b",
    re.IGNORECASE,
)

COMMANDS = {
    "hindi": "hi",
    "हिंदी": "hi",
    "हिन्दी": "hi",
    "hinglish": "hinglish",
    "english": "en",
    "angrezi": "en",
}


def language_command(text: str) -> str | None:
    return COMMANDS.get(text.strip().strip(".!").casefold())


def detect_language(text: str) -> str:
    deva = len(_DEVANAGARI.findall(text))
    latin = len(_LATIN.findall(text))
    if deva and deva >= latin:
        return "hi"
    if latin:
        return "hinglish" if len(_HINGLISH_WORDS.findall(text)) >= 2 else "en"
    return DEFAULT_LANG
