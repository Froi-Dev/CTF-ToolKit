from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass

from app.core.flag_detection import DetectedFlag

_COMMON_WORDS = (
    " the ",
    " and ",
    " this ",
    " that ",
    " flag",
    "ctf",
    "password",
    "secret",
    "token",
    "http",
    "user",
    "key",
)
_COMMON_BIGRAMS = {
    "al", "an", "ar", "as", "at", "ed", "en", "er", "es", "ha", "he",
    "in", "io", "is", "it", "le", "nd", "ng", "nt", "of", "on", "or",
    "ou", "re", "se", "st", "te", "th", "ti", "to", "ve", "yo",
}


@dataclass(frozen=True, slots=True)
class ScoreComponents:
    printable: float
    utf8: float
    language: float
    structure: float
    flag_bonus: float
    entropy: float


@dataclass(frozen=True, slots=True)
class ScoredBytes:
    total: float
    components: ScoreComponents


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _language_score(text: str) -> float:
    if not text:
        return 0.0
    lowered = f" {text.lower()} "
    letters_and_spaces = sum(character.isalpha() or character.isspace() for character in text)
    natural_ratio = letters_and_spaces / len(text)
    word_hits = sum(word in lowered for word in _COMMON_WORDS)
    word_score = min(1.0, word_hits / 3)

    letters = [character.lower() for character in text if character.isalpha()]
    vowel_score = 0.0
    bigram_score = 0.0
    if letters:
        vowel_ratio = sum(character in "aeiou" for character in letters) / len(letters)
        vowel_score = max(0.0, 1.0 - abs(vowel_ratio - 0.38) / 0.38)
    if len(letters) > 1:
        bigram_hits = sum(
            "".join(letters[index : index + 2]) in _COMMON_BIGRAMS
            for index in range(len(letters) - 1)
        )
        bigram_ratio = bigram_hits / (len(letters) - 1)
        bigram_score = min(1.0, bigram_ratio / 0.45)
    return min(
        1.0,
        natural_ratio * 0.30
        + vowel_score * 0.15
        + word_score * 0.25
        + bigram_score * 0.30,
    )


def _structure_score(text: str) -> float:
    score = 0.0
    stripped = text.strip()
    if not stripped:
        return score
    if "{" in stripped and "}" in stripped:
        score += 0.35
    if any(marker in stripped.lower() for marker in ("http://", "https://", "=", "://")):
        score += 0.25
    if "\n" in stripped or " " in stripped:
        score += 0.15
    if stripped[:1] in "[{" and stripped[-1:] in "]}":
        try:
            json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            pass
        else:
            score += 0.35
    return min(1.0, score)


def score_bytes(data: bytes, flags: list[DetectedFlag]) -> ScoredBytes:
    if not data:
        return ScoredBytes(0.0, ScoreComponents(0.0, 0.0, 0.0, 0.0, 0.0, 0.0))

    sample = data[:32_768]
    try:
        text = sample.decode("utf-8")
        utf8 = 1.0
    except UnicodeDecodeError:
        text = sample.decode("latin-1")
        utf8 = 0.0

    printable = sum(
        character.isprintable() or character in "\r\n\t" for character in text
    ) / len(text)
    language = _language_score(text)
    structure = _structure_score(text)
    flag_bonus = 1.0 if flags else 0.0
    entropy = _shannon_entropy(sample)

    total = (
        printable * 0.38
        + utf8 * 0.14
        + language * 0.25
        + structure * 0.08
        + flag_bonus * 0.35
    )
    if b"\x00" in sample:
        total -= min(0.25, sample.count(0) / len(sample))
    total = round(max(0.0, min(1.0, total)), 4)
    return ScoredBytes(
        total,
        ScoreComponents(
            printable=round(printable, 4),
            utf8=utf8,
            language=round(language, 4),
            structure=round(structure, 4),
            flag_bonus=flag_bonus,
            entropy=round(entropy, 4),
        ),
    )


def quick_text_score(data: bytes) -> float:
    """Cheap ranker used to limit exhaustive single-byte XOR output."""
    if not data:
        return 0.0
    sample = data[:4_096]
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in sample) / len(sample)
    common = sum(byte in b" etaoinETAOIN{}_" for byte in sample) / len(sample)
    return printable * 0.7 + common * 0.3
