from __future__ import annotations

import re
from collections.abc import Iterable


MAX_SIMILARITY_BYTES = 131_072
MAX_SIMILARITY_TOKENS = 4_096
_TOKEN_RE = re.compile(rb"[a-z0-9_./:@-]{2,64}", re.I)


def _tokens(body: bytes, substitutions: Iterable[str]) -> set[bytes]:
    sample = body[:MAX_SIMILARITY_BYTES].lower()
    for value in substitutions:
        encoded = value.encode("utf-8", errors="ignore").lower()
        if encoded:
            sample = sample.replace(encoded, b" ")
    found: set[bytes] = set()
    for match in _TOKEN_RE.finditer(sample):
        found.add(match.group())
        if len(found) >= MAX_SIMILARITY_TOKENS:
            break
    return found


def bounded_body_similarity(
    left: bytes,
    right: bytes,
    *,
    left_substitutions: Iterable[str] = (),
    right_substitutions: Iterable[str] = (),
) -> float:
    """Return a deterministic, linear-time approximation for bounded HTTP bodies."""
    if left == right:
        return 1.0
    if not left or not right:
        return 0.0

    maximum_length = max(len(left), len(right))
    length_similarity = 1.0 - abs(len(left) - len(right)) / maximum_length
    left_tokens = _tokens(left, left_substitutions)
    right_tokens = _tokens(right, right_substitutions)
    if not left_tokens or not right_tokens:
        return round(max(0.0, length_similarity * 0.25), 4)

    union = left_tokens | right_tokens
    token_similarity = len(left_tokens & right_tokens) / len(union) if union else 1.0
    return round(token_similarity * 0.85 + length_similarity * 0.15, 4)
