from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DetectedFlag:
    value: str
    matched_pattern: str
    offset: int
    confidence: float
    context: str


class FlagDetector:
    """Detect bounded prefix-based flag patterns without user-supplied regex."""

    def __init__(self, prefixes: list[str]) -> None:
        alternatives = b"|".join(re.escape(prefix.encode("ascii")) for prefix in prefixes)
        self._pattern = re.compile(
            rb"(?P<prefix>" + alternatives + rb")\{(?P<body>[^{}\r\n]{1,256})\}"
        )

    def detect(self, data: bytes) -> list[DetectedFlag]:
        matches: list[DetectedFlag] = []
        for match in self._pattern.finditer(data):
            start, end = match.span()
            context_start = max(0, start - 32)
            context_end = min(len(data), end + 32)
            matches.append(
                DetectedFlag(
                    value=match.group(0).decode("utf-8", errors="replace"),
                    matched_pattern=f"{match.group('prefix').decode('ascii')}{{...}}",
                    offset=start,
                    confidence=0.95,
                    context=data[context_start:context_end].decode("utf-8", errors="replace"),
                )
            )
        return matches
