"""Flag pattern detector — scans text and structured data for CTF flag patterns."""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.schemas.active_recon import FlagMatch, FlagResult


@dataclass(slots=True)
class _TextSource:
    text: str
    source: str
    url: str = ""


class FlagDetector:
    """Compiles user-supplied regex patterns and scans collected evidence for flags."""

    def __init__(self, patterns: list[str] | None = None) -> None:
        raw = patterns or [
            r"CTF\{[^}]+\}",
            r"FLAG\{[^}]+\}",
            r"flag\{[^}]+\}",
            r"THM\{[^}]+\}",
            r"DICT\{[^}]+\}",
            r"H4G\{[^}]+\}",
        ]
        self._compiled: list[tuple[str, re.Pattern[str]]] = []
        for pattern in raw:
            try:
                self._compiled.append((pattern, re.compile(pattern)))
            except re.error:
                continue

    def scan_text(self, text: str, source: str, url: str = "") -> list[FlagMatch]:
        """Scan a text blob for matching flag patterns."""
        matches: list[FlagMatch] = []
        seen: set[str] = set()
        for pattern_str, regex in self._compiled:
            for match in regex.finditer(text):
                value = match.group(0)
                key = f"{source}:{value}"
                if key in seen:
                    continue
                seen.add(key)
                start = max(0, match.start() - 60)
                end = min(len(text), match.end() + 60)
                context = text[start:end].replace("\n", " ").strip()
                matches.append(FlagMatch(
                    pattern=pattern_str,
                    value=value,
                    source=source,
                    url=url,
                    context=context,
                ))
        return matches

    def scan_sources(self, sources: list[_TextSource]) -> FlagResult:
        """Scan multiple text sources and aggregate results."""
        all_matches: list[FlagMatch] = []
        seen_values: set[str] = set()
        for src in sources:
            for match in self.scan_text(src.text, src.source, src.url):
                if match.value not in seen_values:
                    seen_values.add(match.value)
                    all_matches.append(match)
        return FlagResult(
            matches=all_matches,
            patterns_used=[p for p, _ in self._compiled],
        )

    def scan_dict(self, data: dict[str, str], source: str, url: str = "") -> list[FlagMatch]:
        """Scan a dict's keys and values (e.g. cookies, storage) for flags."""
        matches: list[FlagMatch] = []
        for key, value in data.items():
            matches.extend(self.scan_text(f"{key}={value}", source, url))
        return matches
