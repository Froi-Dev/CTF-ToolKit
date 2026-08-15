from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

from app.core.flag_detection import DetectedFlag, FlagDetector


@dataclass(frozen=True, slots=True)
class RawFlagMatch:
    detected: DetectedFlag
    encoding: str


class RawFlagHunter:
    """Cheap first-pass flag scan over raw and UTF-16 capture representations."""

    def __init__(self, prefixes: list[str], *, maximum_matches: int = 1_000) -> None:
        self._detector = FlagDetector(prefixes)
        self._maximum_matches = maximum_matches

    def analyze(self, path: Path) -> tuple[RawFlagMatch, ...]:
        matches: list[RawFlagMatch] = []
        seen: set[tuple[str, str]] = set()
        chunk_size = 1024 * 1024
        overlap_size = 4096
        overlap = b""
        consumed = 0

        with path.open("rb") as source:
            while chunk := source.read(chunk_size):
                data = overlap + chunk
                data_offset = consumed - len(overlap)
                raw = [
                    replace(item, offset=data_offset + item.offset)
                    for item in self._detector.detect(data)
                ]
                self._add(matches, seen, raw, "ASCII / UTF-8")
                for codec, label in (("utf-16le", "UTF-16LE"), ("utf-16be", "UTF-16BE")):
                    for alignment in (0, 1):
                        decoded = data[alignment:].decode(codec, errors="ignore").encode("utf-8")
                        wide = [
                            replace(
                                item,
                                offset=max(0, data_offset + alignment + item.offset * 2),
                            )
                            for item in self._detector.detect(decoded)
                        ]
                        self._add(matches, seen, wide, label)
                consumed += len(chunk)
                overlap = data[-overlap_size:]
                if len(matches) >= self._maximum_matches:
                    break
        return tuple(matches[: self._maximum_matches])

    def _add(
        self,
        target: list[RawFlagMatch],
        seen: set[tuple[str, str]],
        detected: list[DetectedFlag],
        encoding: str,
    ) -> None:
        for item in detected:
            key = (item.value, encoding)
            if key in seen or len(target) >= self._maximum_matches:
                continue
            seen.add(key)
            target.append(RawFlagMatch(item, encoding))


def normalize_flag_prefix(custom_prefix: str | None) -> str | None:
    if custom_prefix is None:
        return None
    value = custom_prefix.strip()
    if value.endswith("{"):
        value = value[:-1]
    if not value:
        return None
    if len(value) > 64 or any(ord(character) < 33 or ord(character) > 126 for character in value):
        raise ValueError("The custom flag prefix must be 1-64 printable ASCII characters.")
    if any(character in "{}" for character in value):
        raise ValueError("The custom flag prefix must not contain braces except for one trailing '{'.")
    return value
