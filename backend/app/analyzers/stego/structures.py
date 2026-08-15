from __future__ import annotations

import zlib
from dataclasses import dataclass

from app.schemas.stego import JpegSegment, PngChunk

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SIGNATURE = b"\xff\xd8\xff"


@dataclass(frozen=True, slots=True)
class StructureResult:
    logical_end: int | None
    warnings: tuple[str, ...]
    truncated: bool


def parse_png(
    data: bytes, max_results: int
) -> tuple[list[PngChunk], StructureResult]:
    if not data.startswith(PNG_SIGNATURE):
        raise ValueError("not a PNG image")
    chunks: list[PngChunk] = []
    warnings: list[str] = []
    cursor = len(PNG_SIGNATURE)
    index = 0
    logical_end: int | None = None
    truncated = False

    while cursor < len(data):
        if cursor + 12 > len(data):
            warnings.append(f"PNG chunk header at offset {cursor} is truncated.")
            break
        length = int.from_bytes(data[cursor : cursor + 4], "big")
        end = cursor + 12 + length
        if end > len(data):
            warnings.append(
                f"PNG chunk at offset {cursor} declares {length} bytes beyond the file boundary."
            )
            break
        raw_type = data[cursor + 4 : cursor + 8]
        chunk_type = raw_type.decode("ascii", errors="replace")
        expected = int.from_bytes(data[cursor + 8 + length : end], "big")
        actual = zlib.crc32(data[cursor + 4 : cursor + 8 + length]) & 0xFFFFFFFF
        if len(chunks) < max_results:
            chunks.append(
                PngChunk(
                    index=index,
                    chunk_type=chunk_type,
                    offset=cursor,
                    data_length=length,
                    critical=bool(raw_type) and not bool(raw_type[0] & 0x20),
                    crc_expected=f"{expected:08x}",
                    crc_actual=f"{actual:08x}",
                    crc_valid=expected == actual,
                )
            )
        else:
            truncated = True
        if expected != actual:
            warnings.append(f"PNG chunk {chunk_type} at offset {cursor} has an invalid CRC.")
        if index == 0 and chunk_type != "IHDR":
            warnings.append("PNG does not begin with an IHDR chunk.")
        index += 1
        cursor = end
        if chunk_type == "IEND":
            logical_end = end
            break

    if logical_end is None:
        warnings.append("PNG IEND chunk was not found.")
    return chunks, StructureResult(logical_end, tuple(warnings), truncated)


_MARKER_NAMES: dict[int, str] = {
    0x01: "TEM",
    0xC0: "SOF0 (baseline)",
    0xC1: "SOF1",
    0xC2: "SOF2 (progressive)",
    0xC3: "SOF3 (lossless)",
    0xC4: "DHT",
    0xC5: "SOF5",
    0xC6: "SOF6",
    0xC7: "SOF7",
    0xC8: "JPG",
    0xC9: "SOF9",
    0xCA: "SOF10",
    0xCB: "SOF11",
    0xCC: "DAC",
    0xCD: "SOF13",
    0xCE: "SOF14",
    0xCF: "SOF15",
    0xD8: "SOI",
    0xD9: "EOI",
    0xDA: "SOS",
    0xDB: "DQT",
    0xDC: "DNL",
    0xDD: "DRI",
    0xDE: "DHP",
    0xDF: "EXP",
    0xE0: "APP0 (JFIF)",
    0xE1: "APP1 (EXIF/XMP)",
    0xE2: "APP2 (ICC)",
    0xED: "APP13 (IPTC)",
    0xEE: "APP14 (Adobe)",
    0xFE: "COM",
}


def _marker_name(marker: int) -> str:
    if 0xD0 <= marker <= 0xD7:
        return f"RST{marker - 0xD0}"
    if 0xE0 <= marker <= 0xEF:
        return f"APP{marker - 0xE0}"
    return _MARKER_NAMES.get(marker, f"Marker FF{marker:02X}")


def _next_scan_marker(data: bytes, start: int) -> int | None:
    cursor = start
    while cursor + 1 < len(data):
        if data[cursor] != 0xFF:
            cursor += 1
            continue
        lookahead = cursor + 1
        while lookahead < len(data) and data[lookahead] == 0xFF:
            lookahead += 1
        if lookahead >= len(data):
            return None
        marker = data[lookahead]
        if marker == 0x00 or 0xD0 <= marker <= 0xD7:
            cursor = lookahead + 1
            continue
        return cursor
    return None


def parse_jpeg(
    data: bytes, max_results: int
) -> tuple[list[JpegSegment], StructureResult]:
    if not data.startswith(JPEG_SIGNATURE):
        raise ValueError("not a JPEG image")
    segments: list[JpegSegment] = []
    warnings: list[str] = []
    cursor = 0
    index = 0
    logical_end: int | None = None
    truncated = False

    while cursor + 1 < len(data):
        if data[cursor] != 0xFF:
            warnings.append(f"Unexpected JPEG data outside a scan at offset {cursor}.")
            next_marker = data.find(b"\xff", cursor + 1)
            if next_marker < 0:
                break
            cursor = next_marker
        marker_start = cursor
        while cursor < len(data) and data[cursor] == 0xFF:
            cursor += 1
        if cursor >= len(data):
            break
        marker = data[cursor]
        cursor += 1
        if marker == 0x00:
            continue

        standalone = marker in {0x01, 0xD8, 0xD9} or 0xD0 <= marker <= 0xD7
        if standalone:
            segment_length = cursor - marker_start
        else:
            if cursor + 2 > len(data):
                warnings.append(f"JPEG marker FF{marker:02X} has a truncated length field.")
                break
            declared = int.from_bytes(data[cursor : cursor + 2], "big")
            if declared < 2 or cursor + declared > len(data):
                warnings.append(f"JPEG marker FF{marker:02X} has an invalid segment length.")
                break
            cursor += declared
            segment_length = cursor - marker_start

        if len(segments) < max_results:
            segments.append(
                JpegSegment(
                    index=index,
                    marker=f"FF{marker:02X}",
                    name=_marker_name(marker),
                    offset=marker_start,
                    segment_length=segment_length,
                )
            )
        else:
            truncated = True
        index += 1

        if marker == 0xD9:
            logical_end = cursor
            break
        if marker == 0xDA:
            next_marker = _next_scan_marker(data, cursor)
            if next_marker is None:
                warnings.append("JPEG entropy-coded scan has no terminating marker.")
                break
            cursor = next_marker

    if logical_end is None:
        warnings.append("JPEG EOI marker was not found.")
    return segments, StructureResult(logical_end, tuple(warnings), truncated)
