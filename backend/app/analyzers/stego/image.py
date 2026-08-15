from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from PIL import ExifTags, Image, UnidentifiedImageError

from app.analyzers.forensics.signatures import root_signature, scan_signatures
from app.analyzers.stego.structures import JPEG_SIGNATURE, PNG_SIGNATURE, parse_jpeg, parse_png
from app.core.analyzers import BaseAnalyzer
from app.core.errors import InvalidArtifactError
from app.core.flag_detection import FlagDetector
from app.schemas.forensics import EntropyResult, Hashes
from app.schemas.stego import (
    BitPlaneResult,
    CarvedArtifact,
    ChannelInspection,
    EntropyAnalysis,
    ImageMetadataEntry,
    ImageSummary,
    LsbAnalysis,
    LsbSignature,
    SignatureCandidate,
    StegoAnalysisResponse,
    StegoFlagCandidate,
    StegoLimits,
    TrailingBytes,
)

_FLAG_PREFIXES = ["CTF", "FLAG", "HTB", "PICOCTF", "DUCTF", "SEC"]
_PRINTABLE = set(range(32, 127)) | {9, 10, 13}
_ASCII_PREVIEW = 160
_HEX_PREVIEW_BYTES = 96


@dataclass(frozen=True, slots=True)
class StegoPolicy:
    max_upload_bytes: int = 32 * 1024 * 1024
    max_pixels: int = 16_000_000
    max_png_chunks: int = 512
    max_jpeg_segments: int = 512
    max_lsb_bytes: int = 2 * 1024 * 1024
    max_signature_matches: int = 64
    max_carved_bytes: int = 32 * 1024 * 1024
    max_metadata_entries: int = 128


@dataclass(frozen=True, slots=True)
class StegoInput:
    path: Path
    original_filename: str
    artifact_id: str
    workspace: Path


def _hashes(data: bytes) -> Hashes:
    return Hashes(
        md5=hashlib.md5(data).hexdigest(),
        sha1=hashlib.sha1(data).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _entropy(data: bytes) -> EntropyResult:
    if not data:
        return EntropyResult(bits_per_byte=0.0, classification="very-low", sample_size=0)
    counts = Counter(data)
    bits_per_byte = -sum(
        (count / len(data)) * math.log2(count / len(data)) for count in counts.values()
    )
    if bits_per_byte < 2.0:
        classification = "very-low"
    elif bits_per_byte < 4.0:
        classification = "low"
    elif bits_per_byte < 6.5:
        classification = "normal"
    elif bits_per_byte < 7.5:
        classification = "high"
    else:
        classification = "very-high"
    return EntropyResult(
        bits_per_byte=round(bits_per_byte, 4),
        classification=classification,
        sample_size=len(data),
    )


def _binary_entropy(ones: int, total: int) -> float:
    if total <= 0 or ones in {0, total}:
        return 0.0
    ratio = ones / total
    return round(-(ratio * math.log2(ratio) + (1 - ratio) * math.log2(1 - ratio)), 4)


def _ascii_preview(data: bytes, limit: int = _ASCII_PREVIEW) -> str:
    visible = bytearray()
    for value in data[:limit]:
        visible.append(value if value in _PRINTABLE and value not in {10, 13} else ord("."))
    return visible.decode("ascii", errors="replace")


def _preview_hex(data: bytes, limit: int = _HEX_PREVIEW_BYTES) -> str:
    return data[:limit].hex()


def _clean_metadata_value(value: object) -> str | int | float | bool:
    if isinstance(value, bool | int | float | str):
        return value if not isinstance(value, str) else value[:500]
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    return str(value)[:500]


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return round(sum(1 for value in data if value in _PRINTABLE) / len(data), 4)


def _flag_candidates(
    detector: FlagDetector, data: bytes, source: str, *, base_offset: int = 0
) -> list[StegoFlagCandidate]:
    return [
        StegoFlagCandidate(
            value=flag.value,
            matched_pattern=flag.matched_pattern,
            source=source,
            offset=base_offset + flag.offset,
            confidence=flag.confidence,
            context=flag.context,
        )
        for flag in detector.detect(data)
    ]


def _pack_lsb(samples: list[int], max_bytes: int) -> tuple[bytes, int, bool]:
    byte_count = min(len(samples) // 8, max_bytes)
    output = bytearray(byte_count)
    bit_index = 0
    for index in range(byte_count):
        value = 0
        for _ in range(8):
            value = (value << 1) | (samples[bit_index] & 1)
            bit_index += 1
        output[index] = value
    return bytes(output), len(samples), len(samples) // 8 > max_bytes


def _channel_names(mode: str) -> list[str]:
    if mode == "L":
        return ["L"]
    if mode == "RGBA":
        return ["R", "G", "B", "A"]
    return ["R", "G", "B"]


def _extract_channels(image: Image.Image) -> tuple[bytes, list[str], str, bool]:
    has_alpha = image.mode in {"RGBA", "LA"} or "transparency" in image.info
    if image.mode == "L":
        normalized = image
    elif has_alpha:
        normalized = image.convert("RGBA")
    else:
        normalized = image.convert("RGB")
    return normalized.tobytes(), _channel_names(normalized.mode), normalized.mode, has_alpha


def _channel_values(pixel_bytes: bytes, channel_count: int, channel_index: int) -> list[int]:
    return list(pixel_bytes[channel_index::channel_count])


def _channel_inspection(channel: str, values: list[int]) -> ChannelInspection:
    total = len(values)
    mean = sum(values) / total if total else 0.0
    variance = sum((value - mean) ** 2 for value in values) / total if total else 0.0
    ones = sum(value & 1 for value in values)
    return ChannelInspection(
        channel=channel,
        minimum=min(values) if values else 0,
        maximum=max(values) if values else 0,
        mean=round(mean, 4),
        standard_deviation=round(math.sqrt(variance), 4),
        entropy=_entropy(bytes(values)).bits_per_byte,
        lsb_zeros=total - ones,
        lsb_ones=ones,
        lsb_one_ratio=round(ones / total, 4) if total else 0.0,
    )


def _bit_planes(channel: str, values: list[int]) -> list[BitPlaneResult]:
    total = len(values)
    planes: list[BitPlaneResult] = []
    for bit in range(8):
        ones = sum((value >> bit) & 1 for value in values)
        ratio = ones / total if total else 0.0
        planes.append(
            BitPlaneResult(
                channel=channel,
                bit=bit,
                zeros=total - ones,
                ones=ones,
                one_ratio=round(ratio, 4),
                entropy=_binary_entropy(ones, total),
                biased=ratio < 0.1 or ratio > 0.9,
            )
        )
    return planes


def _zip_end(data: bytes, offset: int) -> int | None:
    search_end = min(len(data), offset + 128 * 1024 * 1024)
    cursor = data.find(b"PK\x05\x06", offset, search_end)
    while cursor >= 0 and cursor + 22 <= len(data):
        comment_length = int.from_bytes(data[cursor + 20 : cursor + 22], "little")
        end = cursor + 22 + comment_length
        if end <= len(data):
            return end
        cursor = data.find(b"PK\x05\x06", cursor + 1, search_end)
    return None


def _estimated_end(data: bytes, offset: int, detected_type: str) -> int | None:
    if detected_type == "png":
        marker = data.find(b"IEND", offset)
        return marker + 8 if marker >= 0 and marker + 8 <= len(data) else None
    if detected_type in {"jpeg", "gif"}:
        marker = data.find(b"\xff\xd9" if detected_type == "jpeg" else b";", offset)
        return marker + (2 if detected_type == "jpeg" else 1) if marker >= 0 else None
    if detected_type == "pdf":
        marker = data.find(b"%%EOF", offset)
        return marker + 5 if marker >= 0 else None
    if detected_type == "zip":
        return _zip_end(data, offset)
    return None


class ImageStegoAnalyzer(BaseAnalyzer[StegoInput, StegoAnalysisResponse]):
    name = "image-stego"
    category = "steganography"

    def __init__(self, policy: StegoPolicy | None = None) -> None:
        self.policy = policy or StegoPolicy()
        self._flags = FlagDetector(_FLAG_PREFIXES)

    def supports(self, artifact: StegoInput) -> bool:
        sample = artifact.path.read_bytes()[:8]
        return sample.startswith(PNG_SIGNATURE) or sample.startswith(JPEG_SIGNATURE)

    def analyze(self, artifact: StegoInput) -> StegoAnalysisResponse:
        data = artifact.path.read_bytes()
        if not data.startswith((PNG_SIGNATURE, JPEG_SIGNATURE)):
            raise InvalidArtifactError("Only PNG and JPEG images are supported for steganography analysis.")

        warnings: list[str] = []
        png_chunks = []
        jpeg_segments = []
        if data.startswith(PNG_SIGNATURE):
            image_format = "PNG"
            png_chunks, structure = parse_png(data, self.policy.max_png_chunks)
            png_truncated, jpeg_truncated = structure.truncated, False
        else:
            image_format = "JPEG"
            jpeg_segments, structure = parse_jpeg(data, self.policy.max_jpeg_segments)
            png_truncated, jpeg_truncated = False, structure.truncated
        warnings.extend(structure.warnings)
        logical_end = structure.logical_end or len(data)

        try:
            with Image.open(artifact.path, formats=("PNG", "JPEG")) as opened:
                width, height = opened.size
                if width * height > self.policy.max_pixels:
                    raise InvalidArtifactError(
                        f"Image has {width * height} pixels, exceeding the {self.policy.max_pixels}-pixel limit."
                    )
                opened.load()
                metadata = self._metadata(opened)
                pixel_bytes, channels, normalized_mode, has_alpha = _extract_channels(opened)
                frames = int(getattr(opened, "n_frames", 1) or 1)
                animated = bool(getattr(opened, "is_animated", False))
                mode = opened.mode
        except InvalidArtifactError:
            raise
        except (Image.DecompressionBombError, UnidentifiedImageError, OSError, ValueError) as exc:
            raise InvalidArtifactError(f"Image could not be decoded safely: {exc}") from exc

        metadata.insert(0, ImageMetadataEntry(key="format", value=image_format, source="container"))
        metadata.insert(1, ImageMetadataEntry(key="normalized_mode", value=normalized_mode, source="image"))
        metadata = metadata[: self.policy.max_metadata_entries]

        channel_count = len(channels)
        channel_values = {
            name: _channel_values(pixel_bytes, channel_count, index) for index, name in enumerate(channels)
        }
        inspections = [_channel_inspection(name, values) for name, values in channel_values.items()]
        bit_planes = [
            plane for name, values in channel_values.items() for plane in _bit_planes(name, values)
        ]
        lsb = self._lsb(channel_values, channels, warnings)

        trailing = data[logical_end:] if logical_end < len(data) else b""
        trailing_signature = root_signature(trailing) if trailing else None
        trailing_bytes = TrailingBytes(
            present=bool(trailing),
            offset=logical_end,
            size=len(trailing),
            detected_type=trailing_signature.name if trailing_signature else None,
            preview_hex=_preview_hex(trailing),
        )

        signatures, carved = self._signatures_and_carving(
            data, logical_end, artifact.artifact_id, artifact.workspace
        )
        flags = _flag_candidates(self._flags, data, "file")
        for result in lsb:
            flags.extend(result.flags)

        return StegoAnalysisResponse(
            analysis_id=str(uuid4()),
            artifact_id=artifact.artifact_id,
            analyzer=self.name,
            original_filename=artifact.original_filename,
            size=len(data),
            hashes=_hashes(data),
            image=ImageSummary(
                format=image_format,
                mode=mode,
                width=width,
                height=height,
                frames=frames,
                animated=animated,
                has_alpha=has_alpha,
            ),
            metadata=metadata,
            png_chunks=png_chunks,
            png_chunks_truncated=png_truncated,
            jpeg_segments=jpeg_segments,
            jpeg_segments_truncated=jpeg_truncated,
            trailing_bytes=trailing_bytes,
            channels=inspections,
            bit_planes=bit_planes,
            lsb=lsb,
            entropy=EntropyAnalysis(
                file=_entropy(data),
                pixel_data=_entropy(pixel_bytes),
                channels={name: _entropy(bytes(values)) for name, values in channel_values.items()},
            ),
            signatures=signatures,
            carved_artifacts=carved,
            flags=flags,
            warnings=warnings,
            limits=StegoLimits(
                max_upload_bytes=self.policy.max_upload_bytes,
                max_pixels=self.policy.max_pixels,
                max_png_chunks=self.policy.max_png_chunks,
                max_jpeg_segments=self.policy.max_jpeg_segments,
                max_lsb_bytes=self.policy.max_lsb_bytes,
                max_signature_matches=self.policy.max_signature_matches,
                max_carved_bytes=self.policy.max_carved_bytes,
            ),
        )

    def _metadata(self, image: Image.Image) -> list[ImageMetadataEntry]:
        entries: list[ImageMetadataEntry] = [
            ImageMetadataEntry(key="mode", value=image.mode, source="image"),
            ImageMetadataEntry(key="width", value=image.width, source="image"),
            ImageMetadataEntry(key="height", value=image.height, source="image"),
        ]
        for key, value in sorted(image.info.items(), key=lambda item: str(item[0])):
            source = "png-text" if image.format == "PNG" and isinstance(value, str) else "image"
            entries.append(
                ImageMetadataEntry(key=str(key), value=_clean_metadata_value(value), source=source)
            )
        try:
            exif = image.getexif()
        except (AttributeError, OSError, ValueError):
            exif = {}
        for tag, value in exif.items():
            name = ExifTags.TAGS.get(tag, str(tag))
            entries.append(
                ImageMetadataEntry(
                    key=f"EXIF.{name}",
                    value=_clean_metadata_value(value),
                    source="exif",
                )
            )
        return entries

    def _lsb(
        self, channel_values: dict[str, list[int]], channels: list[str], warnings: list[str]
    ) -> list[LsbAnalysis]:
        streams: list[tuple[str, list[int]]] = []
        visible_channels = [name for name in channels if name != "A"]
        if len(visible_channels) > 1:
            composite: list[int] = []
            for index in range(len(next(iter(channel_values.values()), []))):
                for name in visible_channels:
                    composite.append(channel_values[name][index])
            streams.append(("".join(visible_channels), composite))
        streams.extend((name, channel_values[name]) for name in channels)

        results: list[LsbAnalysis] = []
        for stream_name, samples in streams:
            extracted, available_bits, truncated = _pack_lsb(samples, self.policy.max_lsb_bytes)
            if truncated:
                warnings.append(
                    f"LSB stream {stream_name} was truncated at {self.policy.max_lsb_bytes} extracted bytes."
                )
            signatures = [
                LsbSignature(detected_type=signature.name, mime_type=signature.mime_type, offset=offset)
                for signature, offset in scan_signatures(extracted, self.policy.max_signature_matches)
            ]
            flags = _flag_candidates(self._flags, extracted, f"lsb:{stream_name}")
            printable = _printable_ratio(extracted)
            suspicious = bool(signatures or flags) or (len(extracted) >= 16 and printable >= 0.85)
            results.append(
                LsbAnalysis(
                    stream=stream_name,
                    channel_order=stream_name,
                    available_bits=available_bits,
                    extracted_bytes=len(extracted),
                    truncated=truncated,
                    printable_ratio=printable,
                    entropy=_entropy(extracted),
                    preview_ascii=_ascii_preview(extracted),
                    preview_hex=_preview_hex(extracted),
                    signatures=signatures,
                    flags=flags,
                    suspicious=suspicious,
                )
            )
        return results

    def _signatures_and_carving(
        self, data: bytes, logical_end: int, parent_id: str, workspace: Path
    ) -> tuple[list[SignatureCandidate], list[CarvedArtifact]]:
        candidates: list[SignatureCandidate] = []
        carved: list[CarvedArtifact] = []
        total_carved = 0
        root = root_signature(data)

        carving_dir = workspace / "carved"
        carving_dir.mkdir(exist_ok=True)
        for signature, offset in scan_signatures(data, self.policy.max_signature_matches):
            if root and offset == root.offset and signature.name == root.name:
                continue
            source = "trailing-bytes" if offset >= logical_end else "embedded-signature"
            end = _estimated_end(data, offset, signature.name)
            if end is None and source == "trailing-bytes":
                end = len(data)
            estimated_size = end - offset if end and end > offset else None
            artifact_id: str | None = None
            if estimated_size is not None and total_carved + estimated_size <= self.policy.max_carved_bytes:
                payload = data[offset:end]
                if payload:
                    artifact_id = str(uuid4())
                    suffix = re.sub(r"[^a-z0-9]+", "-", signature.name.lower()).strip("-") or "bin"
                    (carving_dir / f"{artifact_id}.{suffix}").write_bytes(payload)
                    total_carved += len(payload)
                    carved.append(
                        CarvedArtifact(
                            artifact_id=artifact_id,
                            parent_artifact_id=parent_id,
                            source_offset=offset,
                            source=source,
                            detected_type=signature.name,
                            mime_type=signature.mime_type,
                            size=len(payload),
                            hashes=_hashes(payload),
                            entropy=_entropy(payload),
                        )
                    )
            candidates.append(
                SignatureCandidate(
                    detected_type=signature.name,
                    mime_type=signature.mime_type,
                    offset=offset,
                    source=source,
                    estimated_size=estimated_size,
                    carved_artifact_id=artifact_id,
                )
            )
        return candidates, carved
