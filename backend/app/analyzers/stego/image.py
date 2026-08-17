from __future__ import annotations

import base64
import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import numpy as np
from PIL import ExifTags, Image, UnidentifiedImageError

from app.analyzers.crypto.decoder import RecursiveDecoder, detect_encodings
from app.analyzers.forensics.metadata import DeepMetadataAnalyzer
from app.analyzers.forensics.signatures import root_signature, scan_signatures
from app.analyzers.stego.pixel import PixelScanPolicy, PixelStegoEngine
from app.analyzers.stego.structures import JPEG_SIGNATURE, PNG_SIGNATURE, parse_jpeg, parse_png
from app.core.analyzers import BaseAnalyzer
from app.core.errors import InvalidArtifactError, ToolExecutionError, ToolNotAvailableError
from app.core.flag_detection import FlagDetector
from app.core.tool_runner import ToolRunner
from app.schemas.forensics import EntropyResult, Hashes, MetadataAnalysis
from app.schemas.crypto import DecodeRequest
from app.schemas.stego import (
    BitPlaneResult,
    AnalysisChainStep,
    CarvedArtifact,
    ChannelInspection,
    EntropyAnalysis,
    ExternalValidation,
    ImageMetadataEntry,
    ImageSummary,
    LsbAnalysis,
    LsbSignature,
    SignatureCandidate,
    StegoFinding,
    StegoAnalysisResponse,
    StegoFlagCandidate,
    StegoLimits,
    TrailingBytes,
)

_FLAG_PREFIXES = ["CTF", "FLAG", "flag", "HTB", "THM", "picoCTF", "PICOCTF", "DUCTF", "SEC"]
_PRINTABLE = set(range(32, 127)) | {9, 10, 13}
_GENERAL_FLAG_PATTERN = re.compile(
    rb"(?P<prefix>[A-Za-z][A-Za-z0-9_]{1,31})\{(?P<body>[\x20-\x7e]{1,256})\}"
)
_ASCII_PREVIEW = 160
_HEX_PREVIEW_BYTES = 96


@dataclass(frozen=True, slots=True)
class StegoPolicy:
    max_upload_bytes: int = 32 * 1024 * 1024
    max_pixels: int = 16_000_000
    max_png_chunks: int = 512
    max_jpeg_segments: int = 512
    max_lsb_bytes: int = 512 * 1024
    max_signature_matches: int = 64
    max_carved_bytes: int = 32 * 1024 * 1024
    max_metadata_entries: int = 128
    max_candidates: int = 32
    max_candidate_bytes: int = 512 * 1024
    max_candidate_export_bytes: int = 16 * 1024
    max_analysis_seconds: float = 15.0


@dataclass(frozen=True, slots=True)
class StegoInput:
    path: Path
    original_filename: str
    artifact_id: str
    workspace: Path
    show_all: bool = False
    deep_scan: bool = False


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
        preview = value[:4096]
        decoded = preview.decode("utf-8", errors="replace")
        readable = sum(character.isprintable() or character.isspace() for character in decoded)
        if decoded and readable / len(decoded) >= 0.7:
            suffix = "…" if len(value) > len(preview) else ""
            return decoded[:500] + suffix
        return f"<{len(value)} bytes>"
    return str(value)[:500]


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return round(sum(1 for value in data if value in _PRINTABLE) / len(data), 4)


def _flag_candidates(
    detector: FlagDetector, data: bytes, source: str, *, base_offset: int = 0
) -> list[StegoFlagCandidate]:
    candidates = [
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
    seen = {(candidate.value, candidate.offset) for candidate in candidates}
    for match in _GENERAL_FLAG_PATTERN.finditer(data):
        value = match.group(0).decode("utf-8", errors="replace")
        offset = base_offset + match.start()
        if (value, offset) in seen:
            continue
        prefix = match.group("prefix").decode("ascii", errors="replace")
        candidates.append(
            StegoFlagCandidate(
                value=value,
                matched_pattern=f"{prefix}{{...}}",
                source=source,
                offset=offset,
                confidence=0.9,
                context=data[max(0, match.start() - 32) : min(len(data), match.end() + 32)].decode(
                    "utf-8", errors="replace"
                ),
            )
        )
    return candidates


def _pack_lsb(samples: np.ndarray, max_bytes: int) -> tuple[bytes, int, bool]:
    byte_count = min(len(samples) // 8, max_bytes)
    bits = (samples[: byte_count * 8] & 1).astype(np.uint8, copy=False)
    output = np.packbits(bits, bitorder="big").tobytes()
    return output, len(samples), len(samples) // 8 > max_bytes


def _pack_msb(samples: np.ndarray, max_bytes: int) -> tuple[bytes, int, bool]:
    byte_count = min(len(samples) // 8, max_bytes)
    bits = ((samples[: byte_count * 8] >> 7) & 1).astype(np.uint8, copy=False)
    output = np.packbits(bits, bitorder="big").tobytes()
    return output, len(samples), len(samples) // 8 > max_bytes


def _channel_names(mode: str) -> list[str]:
    if mode == "L":
        return ["L"]
    if mode == "RGBA":
        return ["R", "G", "B", "A"]
    return ["R", "G", "B"]


def _extract_channels(image: Image.Image) -> tuple[bytes, list[str], str, bool]:
    has_alpha = image.mode in {"RGBA", "LA"} or "transparency" in image.info
    if has_alpha:
        normalized = image.convert("RGBA")
    else:
        normalized = image.convert("RGB")
    return normalized.tobytes(), _channel_names(normalized.mode), normalized.mode, has_alpha


def _channel_values(pixel_bytes: bytes, channel_count: int, channel_index: int) -> np.ndarray:
    return np.frombuffer(pixel_bytes, dtype=np.uint8)[channel_index::channel_count]


def _channel_inspection(channel: str, values: np.ndarray) -> ChannelInspection:
    total = len(values)
    mean = float(np.mean(values)) if total else 0.0
    variance = float(np.var(values)) if total else 0.0
    ones = int(np.count_nonzero(values & 1))
    return ChannelInspection(
        channel=channel,
        minimum=int(np.min(values)) if total else 0,
        maximum=int(np.max(values)) if total else 0,
        mean=round(mean, 4),
        standard_deviation=round(math.sqrt(variance), 4),
        entropy=_entropy(bytes(values)).bits_per_byte,
        lsb_zeros=total - ones,
        lsb_ones=ones,
        lsb_one_ratio=round(ones / total, 4) if total else 0.0,
    )


def _bit_planes(channel: str, values: np.ndarray) -> list[BitPlaneResult]:
    total = len(values)
    planes: list[BitPlaneResult] = []
    for bit in range(8):
        ones = int(np.count_nonzero((values >> bit) & 1))
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


def _detect_image_format(data: bytes) -> str | None:
    if data.startswith(PNG_SIGNATURE):
        return "PNG"
    if data.startswith(JPEG_SIGNATURE):
        return "JPEG"
    if data.startswith(b"BM"):
        return "BMP"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return "TIFF"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "WEBP"
    return None


def _container_end(data: bytes, image_format: str) -> int:
    if image_format == "BMP" and len(data) >= 6:
        declared = int.from_bytes(data[2:6], "little")
        return declared if 14 <= declared <= len(data) else len(data)
    if image_format == "GIF":
        trailer = data.rfind(b";")
        return trailer + 1 if trailer >= 0 else len(data)
    if image_format == "WEBP" and len(data) >= 12:
        declared = int.from_bytes(data[4:8], "little") + 8
        return declared if 12 <= declared <= len(data) else len(data)
    return len(data)


class ImageStegoAnalyzer(BaseAnalyzer[StegoInput, StegoAnalysisResponse]):
    name = "image-stego"
    category = "steganography"

    def __init__(
        self,
        policy: StegoPolicy | None = None,
        tool_runner: ToolRunner | None = None,
        metadata_analyzer: DeepMetadataAnalyzer | None = None,
    ) -> None:
        self.policy = policy or StegoPolicy()
        self._flags = FlagDetector(_FLAG_PREFIXES)
        self._decoder = RecursiveDecoder()
        self._tool_runner = tool_runner or ToolRunner(
            {"zsteg"}, default_timeout_seconds=8.0, default_output_limit=256 * 1024
        )
        self._metadata_analyzer = metadata_analyzer or DeepMetadataAnalyzer()
        self._pixels = PixelStegoEngine(
            PixelScanPolicy(
                max_candidate_bytes=self.policy.max_candidate_bytes,
                max_export_bytes=self.policy.max_candidate_export_bytes,
                max_findings=self.policy.max_candidates,
                max_analysis_seconds=self.policy.max_analysis_seconds,
            )
        )

    def supports(self, artifact: StegoInput) -> bool:
        sample = artifact.path.read_bytes()[:12]
        return _detect_image_format(sample) is not None

    def analyze(self, artifact: StegoInput) -> StegoAnalysisResponse:
        data = artifact.path.read_bytes()
        image_format = _detect_image_format(data)
        if image_format is None:
            raise InvalidArtifactError(
                "Only PNG, BMP, GIF, TIFF, lossless WebP, and JPEG images are supported."
            )
        if image_format == "WEBP" and data.find(b"VP8L", 12) < 0:
            raise InvalidArtifactError(
                "Lossy WebP pixel planes are unstable; provide a lossless WebP image."
            )

        warnings: list[str] = []
        png_chunks = []
        jpeg_segments = []
        png_text_entries: tuple[tuple[str, str], ...] = ()
        if image_format == "PNG":
            png_chunks, structure = parse_png(data, self.policy.max_png_chunks)
            png_truncated, jpeg_truncated = structure.truncated, False
            png_text_entries = structure.text_entries
        elif image_format == "JPEG":
            jpeg_segments, structure = parse_jpeg(data, self.policy.max_jpeg_segments)
            png_truncated, jpeg_truncated = False, structure.truncated
        else:
            structure = None
            png_truncated = jpeg_truncated = False
        if structure is not None:
            warnings.extend(structure.warnings)
            logical_end = structure.logical_end or len(data)
        else:
            logical_end = _container_end(data, image_format)

        try:
            with Image.open(
                artifact.path, formats=("PNG", "JPEG", "BMP", "GIF", "TIFF", "WEBP")
            ) as opened:
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
        for key, value in png_text_entries:
            entry = ImageMetadataEntry(key=key[:128], value=value[:500], source="png-text")
            if entry not in metadata:
                metadata.append(entry)
        metadata = metadata[: self.policy.max_metadata_entries]
        try:
            metadata_analysis = self._metadata_analyzer.analyze(
                artifact.path, artifact.original_filename
            )
        except Exception as exc:
            metadata_analysis = MetadataAnalysis(
                tool_available=True,
                summary="ExifTool metadata analysis failed safely; built-in image metadata remains available.",
                warnings=[f"ExifTool analyzer error: {type(exc).__name__}."],
            )
        warnings.extend(metadata_analysis.warnings)
        if image_format == "JPEG":
            warnings.append(
                "JPEG is lossy; pixel bit-plane results are shown for triage but are less reliable than lossless-image results."
            )

        channel_count = len(channels)
        channel_values = {
            name: _channel_values(pixel_bytes, channel_count, index) for index, name in enumerate(channels)
        }
        inspections = [_channel_inspection(name, values) for name, values in channel_values.items()]
        bit_planes = [
            plane for name, values in channel_values.items() for plane in _bit_planes(name, values)
        ]
        lsb = self._lsb(channel_values, channels, warnings)
        msb = self._msb(channel_values, channels, warnings)
        pixels = np.frombuffer(pixel_bytes, dtype=np.uint8).reshape(height, width, channel_count)
        findings, bit_plane_visuals, barcodes, pixel_scan = self._pixels.scan(
            pixels,
            channels,
            show_all=artifact.show_all,
            deep_scan=artifact.deep_scan,
        )
        external_validation, external_findings = self._external_validation(
            artifact, image_format
        )

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
        file_flags = _flag_candidates(self._flags, data, "file")
        flags = list(file_flags)
        for result in lsb:
            flags.extend(result.flags)
        for result in msb:
            flags.extend(result.flags)
        for finding in findings:
            flags.extend(finding.flags)
        findings.extend(
            self._container_findings(
                data, metadata, png_chunks, trailing_bytes, signatures, file_flags
            )
        )
        findings.extend(external_findings)
        findings.sort(key=lambda item: (item.score, item.confidence), reverse=True)
        findings = findings[: self.policy.max_candidates]

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
            metadata_analysis=metadata_analysis,
            png_chunks=png_chunks,
            png_chunks_truncated=png_truncated,
            jpeg_segments=jpeg_segments,
            jpeg_segments_truncated=jpeg_truncated,
            trailing_bytes=trailing_bytes,
            channels=inspections,
            bit_planes=bit_planes,
            lsb=lsb,
            msb=msb,
            entropy=EntropyAnalysis(
                file=_entropy(data),
                pixel_data=_entropy(pixel_bytes),
                channels={name: _entropy(bytes(values)) for name, values in channel_values.items()},
            ),
            signatures=signatures,
            carved_artifacts=carved,
            flags=flags,
            findings=findings,
            bit_plane_visuals=bit_plane_visuals,
            barcodes=barcodes,
            pixel_scan=pixel_scan,
            external_validation=external_validation,
            noise_included=artifact.show_all,
            warnings=warnings,
            limits=StegoLimits(
                max_upload_bytes=self.policy.max_upload_bytes,
                max_pixels=self.policy.max_pixels,
                max_png_chunks=self.policy.max_png_chunks,
                max_jpeg_segments=self.policy.max_jpeg_segments,
                max_lsb_bytes=self.policy.max_lsb_bytes,
                max_signature_matches=self.policy.max_signature_matches,
                max_carved_bytes=self.policy.max_carved_bytes,
                max_candidates=self.policy.max_candidates,
                max_candidate_bytes=self.policy.max_candidate_bytes,
                max_analysis_seconds=self.policy.max_analysis_seconds,
            ),
        )

    def _metadata(self, image: Image.Image) -> list[ImageMetadataEntry]:
        entries: list[ImageMetadataEntry] = [
            ImageMetadataEntry(key="mode", value=image.mode, source="image"),
            ImageMetadataEntry(key="width", value=image.width, source="image"),
            ImageMetadataEntry(key="height", value=image.height, source="image"),
        ]
        for key, value in sorted(image.info.items(), key=lambda item: str(item[0])):
            lowered = str(key).lower()
            if "icc" in lowered:
                source = "icc"
            elif "xmp" in lowered or "xml" in lowered:
                source = "xmp"
            elif image.format == "PNG" and isinstance(value, str):
                source = "png-text"
            else:
                source = "image"
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

    def _external_validation(
        self, artifact: StegoInput, image_format: str
    ) -> tuple[list[ExternalValidation], list[StegoFinding]]:
        available = self._tool_runner.available("zsteg")
        if not available or image_format not in {"PNG", "BMP"}:
            return [
                ExternalValidation(
                    tool="zsteg",
                    available=available,
                    executed=False,
                    error=None if available else "zsteg is not installed or configured.",
                )
            ], []
        try:
            execution = self._tool_runner.run(
                "zsteg",
                ["-a", str(artifact.path)],
                cwd=artifact.workspace,
                timeout_seconds=8.0,
                output_limit=256 * 1024,
            )
        except (ToolExecutionError, ToolNotAvailableError) as exc:
            return [
                ExternalValidation(
                    tool="zsteg", available=True, executed=True, error=str(exc)
                )
            ], []

        ansi = re.compile(rb"\x1b\[[0-9;]*m")
        clean = ansi.sub(b"", execution.stdout)
        lines = [
            line.decode("utf-8", errors="replace")[:1000]
            for line in clean.splitlines()
            if line.strip() and not line.lstrip().startswith(b"-")
        ][:64]
        findings: list[StegoFinding] = []
        for line in lines:
            raw = line.encode("utf-8")
            flags = _flag_candidates(self._flags, raw, "external:zsteg")
            interesting = bool(flags) or any(
                marker in line.lower()
                for marker in ("text:", "file:", "zip", "gzip", "png image", "flag{")
            )
            if not interesting:
                continue
            findings.append(
                StegoFinding(
                    finding_id=str(uuid4()),
                    title="FLAG CANDIDATE FOUND" if flags else "External zsteg validation",
                    source="external_tool",
                    severity="critical" if flags else "medium",
                    confidence=0.99 if flags else 0.7,
                    score=100 if flags else 45,
                    detected_type="ctf_flag" if flags else "external_validation",
                    explanation="External Tool Validation: zsteg reported this candidate.",
                    offset=0,
                    length=len(raw),
                    entropy=_entropy(raw).bits_per_byte,
                    printable_ratio=_printable_ratio(raw),
                    utf8_valid=True,
                    null_ratio=0.0,
                    preview_text=line,
                    preview_hex=raw[:128].hex(),
                    data_base64=base64.b64encode(raw).decode("ascii"),
                    data_truncated=False,
                    flags=flags,
                    analysis_chain=[
                        AnalysisChainStep(operation="external validation", detail="zsteg -a")
                    ],
                )
            )
        return [
            ExternalValidation(
                tool="zsteg",
                available=True,
                executed=True,
                duration_ms=execution.duration_ms,
                findings=lines,
                error=(
                    execution.stderr.decode("utf-8", errors="replace")[:1000]
                    if execution.returncode not in {0, 1} else None
                ),
            )
        ], findings

    def _container_findings(
        self,
        data: bytes,
        metadata: list[ImageMetadataEntry],
        png_chunks: list[object],
        trailing: TrailingBytes,
        signatures: list[SignatureCandidate],
        file_flags: list[StegoFlagCandidate],
    ) -> list[StegoFinding]:
        findings: list[StegoFinding] = []

        def build(
            *,
            title: str,
            source: str,
            severity: str,
            score: int,
            detected_type: str,
            explanation: str,
            payload: bytes,
            offset: int = 0,
            flags: list[StegoFlagCandidate] | None = None,
            chain: list[AnalysisChainStep] | None = None,
            encodings: list[object] | None = None,
        ) -> StegoFinding:
            sample = payload[:32_768]
            try:
                sample.decode("utf-8")
                utf8 = True
            except UnicodeDecodeError:
                utf8 = False
            exported = payload[: self.policy.max_candidate_export_bytes]
            printable = _printable_ratio(sample)
            return StegoFinding(
                finding_id=str(uuid4()),
                title=title,
                source=source,
                severity=severity,
                confidence=0.99 if flags else min(0.95, score / 100),
                score=score,
                detected_type=detected_type,
                explanation=explanation,
                offset=offset,
                length=len(payload),
                entropy=_entropy(sample).bits_per_byte,
                printable_ratio=printable,
                utf8_valid=utf8,
                null_ratio=round(sample.count(0) / len(sample), 4) if sample else 0.0,
                preview_text=payload[:512].decode("utf-8", errors="replace"),
                preview_hex=payload[:128].hex(),
                data_base64=base64.b64encode(exported).decode("ascii"),
                data_truncated=len(payload) > len(exported),
                flags=flags or [],
                encodings=encodings or [],
                analysis_chain=chain or [],
            )

        for flag in file_flags:
            raw = flag.value.encode("utf-8")
            findings.append(
                build(
                    title="FLAG CANDIDATE FOUND",
                    source="metadata",
                    severity="critical",
                    score=100,
                    detected_type="ctf_flag",
                    explanation="Recognized CTF flag structure in the image container.",
                    payload=raw,
                    offset=flag.offset,
                    flags=[flag],
                    chain=[AnalysisChainStep(operation="container scan", detail="raw image bytes")],
                )
            )

        for chunk in png_chunks:
            if not getattr(chunk, "suspicious", False):
                continue
            preview = (getattr(chunk, "text_preview", None) or "").encode("utf-8")
            findings.append(
                build(
                    title="Suspicious PNG chunk",
                    source="png_structure",
                    severity="medium",
                    score=45,
                    detected_type="png_chunk",
                    explanation=getattr(chunk, "explanation", None) or "Unusual PNG chunk structure.",
                    payload=preview,
                    offset=int(getattr(chunk, "offset", 0)),
                    chain=[
                        AnalysisChainStep(
                            operation="PNG structure scan", detail=str(getattr(chunk, "chunk_type", "unknown"))
                        )
                    ],
                )
            )

        decoded_metadata = 0
        for entry in metadata:
            if not isinstance(entry.value, str) or len(entry.value) < 4:
                continue
            raw = entry.value.encode("utf-8")
            entry_flags = _flag_candidates(self._flags, raw, f"metadata:{entry.key}")
            encodings = [item for item in detect_encodings(raw) if item.confidence >= 0.86]
            if not entry_flags and not encodings:
                continue
            chain = [AnalysisChainStep(operation="metadata scan", detail=f"{entry.source}:{entry.key}")]
            if encodings and decoded_metadata < 8 and len(raw) <= 32_768:
                decoded_metadata += 1
                try:
                    decoded = self._decoder.analyze(
                        DecodeRequest(
                            input=entry.value,
                            max_depth=3,
                            max_results=4,
                            beam_width=12,
                            timeout_ms=250,
                            flag_prefixes=_FLAG_PREFIXES,
                        )
                    )
                except ValueError:
                    decoded = None
                if decoded is not None:
                    for result in decoded.results:
                        try:
                            output = base64.b64decode(result.output_base64, validate=True)
                        except ValueError:
                            continue
                        recovered = _flag_candidates(
                            self._flags, output, f"metadata-decoder:{entry.key}"
                        )
                        if not recovered:
                            continue
                        entry_flags.extend(recovered)
                        chain.extend(
                            AnalysisChainStep(
                                operation="decode",
                                detail=step.transform + (f" ({step.parameter})" if step.parameter else ""),
                            )
                            for step in result.chain
                        )
                        break
            findings.append(
                build(
                    title="FLAG CANDIDATE FOUND" if entry_flags else f"Encoded metadata ({encodings[0].name})",
                    source="metadata",
                    severity="critical" if entry_flags else "medium",
                    score=100 if entry_flags else 50,
                    detected_type="ctf_flag" if entry_flags else "encoded_text",
                    explanation=(
                        "Recognized flag structure in image metadata."
                        if entry_flags else f"Metadata value is plausible {encodings[0].name}."
                    ),
                    payload=raw,
                    flags=entry_flags,
                    encodings=[item.model_dump() for item in encodings],
                    chain=chain,
                )
            )

        if trailing.present:
            payload = data[trailing.offset :]
            score = 75 if trailing.detected_type else 45
            findings.append(
                build(
                    title=(
                        f"Appended {trailing.detected_type.upper()}"
                        if trailing.detected_type else "Trailing data after image end"
                    ),
                    source="trailing_data",
                    severity="high" if trailing.detected_type else "medium",
                    score=score,
                    detected_type=trailing.detected_type or "binary",
                    explanation=f"{trailing.size} bytes occur after the logical image end.",
                    payload=payload,
                    offset=trailing.offset,
                    chain=[AnalysisChainStep(operation="container boundary scan", detail="data after logical end")],
                )
            )

        for signature in signatures:
            if signature.source == "trailing-bytes":
                continue
            payload = data[signature.offset :]
            findings.append(
                build(
                    title=f"Embedded {signature.detected_type.upper()} candidate",
                    source="embedded_file",
                    severity="high",
                    score=65,
                    detected_type=signature.detected_type,
                    explanation="A known file signature appears inside the image container.",
                    payload=payload,
                    offset=signature.offset,
                    chain=[AnalysisChainStep(operation="signature carving", detail=signature.detected_type)],
                )
            )
        return findings

    def _lsb(
        self, channel_values: dict[str, np.ndarray], channels: list[str], warnings: list[str]
    ) -> list[LsbAnalysis]:
        streams: list[tuple[str, np.ndarray]] = []
        visible_channels = [name for name in channels if name != "A"]
        if len(visible_channels) > 1:
            composite = np.column_stack(
                [channel_values[name] for name in visible_channels]
            ).reshape(-1)
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

    def _msb(
        self, channel_values: dict[str, np.ndarray], channels: list[str], warnings: list[str]
    ) -> list[LsbAnalysis]:
        streams: list[tuple[str, np.ndarray]] = []
        visible_channels = [name for name in channels if name != "A"]
        if len(visible_channels) > 1:
            composite = np.column_stack(
                [channel_values[name] for name in visible_channels]
            ).reshape(-1)
            streams.append(("".join(visible_channels), composite))
        streams.extend((name, channel_values[name]) for name in channels)

        results: list[LsbAnalysis] = []
        for stream_name, samples in streams:
            extracted, available_bits, truncated = _pack_msb(
                samples, self.policy.max_lsb_bytes
            )
            if truncated:
                warnings.append(
                    f"MSB stream {stream_name} was truncated at {self.policy.max_lsb_bytes} extracted bytes."
                )
            signatures = [
                LsbSignature(detected_type=signature.name, mime_type=signature.mime_type, offset=offset)
                for signature, offset in scan_signatures(extracted, self.policy.max_signature_matches)
            ]
            flags = _flag_candidates(self._flags, extracted, f"msb:{stream_name}")
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
