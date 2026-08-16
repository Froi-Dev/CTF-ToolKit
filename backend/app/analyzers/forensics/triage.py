from __future__ import annotations

import hashlib
import math
import mimetypes
import re
import struct
import tarfile
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from app.analyzers.forensics.archives import (
    ArchivePolicy,
    ExtractedPath,
    inspect_gzip,
    inspect_tar,
    inspect_zip,
)
from app.analyzers.forensics.metadata import DeepMetadataAnalyzer
from app.analyzers.forensics.qr_barcode import QRBarcodeRecoveryAnalyzer
from app.analyzers.forensics.signatures import (
    TYPE_EXTENSIONS,
    FileSignature,
    root_signature,
    scan_signatures,
)
from app.core.analyzers import BaseAnalyzer
from app.core.flag_detection import FlagDetector
from app.schemas.forensics import (
    EmbeddedFile,
    EntropyResult,
    ExtensionAssessment,
    ExtractedArtifact,
    FlagCandidate,
    ForensicsTriageResponse,
    Hashes,
    MagicByteDetection,
    MetadataEntry,
    MetadataAnalysis,
    ForensicFinding,
    QRBarcodeAnalysis,
    SignatureMatch,
    StringOccurrence,
    TriageLimits,
)

DEFAULT_FLAG_PREFIXES = ["flag", "CTF", "picoCTF", "HTB", "THM", "hack", "H4G"]
_ASCII_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_UTF16BE_STRINGS = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")


@dataclass(frozen=True, slots=True)
class TriagePolicy:
    max_upload_bytes: int = 32 * 1024 * 1024
    max_strings: int = 500
    max_string_length: int = 1_024
    max_signature_matches: int = 256
    max_embedded_files: int = 32
    max_archive_members: int = 100
    max_extracted_bytes: int = 32 * 1024 * 1024
    max_compression_ratio: float = 100.0


@dataclass(frozen=True, slots=True)
class TriageInput:
    path: Path
    original_filename: str
    artifact_id: str
    extraction_root: Path
    custom_flag_regex: str | None = None


@dataclass(frozen=True, slots=True)
class _Detection:
    name: str
    mime_type: str
    description: str
    extensions: tuple[str, ...]
    signature: bytes | None
    confidence: float


def _hashes(data: bytes) -> Hashes:
    return Hashes(
        md5=hashlib.md5(data, usedforsecurity=False).hexdigest(),
        sha1=hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _entropy(data: bytes) -> EntropyResult:
    if not data:
        value = 0.0
    else:
        counts = Counter(data)
        value = -sum(
            (count / len(data)) * math.log2(count / len(data))
            for count in counts.values()
        )
    if value < 1.0:
        classification = "very-low"
    elif value < 3.5:
        classification = "low"
    elif value < 7.0:
        classification = "normal"
    elif value < 7.7:
        classification = "high"
    else:
        classification = "very-high"
    return EntropyResult(
        bits_per_byte=round(value, 4),
        classification=classification,
        sample_size=len(data),
    )


def _is_probably_text(data: bytes) -> bool:
    if not data:
        return True
    sample = data[:65_536]
    if b"\x00" in sample:
        return False
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return sum(character.isprintable() or character in "\r\n\t" for character in decoded) / max(
        1, len(decoded)
    ) >= 0.90


def _zip_subtype(path: Path) -> _Detection | None:
    try:
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            if "word/document.xml" in names:
                return _Detection(
                    "docx",
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    "Microsoft Word Open XML document",
                    ("docx",),
                    b"PK\x03\x04",
                    0.99,
                )
            if "xl/workbook.xml" in names:
                return _Detection(
                    "xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    "Microsoft Excel Open XML workbook",
                    ("xlsx",),
                    b"PK\x03\x04",
                    0.99,
                )
            if "ppt/presentation.xml" in names:
                return _Detection(
                    "pptx",
                    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    "Microsoft PowerPoint Open XML presentation",
                    ("pptx",),
                    b"PK\x03\x04",
                    0.99,
                )
            if "META-INF/MANIFEST.MF" in names:
                return _Detection(
                    "jar", "application/java-archive", "Java archive", ("jar",), b"PK\x03\x04", 0.98
                )
            if "mimetype" in names:
                try:
                    mime = archive.read("mimetype").decode("ascii", errors="replace").strip()
                except (KeyError, RuntimeError, OSError):
                    mime = ""
                if mime == "application/epub+zip":
                    return _Detection(
                        "epub", "application/epub+zip", "EPUB document", ("epub",), b"PK\x03\x04", 0.99
                    )
    except (zipfile.BadZipFile, OSError):
        return None
    return None


def _detect(data: bytes, path: Path | None = None) -> _Detection:
    signature = root_signature(data)
    if signature is not None:
        if signature.name == "zip" and path is not None:
            subtype = _zip_subtype(path)
            if subtype is not None:
                return subtype
        return _Detection(
            signature.name,
            signature.mime_type,
            signature.description,
            signature.extensions,
            signature.magic,
            0.99,
        )

    if len(data) >= 12 and data.startswith(b"RIFF"):
        riff_types = {
            b"WAVE": ("wav", "audio/wav", "RIFF WAVE audio", ("wav",)),
            b"AVI ": ("avi", "video/x-msvideo", "RIFF AVI video", ("avi",)),
            b"WEBP": ("webp", "image/webp", "WebP image", ("webp",)),
        }
        values = riff_types.get(data[8:12])
        if values:
            return _Detection(*values, b"RIFF", 0.99)
    if len(data) >= 262 and data[257:262] == b"ustar":
        return _Detection("tar", "application/x-tar", "TAR archive", ("tar",), b"ustar", 0.99)
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return _Detection("mp4", "video/mp4", "ISO Base Media file", ("mp4", "m4v", "mov"), b"ftyp", 0.92)
    if _is_probably_text(data):
        return _Detection("text", "text/plain", "UTF-8 or ASCII text", ("txt", "log", "csv"), None, 0.90)
    return _Detection(
        "unknown", "application/octet-stream", "Unknown binary data", (), None, 0.20
    )


def _extract_strings(data: bytes, policy: TriagePolicy) -> tuple[list[StringOccurrence], bool]:
    found: list[StringOccurrence] = []
    patterns = (
        (_ASCII_STRINGS, "ascii", lambda value: value.decode("ascii")),
        (_UTF16LE_STRINGS, "utf-16le", lambda value: value.decode("utf-16le")),
        (_UTF16BE_STRINGS, "utf-16be", lambda value: value.decode("utf-16be")),
    )
    for pattern, encoding, decoder in patterns:
        for match in pattern.finditer(data):
            value = decoder(match.group(0))
            found.append(
                StringOccurrence(
                    offset=match.start(),
                    value=value[: policy.max_string_length],
                    encoding=encoding,
                )
            )
    found.sort(key=lambda item: (item.offset, item.encoding))
    truncated = len(found) > policy.max_strings
    return found[: policy.max_strings], truncated


def _image_metadata(data: bytes, detection: _Detection) -> list[MetadataEntry]:
    values: list[MetadataEntry] = []
    if detection.name == "png" and len(data) >= 29:
        values.extend(
            [
                MetadataEntry(key="width", value=int.from_bytes(data[16:20], "big")),
                MetadataEntry(key="height", value=int.from_bytes(data[20:24], "big")),
                MetadataEntry(key="bit_depth", value=data[24]),
                MetadataEntry(key="color_type", value=data[25]),
            ]
        )
    elif detection.name == "gif" and len(data) >= 10:
        values.extend(
            [
                MetadataEntry(key="width", value=int.from_bytes(data[6:8], "little")),
                MetadataEntry(key="height", value=int.from_bytes(data[8:10], "little")),
            ]
        )
    elif detection.name == "jpeg":
        cursor = 2
        sof_markers = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
        while cursor + 9 < len(data):
            if data[cursor] != 0xFF:
                cursor += 1
                continue
            marker = data[cursor + 1]
            if marker in sof_markers:
                values.extend(
                    [
                        MetadataEntry(key="width", value=int.from_bytes(data[cursor + 7 : cursor + 9], "big")),
                        MetadataEntry(key="height", value=int.from_bytes(data[cursor + 5 : cursor + 7], "big")),
                        MetadataEntry(key="bits_per_sample", value=data[cursor + 4]),
                    ]
                )
                break
            if marker in {0xD8, 0xD9} or cursor + 4 > len(data):
                cursor += 2
                continue
            segment_length = int.from_bytes(data[cursor + 2 : cursor + 4], "big")
            cursor += max(2, segment_length + 2)
    return values


def _format_metadata(data: bytes, detection: _Detection) -> list[MetadataEntry]:
    values = [
        MetadataEntry(key="detected_type", value=detection.name),
        MetadataEntry(key="mime_type", value=detection.mime_type),
        MetadataEntry(key="byte_size", value=len(data)),
    ]
    values.extend(_image_metadata(data, detection))
    if detection.name == "pdf":
        version = data[5:8].decode("ascii", errors="replace")
        values.extend(
            [
                MetadataEntry(key="pdf_version", value=version),
                MetadataEntry(key="page_objects", value=len(re.findall(rb"/Type\s*/Page\b", data))),
            ]
        )
    elif detection.name == "elf" and len(data) >= 20:
        endian = "little" if data[5] == 1 else "big" if data[5] == 2 else "unknown"
        values.extend(
            [
                MetadataEntry(key="elf_class", value={1: "32-bit", 2: "64-bit"}.get(data[4], "unknown")),
                MetadataEntry(key="endianness", value=endian),
                MetadataEntry(key="machine", value=int.from_bytes(data[18:20], endian if endian != "unknown" else "little")),
            ]
        )
    elif detection.name == "pe" and len(data) >= 64:
        pe_offset = int.from_bytes(data[60:64], "little")
        if pe_offset + 24 <= len(data) and data[pe_offset : pe_offset + 4] == b"PE\x00\x00":
            values.extend(
                [
                    MetadataEntry(key="pe_header_offset", value=pe_offset),
                    MetadataEntry(key="machine", value=int.from_bytes(data[pe_offset + 4 : pe_offset + 6], "little")),
                    MetadataEntry(key="section_count", value=int.from_bytes(data[pe_offset + 6 : pe_offset + 8], "little")),
                ]
            )
    return values


def _extension_assessment(filename: str, detection: _Detection) -> ExtensionAssessment:
    suffix = Path(filename).suffix.lower().lstrip(".") or None
    expected = list(detection.extensions)
    if not expected:
        return ExtensionAssessment(
            provided_extension=suffix,
            expected_extensions=[],
            mismatch=False,
            reason="The detected type has no reliable extension mapping.",
        )
    mismatch = suffix is not None and suffix not in expected
    if suffix is None:
        reason = f"No extension was supplied; detected content normally uses: {', '.join(expected)}."
    elif mismatch:
        reason = f"Extension .{suffix} does not match detected {detection.name} content."
    else:
        reason = "The filename extension is consistent with detected content."
    return ExtensionAssessment(
        provided_extension=suffix,
        expected_extensions=expected,
        mismatch=mismatch,
        reason=reason,
    )


def _carve_end(data: bytes, signature: FileSignature, offset: int) -> int | None:
    if signature.name == "png":
        marker = data.find(b"IEND", offset + len(signature.magic))
        return marker + 8 if marker >= 0 and marker + 8 <= len(data) else None
    if signature.name == "jpeg":
        marker = data.find(b"\xff\xd9", offset + len(signature.magic))
        return marker + 2 if marker >= 0 else None
    if signature.name == "pdf":
        marker = data.find(b"%%EOF", offset + len(signature.magic))
        return marker + 5 if marker >= 0 else None
    if signature.name == "zip":
        marker = data.find(b"PK\x05\x06", offset + len(signature.magic))
        if marker >= 0 and marker + 22 <= len(data):
            comment_length = int.from_bytes(data[marker + 20 : marker + 22], "little")
            end = marker + 22 + comment_length
            return end if end <= len(data) else None
    return None


def _child_artifact(extracted: ExtractedPath, parent_id: str) -> ExtractedArtifact:
    data = extracted.path.read_bytes()
    detection = _detect(data, extracted.path)
    return ExtractedArtifact(
        artifact_id=extracted.artifact_id,
        parent_artifact_id=parent_id,
        source_path=extracted.source_path,
        extraction_method=extracted.method,
        size=len(data),
        detected_type=detection.name,
        mime_type=detection.mime_type,
        hashes=_hashes(data),
        entropy=_entropy(data),
    )


class FileTriageAnalyzer(BaseAnalyzer[TriageInput, ForensicsTriageResponse]):
    name = "file_forensics_triage"
    category = "forensics"

    def __init__(
        self,
        policy: TriagePolicy | None = None,
        metadata_analyzer: DeepMetadataAnalyzer | None = None,
        qr_analyzer: QRBarcodeRecoveryAnalyzer | None = None,
    ) -> None:
        self.policy = policy or TriagePolicy()
        self._metadata = metadata_analyzer or DeepMetadataAnalyzer()
        self._qr = qr_analyzer or QRBarcodeRecoveryAnalyzer()

    def supports(self, value: object) -> bool:
        return isinstance(value, TriageInput) and value.path.is_file()

    def analyze(self, value: TriageInput) -> ForensicsTriageResponse:
        if not self.supports(value):
            raise TypeError("FileTriageAnalyzer requires a regular file")
        data = value.path.read_bytes()
        if len(data) > self.policy.max_upload_bytes:
            raise ValueError("artifact exceeds the configured triage size limit")

        detection = _detect(data, value.path)
        strings, strings_truncated = _extract_strings(data, self.policy)
        flag_detector = FlagDetector(DEFAULT_FLAG_PREFIXES)
        detected_flags = flag_detector.detect(data)
        flags = [
            FlagCandidate(
                value=flag.value,
                matched_pattern=flag.matched_pattern,
                source=value.original_filename,
                offset=flag.offset,
                confidence=flag.confidence,
                context=flag.context,
            )
            for flag in detected_flags
        ]

        raw_signature_matches = scan_signatures(data, self.policy.max_signature_matches)
        signatures = [
            SignatureMatch(
                name=signature.name,
                mime_type=signature.mime_type,
                offset=offset,
                signature=signature.magic.hex(),
                is_embedded=offset > 0,
            )
            for signature, offset in raw_signature_matches
        ]

        archive_policy = ArchivePolicy(
            max_members=self.policy.max_archive_members,
            max_extracted_bytes=self.policy.max_extracted_bytes,
            max_compression_ratio=self.policy.max_compression_ratio,
        )
        archives = []
        extracted_paths: list[ExtractedPath] = []
        warnings: list[str] = []
        value.extraction_root.mkdir(parents=True, exist_ok=True)
        try:
            if zipfile.is_zipfile(value.path):
                archive, extracted, archive_warnings = inspect_zip(
                    value.path, value.extraction_root / "archive", archive_policy
                )
                archives.append(archive)
                extracted_paths.extend(extracted)
                warnings.extend(archive_warnings)
            elif detection.name == "zip":
                warnings.append("ZIP magic was detected, but the archive structure is malformed.")
            elif tarfile.is_tarfile(value.path):
                archive, extracted, archive_warnings = inspect_tar(
                    value.path, value.extraction_root / "archive", archive_policy
                )
                archives.append(archive)
                extracted_paths.extend(extracted)
                warnings.extend(archive_warnings)
            elif detection.name in {"7z", "rar"}:
                warnings.append(
                    f"{detection.name.upper()} member discovery is unavailable without an allowlisted external extractor."
                )
            elif detection.name == "gzip":
                archive, extracted, archive_warnings = inspect_gzip(
                    value.path,
                    value.extraction_root / "archive",
                    archive_policy,
                    value.original_filename,
                )
                archives.append(archive)
                extracted_paths.extend(extracted)
                warnings.extend(archive_warnings)
        except (zipfile.BadZipFile, tarfile.TarError, OSError, ValueError) as exc:
            warnings.append(f"Archive inspection failed safely: {type(exc).__name__}.")

        embedded_files: list[EmbeddedFile] = []
        extracted_total = sum(item.path.stat().st_size for item in extracted_paths)
        carve_root = value.extraction_root / "embedded"
        for signature, offset in raw_signature_matches:
            if offset == 0 or len(embedded_files) >= self.policy.max_embedded_files:
                continue
            end = _carve_end(data, signature, offset)
            estimated_size = end - offset if end is not None else None
            artifact_id: str | None = None
            if end is not None and estimated_size is not None:
                if extracted_total + estimated_size <= self.policy.max_extracted_bytes:
                    carve_root.mkdir(parents=True, exist_ok=True)
                    extension = signature.extensions[0] if signature.extensions else "bin"
                    destination = carve_root / f"embedded_{offset:08x}.{extension}"
                    destination.write_bytes(data[offset:end])
                    artifact_id = str(uuid4())
                    extracted_paths.append(
                        ExtractedPath(
                            artifact_id,
                            f"offset:0x{offset:x}",
                            "embedded-carve",
                            destination,
                        )
                    )
                    extracted_total += estimated_size
                else:
                    warnings.append(
                        f"Embedded {signature.name} at offset {offset} was not carved: expanded data limit exceeded."
                    )
            embedded_files.append(
                EmbeddedFile(
                    name=f"embedded_{offset:08x}",
                    detected_type=signature.name,
                    mime_type=signature.mime_type,
                    offset=offset,
                    estimated_size=estimated_size,
                    extracted_artifact_id=artifact_id,
                )
            )
        if len([item for item in raw_signature_matches if item[1] > 0]) > self.policy.max_embedded_files:
            warnings.append(
                f"Embedded signature results were limited to {self.policy.max_embedded_files}."
            )

        # Search safely extracted content as well as the container. These candidates retain
        # their archive path or carve offset so an analyst can trace them to their source.
        for extracted in extracted_paths:
            for flag in flag_detector.detect(extracted.path.read_bytes()):
                flags.append(
                    FlagCandidate(
                        value=flag.value,
                        matched_pattern=flag.matched_pattern,
                        source=extracted.source_path,
                        offset=flag.offset,
                        confidence=flag.confidence,
                        context=flag.context,
                    )
                )

        guessed_mime, _ = mimetypes.guess_type(value.original_filename)
        metadata = _format_metadata(data, detection)
        if guessed_mime:
            metadata.append(MetadataEntry(key="filename_mime_hint", value=guessed_mime))

        try:
            metadata_analysis = self._metadata.analyze(
                value.path, value.original_filename, value.custom_flag_regex
            )
        except Exception as exc:
            metadata_analysis = MetadataAnalysis(
                tool_available=True,
                summary="Deep metadata analysis failed safely; baseline metadata remains available.",
                warnings=[f"Metadata analyzer error: {type(exc).__name__}."],
            )
        qr_workspace = value.extraction_root / "qr-recovery"
        qr_workspace.mkdir(parents=True, exist_ok=True)
        try:
            qr_barcode = self._qr.analyze(
                value.path, value.original_filename, detection.name, qr_workspace
            )
        except Exception as exc:
            qr_barcode = QRBarcodeAnalysis(
                warnings=[f"QR/barcode recovery failed safely: {type(exc).__name__}."],
            )
        extracted_images = 0
        for extracted in extracted_paths:
            if extracted_images >= 20:
                qr_barcode.warnings.append("QR scanning of extracted image artifacts was limited to 20 files.")
                break
            try:
                child_data = extracted.path.read_bytes()[:16]
                child_detection = _detect(child_data, extracted.path)
                if child_detection.name not in {"png", "jpeg", "gif", "bmp", "tiff", "webp"}:
                    continue
                child_workspace = qr_workspace / f"extracted-{extracted_images}"
                child_workspace.mkdir(parents=True, exist_ok=True)
                child = self._qr.analyze(
                    extracted.path, extracted.source_path, child_detection.name, child_workspace
                )
                qr_barcode.findings.extend(child.findings)
                qr_barcode.attempts.extend(child.attempts)
                qr_barcode.variants.extend(child.variants)
                qr_barcode.structures.extend(child.structures)
                qr_barcode.scanned_sources.extend(child.scanned_sources)
                qr_barcode.warnings.extend(child.warnings)
                qr_barcode.decoders_available = list(dict.fromkeys(qr_barcode.decoders_available + child.decoders_available))
                qr_barcode.decoders_unavailable = list(dict.fromkeys(qr_barcode.decoders_unavailable + child.decoders_unavailable))
                extracted_images += 1
            except (OSError, ValueError):
                continue
        qr_barcode.attempts = qr_barcode.attempts[:500]
        qr_barcode.variants = qr_barcode.variants[:24]
        qr_barcode.structures = qr_barcode.structures[:40]

        # Promote flags recovered specifically from metadata and machine-readable codes
        # into the existing unified flag list while retaining their source provenance.
        existing_flags = {(item.value, item.source) for item in flags}
        derived_sources: list[tuple[str, str]] = []
        for item in metadata_analysis.all_metadata:
            derived_sources.append((item.display_value, f"metadata:{item.key}"))
        for item in metadata_analysis.decoded:
            derived_sources.append((item.decoded, f"decoded-metadata:{item.field}"))
        for item in qr_barcode.findings:
            derived_sources.append((item.decoded_value, f"{item.symbology}:{item.source}"))
            if item.secondary_analysis and item.secondary_analysis.decoded:
                derived_sources.append((item.secondary_analysis.decoded, f"decoded-{item.symbology}:{item.source}"))
        custom_pattern = None
        if value.custom_flag_regex:
            try:
                custom_pattern = re.compile(value.custom_flag_regex)
            except re.error:
                warnings.append("The custom flag regex was invalid and was ignored.")
        for content, source in derived_sources:
            candidates = [
                (flag.value, flag.matched_pattern, flag.offset, flag.confidence, flag.context)
                for flag in flag_detector.detect(content.encode("utf-8", errors="replace"))
            ]
            if custom_pattern:
                candidates.extend(
                    (match.group(0), value.custom_flag_regex or "custom", match.start(), 0.95,
                     content[max(0, match.start() - 32):match.end() + 32])
                    for match in list(custom_pattern.finditer(content))[:20]
                )
            for flag_value, pattern, offset, confidence, context in candidates:
                if (flag_value, source) in existing_flags:
                    continue
                flags.append(FlagCandidate(
                    value=flag_value, matched_pattern=pattern, source=source, offset=offset,
                    confidence=confidence, context=context,
                ))
                existing_flags.add((flag_value, source))

        notable_findings = list(metadata_analysis.notable)
        for item in qr_barcode.findings:
            has_flag = bool(item.secondary_analysis and item.secondary_analysis.flags) or bool(
                flag_detector.detect(item.decoded_value.encode("utf-8", errors="replace"))
            )
            notable_findings.append(ForensicFinding(
                finding_id=str(uuid4()), severity="critical" if has_flag else "high",
                title=("Flag recovered from machine-readable code" if has_flag else f"{item.symbology} recovered"),
                reason=f"{item.decoder} decoded a validated payload using {item.recovery_method}.",
                analyzer="qr_barcode", section="findings", value=item.decoded_value[:1024],
            ))
        for item in flags:
            if not any(finding.severity == "critical" and finding.value == item.value for finding in notable_findings):
                notable_findings.append(ForensicFinding(
                    finding_id=str(uuid4()), severity="critical", title="Flag candidate recovered",
                    reason=f"A configured flag pattern matched data from {item.source}.",
                    analyzer="file", section="flags", value=item.value,
                ))
        if detection.name != "unknown" and detection.name not in {"text"}:
            notable_findings.append(ForensicFinding(
                finding_id=str(uuid4()), severity="info", title=f"Identified {detection.name.upper()} content",
                reason=detection.description, analyzer="file", section="overview",
            ))
        if _extension_assessment(value.original_filename, detection).mismatch:
            notable_findings.append(ForensicFinding(
                finding_id=str(uuid4()), severity="medium", title="Filename extension mismatch",
                reason=_extension_assessment(value.original_filename, detection).reason,
                analyzer="file", section="overview",
            ))
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        notable_findings.sort(key=lambda item: severity_order[item.severity])

        return ForensicsTriageResponse(
            analysis_id=str(uuid4()),
            artifact_id=value.artifact_id,
            analyzer=self.name,
            original_filename=value.original_filename,
            size=len(data),
            magic=MagicByteDetection(
                detected_type=detection.name,
                mime_type=detection.mime_type,
                description=detection.description,
                signature=detection.signature.hex() if detection.signature else None,
                confidence=detection.confidence,
            ),
            hashes=_hashes(data),
            metadata=metadata,
            metadata_analysis=metadata_analysis,
            qr_barcode=qr_barcode,
            notable_findings=notable_findings,
            strings=strings,
            strings_truncated=strings_truncated,
            entropy=_entropy(data),
            signatures=signatures,
            extension=_extension_assessment(value.original_filename, detection),
            embedded_files=embedded_files,
            archives=archives,
            flags=flags,
            extracted_artifacts=[
                _child_artifact(extracted, value.artifact_id) for extracted in extracted_paths
            ],
            warnings=warnings,
            limits=TriageLimits(
                max_upload_bytes=self.policy.max_upload_bytes,
                max_strings=self.policy.max_strings,
                max_archive_members=self.policy.max_archive_members,
                max_extracted_bytes=self.policy.max_extracted_bytes,
                max_compression_ratio=self.policy.max_compression_ratio,
            ),
        )
