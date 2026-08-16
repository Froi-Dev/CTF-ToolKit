from __future__ import annotations

import base64
import hashlib
import io
import math
import re
import time
import zlib
from collections import Counter
from dataclasses import dataclass
from typing import Iterable
from uuid import uuid4

import numpy as np
from PIL import Image

from app.analyzers.crypto.decoder import RecursiveDecoder, detect_encodings
from app.analyzers.forensics.signatures import scan_signatures
from app.schemas.crypto import DecodeRequest
from app.schemas.stego import (
    AnalysisChainStep,
    BarcodeDetection,
    BitPlaneVisual,
    CandidateEncoding,
    CandidateSignature,
    ExtractionMethod,
    PixelScanSummary,
    StegoFinding,
    StegoFlagCandidate,
)

_GENERAL_FLAG = re.compile(
    rb"(?P<prefix>[A-Za-z][A-Za-z0-9_]{1,31})\{(?P<body>[\x20-\x7e]{1,256})\}"
)
_PRINTABLE_RUN = re.compile(rb"[\t\r\n\x20-\x7e]{8,}")
_CTF_WORDS = (b"flag", b"ctf", b"secret", b"password", b"token", b"key", b"hidden")


@dataclass(frozen=True, slots=True)
class PixelScanPolicy:
    max_candidate_bytes: int = 512 * 1024
    quick_candidate_bytes: int = 128 * 1024
    max_export_bytes: int = 64 * 1024
    max_findings: int = 64
    max_noise_findings: int = 12
    max_deep_candidates: int = 24
    max_analysis_seconds: float = 15.0
    quick_analysis_seconds: float = 5.0
    max_decompressed_bytes: int = 1024 * 1024
    visual_max_dimension: int = 192


@dataclass(slots=True)
class _RawCandidate:
    data: bytes
    method: ExtractionMethod
    finding: StegoFinding


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return round(-sum((count / size) * math.log2(count / size) for count in counts.values()), 4)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    return sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data) / len(data)


def _best_text(data: bytes) -> tuple[int, bytes]:
    best_offset = 0
    best = b""
    for match in _PRINTABLE_RUN.finditer(data):
        candidate = match.group(0)
        if len(candidate) > len(best):
            best_offset, best = match.start(), candidate
    return best_offset, best


def _flags(data: bytes, source: str) -> list[StegoFlagCandidate]:
    found: list[StegoFlagCandidate] = []
    for match in _GENERAL_FLAG.finditer(data):
        value = match.group(0).decode("utf-8", errors="replace")
        prefix = match.group("prefix").decode("ascii", errors="replace")
        start, end = match.span()
        found.append(
            StegoFlagCandidate(
                value=value,
                matched_pattern=f"{prefix}{{...}}",
                source=source,
                offset=start,
                confidence=0.99,
                context=data[max(0, start - 32) : min(len(data), end + 32)].decode(
                    "utf-8", errors="replace"
                ),
            )
        )
    return found


def _compound_signature(data: bytes, name: str, offset: int) -> tuple[str, str | None]:
    if name == "riff" and offset + 12 <= len(data):
        form = data[offset + 8 : offset + 12]
        if form == b"WAVE":
            return "wav", "audio/wav"
        if form == b"WEBP":
            return "webp", "image/webp"
    return name, {"riff": "application/x-riff", "mp3": "audio/mpeg"}.get(name)


def _signatures(data: bytes, limit: int = 16) -> list[CandidateSignature]:
    results: list[CandidateSignature] = []
    seen: set[tuple[str, int]] = set()
    for signature, offset in scan_signatures(data, max_matches=limit):
        name, mime = _compound_signature(data, signature.name, offset)
        identity = (name, offset)
        if identity in seen:
            continue
        seen.add(identity)
        results.append(
            CandidateSignature(
                detected_type=name, mime_type=mime or signature.mime_type, offset=offset
            )
        )
    start = 0
    while start < len(data) - 1:
        offset = data.find(b"\x78", start)
        if offset < 0 or offset + 1 >= len(data):
            break
        header = int.from_bytes(data[offset : offset + 2], "big")
        if header % 31 == 0 and data[offset] & 0x0F == 8:
            identity = ("zlib", offset)
            if identity not in seen:
                results.append(
                    CandidateSignature(
                        detected_type="zlib", mime_type="application/zlib", offset=offset
                    )
                )
            break
        start = offset + 1
    return results[:limit]


def _safe_decompress(data: bytes, offset: int, kind: str, maximum: int) -> bytes | None:
    try:
        if kind == "gzip":
            decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif kind == "zlib":
            decompressor = zlib.decompressobj(zlib.MAX_WBITS)
        else:
            return None
        output = decompressor.decompress(data[offset:], maximum + 1)
        if len(output) > maximum or decompressor.unconsumed_tail or not decompressor.eof:
            return None
        output += decompressor.flush(maximum + 1 - len(output))
        return output if len(output) <= maximum else None
    except (OSError, EOFError, zlib.error, ValueError):
        return None


def _severity(score: int, has_flag: bool) -> str:
    if has_flag or score >= 90:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "noise"


def _method_notation(
    bits: int, channels: str, source_order: str, traversal: str, plane: int | None
) -> str:
    selector = source_order if plane in {None, 0, 7} else f"bit{plane}"
    return f"b{bits},{channels.lower()},{selector},{traversal}"


def _pack_samples(
    samples: np.ndarray,
    *,
    bits: int,
    source_order: str,
    byte_order: str,
    plane: int | None,
    max_bytes: int,
) -> bytes:
    if plane is not None:
        positions = np.array([plane], dtype=np.uint8)
    elif source_order == "lsb":
        positions = np.arange(bits, dtype=np.uint8)
    else:
        positions = np.arange(7, 7 - bits, -1, dtype=np.uint8)
    bit_matrix = ((samples[:, None] >> positions[None, :]) & 1).astype(np.uint8, copy=False)
    flat = bit_matrix.reshape(-1)
    usable = min((flat.size // 8) * 8, max_bytes * 8)
    if usable <= 0:
        return b""
    packed = np.packbits(
        flat[:usable], bitorder="big" if byte_order == "msb-first" else "little"
    )
    return packed.tobytes()


def _sample_values(
    pixels: np.ndarray,
    channel_indexes: tuple[int, ...],
    traversal: str,
    sample_limit: int,
) -> np.ndarray:
    height, width, _ = pixels.shape
    pixel_count = min(height * width, math.ceil(sample_limit / len(channel_indexes)))
    if traversal in {"xy", "reverse-xy"}:
        flat = pixels.reshape(-1, pixels.shape[2])
        selected = flat[:pixel_count] if traversal == "xy" else flat[-pixel_count:][::-1]
    else:
        sequence = np.arange(pixel_count, dtype=np.int64)
        if traversal == "reverse-yx":
            sequence = height * width - 1 - sequence
        y = sequence % height
        x = sequence // height
        selected = pixels[y, x]
    return selected[:, channel_indexes].reshape(-1)


def _detect_codes(image: Image.Image) -> list[tuple[str, str]]:
    detections: list[tuple[str, str]] = []
    try:
        import cv2  # type: ignore[import-not-found]

        array = np.asarray(image.convert("RGB"))[:, :, ::-1]
        detector = cv2.QRCodeDetector()
        value, _points, _straight = detector.detectAndDecode(array)
        if value:
            detections.append(("QR_CODE", value))
    except (ImportError, AttributeError, RuntimeError, ValueError):
        pass
    try:
        from pyzbar.pyzbar import decode as decode_barcode  # type: ignore[import-not-found]

        for decoded in decode_barcode(image):
            value = decoded.data.decode("utf-8", errors="replace")
            item = (str(decoded.type), value)
            if value and item not in detections:
                detections.append(item)
    except (ImportError, OSError, RuntimeError, ValueError):
        pass
    return detections


class PixelStegoEngine:
    """Bounded native zsteg-style extraction and candidate ranking engine."""

    def __init__(self, policy: PixelScanPolicy | None = None) -> None:
        self.policy = policy or PixelScanPolicy()
        self._decoder = RecursiveDecoder()

    def scan(
        self,
        pixels: np.ndarray,
        channel_names: list[str],
        *,
        show_all: bool = False,
        deep_scan: bool = False,
    ) -> tuple[list[StegoFinding], list[BitPlaneVisual], list[BarcodeDetection], PixelScanSummary]:
        started = time.monotonic()
        mode = "deep" if deep_scan else "quick"
        analysis_seconds = (
            self.policy.max_analysis_seconds
            if deep_scan
            else min(self.policy.quick_analysis_seconds, self.policy.max_analysis_seconds)
        )
        candidate_bytes = (
            self.policy.max_candidate_bytes
            if deep_scan
            else min(self.policy.quick_candidate_bytes, self.policy.max_candidate_bytes)
        )
        deadline = started + analysis_seconds
        stages = [
            "Analyzing pixel channels",
            "Testing bit-plane combinations",
            "Checking extracted streams",
            "Detecting file signatures and encodings",
            "Ranking candidates",
        ]
        channel_map = {name: index for index, name in enumerate(channel_names)}
        configurations = self._channel_configurations(channel_map)
        candidates: dict[str, _RawCandidate] = {}
        seen_streams: set[str] = set()
        noise_unique = 0
        pool_limit = max(96, self.policy.max_findings * 3)
        evaluated = 0
        truncated = False

        specifications: list[tuple[int, str, str, int | None]] = []
        for plane in range(8):
            source_order = "lsb" if plane <= 3 else "msb"
            specifications.append((1, source_order, "msb-first", plane))
            specifications.append((1, source_order, "lsb-first", plane))
        for bits in range(2, 5):
            for source_order in ("lsb", "msb"):
                specifications.append((bits, source_order, "msb-first", None))
                specifications.append((bits, source_order, "lsb-first", None))

        traversals = ("xy", "yx", "reverse-xy", "reverse-yx")
        for traversal in traversals:
            for channels, indexes in configurations:
                base_samples = _sample_values(
                    pixels,
                    indexes,
                    traversal,
                    candidate_bytes * 8,
                )
                for bits, source_order, byte_order, plane in specifications:
                    if not deep_scan and not self._quick_specification(
                        traversal, bits, byte_order, plane
                    ):
                        continue
                    if time.monotonic() >= deadline:
                        truncated = True
                        break
                    sample_limit = math.ceil(candidate_bytes * 8 / bits)
                    samples = base_samples[:sample_limit]
                    data = _pack_samples(
                        samples,
                        bits=bits,
                        source_order=source_order,
                        byte_order=byte_order,
                        plane=plane,
                        max_bytes=candidate_bytes,
                    )
                    evaluated += 1
                    method = ExtractionMethod(
                        notation=_method_notation(bits, channels, source_order, traversal, plane),
                        bits_per_channel=bits,
                        channels=channels,
                        bit_plane=plane,
                        bit_order=source_order,
                        byte_bit_order=byte_order,
                        traversal=traversal,
                    )
                    raw = self._assess(data, method)
                    identity = hashlib.sha256(data).hexdigest()
                    if identity in seen_streams:
                        previous = candidates.get(identity)
                        if previous is not None and method.notation not in previous.finding.equivalent_methods:
                            previous.finding.equivalent_methods.append(method.notation)
                        continue
                    seen_streams.add(identity)
                    if raw.finding.severity == "noise":
                        noise_unique += 1
                        if not show_all:
                            continue
                    previous = candidates.get(identity)
                    if previous is None:
                        candidates[identity] = raw
                    elif raw.finding.score > previous.finding.score:
                        raw.finding.equivalent_methods = [
                            previous.method.notation,
                            *previous.finding.equivalent_methods,
                        ]
                        candidates[identity] = raw
                    elif method.notation not in previous.finding.equivalent_methods:
                        previous.finding.equivalent_methods.append(method.notation)
                    if len(candidates) > pool_limit:
                        weakest_identity = min(
                            candidates,
                            key=lambda key: (
                                candidates[key].finding.score,
                                candidates[key].finding.confidence,
                            ),
                        )
                        del candidates[weakest_identity]
                if truncated:
                    break
            if truncated:
                break

        ranked = sorted(candidates.values(), key=lambda item: item.finding.score, reverse=True)
        deep_limit = min(self.policy.max_deep_candidates, len(ranked))
        for candidate in ranked[:deep_limit]:
            if time.monotonic() >= deadline:
                truncated = True
                break
            self._deep_analyze(candidate)
        ranked.sort(key=lambda item: (item.finding.score, item.finding.confidence), reverse=True)

        non_noise = [item.finding for item in ranked if item.finding.severity != "noise"]
        noise = [item.finding for item in ranked if item.finding.severity == "noise"]
        findings = non_noise[: self.policy.max_findings]
        if show_all and len(findings) < self.policy.max_findings:
            findings.extend(noise[: min(self.policy.max_noise_findings, self.policy.max_findings - len(findings))])

        visuals, barcodes = self._visuals(pixels, channel_names)
        findings.extend(self._barcode_findings(barcodes))
        findings.sort(key=lambda item: (item.score, item.confidence), reverse=True)
        findings = findings[: self.policy.max_findings]
        elapsed = max(0, round((time.monotonic() - started) * 1000))
        summary = PixelScanSummary(
            mode=mode,
            candidates_evaluated=evaluated,
            unique_streams=len(seen_streams),
            retained_findings=len(findings),
            noise_hidden=0 if show_all else noise_unique,
            elapsed_ms=elapsed,
            truncated=truncated,
            stages=stages,
        )
        return findings, visuals, barcodes, summary

    @staticmethod
    def _quick_specification(
        traversal: str,
        bits: int,
        byte_order: str,
        plane: int | None,
    ) -> bool:
        """Prioritize common CTF layouts while leaving every variant to deep mode."""
        if plane is not None:
            if traversal == "xy":
                return byte_order == "msb-first" or plane == 0
            return plane in {0, 1} and (
                byte_order == "msb-first" or plane == 0
            )
        return traversal == "xy" and byte_order == "msb-first" and bits in {2, 3, 4}

    @staticmethod
    def _channel_configurations(channel_map: dict[str, int]) -> list[tuple[str, tuple[int, ...]]]:
        configurations = [(name, (index,)) for name, index in channel_map.items()]
        for order in ("RGB", "RGBA", "BGR", "BGRA"):
            if all(name in channel_map for name in order):
                configurations.append((order, tuple(channel_map[name] for name in order)))
        return configurations

    def _assess(self, data: bytes, method: ExtractionMethod) -> _RawCandidate:
        source = f"pixel:{method.notation}:{method.byte_bit_order}"
        flags = _flags(data, source)
        signatures = _signatures(data)
        text_offset, best_text = _best_text(data)
        sample = data[:32_768]
        printable = _printable_ratio(sample)
        text_printable = _printable_ratio(best_text) if best_text else 0.0
        try:
            sample.decode("utf-8")
            utf8 = True
        except UnicodeDecodeError:
            utf8 = False
        null_ratio = sample.count(0) / len(sample) if sample else 0.0
        most_common_ratio = Counter(sample).most_common(1)[0][1] / len(sample) if sample else 1.0
        lowered = best_text.lower()
        keyword_hits = sum(word in lowered for word in _CTF_WORDS)
        structured = bool(re.search(rb"(?:https?://|[A-Za-z0-9_]+=|\{[^}\r\n]+\})", best_text))
        encoding_detections = []
        if 4 <= len(best_text) <= 32_768 and text_printable >= 0.95:
            encoding_detections = [item for item in detect_encodings(best_text) if item.confidence >= 0.78]
            letter_ratio = (
                sum(byte in range(65, 91) or byte in range(97, 123) for byte in best_text)
                / len(best_text)
            )
            if not encoding_detections and len(best_text) >= 8 and letter_ratio >= 0.45:
                encoding_detections = [
                    CandidateEncoding(
                        name="ROT/Caesar",
                        confidence=0.55,
                        evidence="Printable alphabetic text is suitable for bounded ROT/Caesar testing.",
                    )
                ]

        score = 0
        reasons: list[str] = []
        if flags:
            score += 100
            reasons.append("recognized generalized CTF flag structure")
        if signatures:
            score += 60
            reasons.append(f"known {signatures[0].detected_type.upper()} signature")
        if len(best_text) >= 12 and text_printable >= 0.95:
            score += min(35, 20 + len(best_text) // 16)
            reasons.append("high-printability text run")
        if encoding_detections:
            score += 30 if encoding_detections[0].confidence >= 0.78 else 15
            reasons.append(f"plausible {encoding_detections[0].name} encoding")
        if utf8 and printable >= 0.70:
            score += 25
            reasons.append("valid UTF-8")
        if structured:
            score += 20
            reasons.append("recognizable structured text")
        if keyword_hits:
            score += min(15, keyword_hits * 5)
            reasons.append("CTF-related keywords")
        if null_ratio > 0.50 and not flags and not signatures:
            score -= 20
        if most_common_ratio > 0.80 and not flags and not signatures:
            score -= 30
        score = max(0, min(100, score))
        severity = _severity(score, bool(flags))
        confidence = 0.99 if flags else min(0.96, max(0.05, score / 100))
        offset = flags[0].offset if flags else signatures[0].offset if signatures else text_offset
        preview_source = best_text if best_text else data[:256]
        preview = preview_source[:512].decode("utf-8", errors="replace")
        exported = data[: self.policy.max_export_bytes]
        detected_type = (
            "ctf_flag" if flags else signatures[0].detected_type if signatures else
            "encoded_text" if encoding_detections else "text" if best_text else "binary"
        )
        title = (
            "FLAG CANDIDATE FOUND" if flags else
            f"Embedded {signatures[0].detected_type.upper()} candidate" if signatures else
            f"{encoding_detections[0].name} payload" if encoding_detections else
            "Readable pixel stream" if best_text else "Low-value pixel stream"
        )
        finding = StegoFinding(
            finding_id=str(uuid4()),
            title=title,
            source="pixel_steganography",
            severity=severity,
            confidence=round(confidence, 4),
            score=score,
            detected_type=detected_type,
            explanation=" + ".join(reasons) if reasons else "No strong semantic signal was detected.",
            method=method,
            offset=offset,
            length=len(data),
            entropy=_entropy(sample),
            printable_ratio=round(printable, 4),
            utf8_valid=utf8,
            null_ratio=round(null_ratio, 4),
            preview_text=preview,
            preview_hex=data[:128].hex(),
            data_base64=base64.b64encode(exported).decode("ascii"),
            data_truncated=len(data) > len(exported),
            signatures=signatures,
            encodings=[
                item if isinstance(item, CandidateEncoding) else CandidateEncoding(**item.model_dump())
                for item in encoding_detections
            ],
            flags=flags,
            analysis_chain=[
                AnalysisChainStep(operation="pixel extraction", detail=f"{method.notation}, {method.byte_bit_order}")
            ],
        )
        return _RawCandidate(data=data, method=method, finding=finding)

    def _deep_analyze(self, candidate: _RawCandidate) -> None:
        finding = candidate.finding
        data = candidate.data
        for signature in finding.signatures:
            decompressed = _safe_decompress(
                data, signature.offset, signature.detected_type, self.policy.max_decompressed_bytes
            )
            if decompressed is None:
                continue
            finding.score = min(100, finding.score + 40)
            finding.explanation += " + valid bounded compressed stream"
            finding.analysis_chain.append(
                AnalysisChainStep(operation="decompress", detail=signature.detected_type)
            )
            decoded_flags = _flags(decompressed, f"decompressed:{candidate.method.notation}")
            if decoded_flags:
                finding.flags.extend(decoded_flags)
                finding.title = "FLAG CANDIDATE FOUND"
                finding.detected_type = "ctf_flag"
                finding.score = 100
            inner = _signatures(decompressed)
            if inner:
                finding.signatures.extend(item for item in inner if item not in finding.signatures)
                finding.analysis_chain.append(
                    AnalysisChainStep(operation="detect file", detail=inner[0].detected_type)
                )

        _offset, text = _best_text(data)
        if finding.encodings and 4 <= len(text) <= 32_768:
            try:
                response = self._decoder.analyze(
                    DecodeRequest(
                        input=text.decode("utf-8"),
                        max_depth=3,
                        max_results=4,
                        beam_width=12,
                        timeout_ms=250,
                        flag_prefixes=["flag", "FLAG", "CTF", "picoCTF", "HTB", "THM", "H4G"],
                    )
                )
            except (UnicodeDecodeError, ValueError):
                response = None
            if response is not None and response.results:
                best = response.results[0]
                generalized_decoded: list[StegoFlagCandidate] = []
                for result in response.results:
                    try:
                        decoded_data = base64.b64decode(result.output_base64, validate=True)
                    except ValueError:
                        continue
                    detected = _flags(decoded_data, f"decoder:{candidate.method.notation}")
                    if detected:
                        best = result
                        generalized_decoded.extend(detected)
                for step in best.chain:
                    finding.analysis_chain.append(
                        AnalysisChainStep(
                            operation="decode",
                            detail=step.transform + (f" ({step.parameter})" if step.parameter else ""),
                        )
                    )
                if response.flags or generalized_decoded:
                    existing = {flag.value for flag in finding.flags}
                    for decoded in response.flags:
                        if decoded.value in existing:
                            continue
                        finding.flags.append(
                            StegoFlagCandidate(
                                value=decoded.value,
                                matched_pattern=decoded.matched_pattern,
                                source=f"decoder:{candidate.method.notation}",
                                offset=decoded.offset,
                                confidence=decoded.confidence,
                                context=decoded.context,
                            )
                        )
                    for decoded in generalized_decoded:
                        if decoded.value not in existing:
                            finding.flags.append(decoded)
                            existing.add(decoded.value)
                    finding.title = "FLAG CANDIDATE FOUND"
                    finding.detected_type = "ctf_flag"
                    finding.score = 100
                    finding.explanation += " + recursive decoder recovered a flag"
        finding.severity = _severity(finding.score, bool(finding.flags))
        finding.confidence = 0.99 if finding.flags else min(0.96, max(finding.confidence, finding.score / 100))

    def _visuals(
        self, pixels: np.ndarray, channel_names: list[str]
    ) -> tuple[list[BitPlaneVisual], list[BarcodeDetection]]:
        visuals: list[BitPlaneVisual] = []
        barcodes: list[BarcodeDetection] = []
        original = Image.fromarray(pixels.astype(np.uint8), mode="RGBA" if pixels.shape[2] == 4 else "RGB")
        barcode_source = original
        if max(original.size) > 1024:
            barcode_source = original.copy()
            barcode_source.thumbnail((1024, 1024), getattr(Image, "Resampling", Image).NEAREST)
        for symbology, payload in _detect_codes(barcode_source):
            barcodes.append(BarcodeDetection(symbology=symbology, payload=payload, source="original"))

        height, width = pixels.shape[:2]
        stride = max(
            1,
            math.ceil(max(height, width) / self.policy.visual_max_dimension),
        )
        for channel_index, channel in enumerate(channel_names):
            values = pixels[::stride, ::stride, channel_index]
            for bit in range(8):
                plane = (((values >> bit) & 1) * 255).astype(np.uint8)
                image = Image.fromarray(plane, mode="L")
                codes = _detect_codes(image)
                payloads = [payload for _symbology, payload in codes]
                for symbology, payload in codes:
                    barcodes.append(
                        BarcodeDetection(
                            symbology=symbology, payload=payload, source=f"bit-plane:{channel}{bit}"
                        )
                    )
                output = io.BytesIO()
                image.save(output, format="PNG")
                visuals.append(
                    BitPlaneVisual(
                        channel=channel,
                        bit=bit,
                        label=f"{channel}{bit}",
                        width=image.width,
                        height=image.height,
                        png_base64=base64.b64encode(output.getvalue()).decode("ascii"),
                        one_ratio=round(float(np.mean(plane > 0)), 4),
                        qr_payloads=payloads,
                    )
                )
        unique: dict[tuple[str, str], BarcodeDetection] = {}
        for item in barcodes:
            unique[(item.symbology, item.payload)] = item
        return visuals, list(unique.values())

    @staticmethod
    def _barcode_findings(barcodes: Iterable[BarcodeDetection]) -> list[StegoFinding]:
        findings: list[StegoFinding] = []
        for barcode in barcodes:
            data = barcode.payload.encode("utf-8")
            flags = _flags(data, barcode.source)
            score = 100 if flags else 70
            findings.append(
                StegoFinding(
                    finding_id=str(uuid4()),
                    title="FLAG CANDIDATE FOUND" if flags else f"{barcode.symbology} payload",
                    source="qr_barcode",
                    severity="critical" if flags else "high",
                    confidence=0.99 if flags else 0.9,
                    score=score,
                    detected_type="ctf_flag" if flags else "barcode_text",
                    explanation=f"Decoded {barcode.symbology} from {barcode.source}.",
                    offset=0,
                    length=len(data),
                    entropy=_entropy(data),
                    printable_ratio=_printable_ratio(data),
                    utf8_valid=True,
                    null_ratio=0.0,
                    preview_text=barcode.payload[:512],
                    preview_hex=data[:128].hex(),
                    data_base64=base64.b64encode(data).decode("ascii"),
                    data_truncated=False,
                    flags=flags,
                    analysis_chain=[
                        AnalysisChainStep(operation="barcode detection", detail=barcode.source)
                    ],
                )
            )
        return findings


__all__ = ["PixelScanPolicy", "PixelStegoEngine"]
