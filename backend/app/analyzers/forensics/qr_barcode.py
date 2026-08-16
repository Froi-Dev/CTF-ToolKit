from __future__ import annotations

import base64
import io
import math
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter, ImageOps, UnidentifiedImageError

from app.analyzers.crypto.decoder import RecursiveDecoder, detect_encodings
from app.core.errors import ToolExecutionError
from app.core.tool_runner import ToolRunner
from app.schemas.crypto import DecodeRequest
from app.schemas.forensics import (
    BoundingBox,
    CodeFinding,
    DecodeStep,
    QRBarcodeAnalysis,
    QRDecodeResult,
    QRStructure,
    RecoveryAttempt,
    RecoveryStep,
    RecoveryVariant,
)

_FLAG_PREFIXES = ["flag", "CTF", "picoCTF", "HTB", "THM", "hack", "H4G"]
_OFFICE_IMAGE_PREFIXES = ("word/media/", "xl/media/", "ppt/media/", "Pictures/")


@dataclass(slots=True)
class _ImageSource:
    label: str
    image: Image.Image
    page: int | None = None
    frame: int | None = None
    timestamp: float | None = None
    scan_bit_planes: bool = False


@dataclass(slots=True)
class _Decoded:
    symbology: str
    value: str
    decoder: str
    box: BoundingBox | None


def _step(operation: str, tool: str = "Pillow", **parameters: str | int | float | bool) -> RecoveryStep:
    return RecoveryStep(operation=operation, tool=tool, parameters=parameters)


def _normalize_symbology(value: str) -> str:
    compact = "".join(character for character in value.upper() if character.isalnum())
    names = {
        "QRCODE": "QR Code", "MICROQRCODE": "Micro QR", "DATAMATRIX": "Data Matrix",
        "PDF417": "PDF417", "CODE128": "Code 128", "CODE39": "Code 39",
        "CODE93": "Code 93", "EAN8": "EAN-8", "EAN13": "EAN-13",
        "UPCA": "UPC-A", "UPCE": "UPC-E", "ITF": "ITF", "CODABAR": "Codabar",
        "AZTEC": "Aztec",
    }
    return names.get(compact, value.replace("_", " ").strip())


def _png(image: Image.Image, max_dimension: int = 1024) -> tuple[str, int, int]:
    exported = image.copy()
    if max(exported.size) > max_dimension:
        exported.thumbnail((max_dimension, max_dimension), Image.Resampling.NEAREST)
    output = io.BytesIO()
    exported.save(output, "PNG", optimize=True)
    return base64.b64encode(output.getvalue()).decode("ascii"), exported.width, exported.height


def _bounded_copy(image: Image.Image, maximum: int = 1600) -> Image.Image:
    copied = image.copy()
    if max(copied.size) > maximum:
        copied.thumbnail((maximum, maximum), Image.Resampling.LANCZOS)
    return copied


class QRBarcodeRecoveryAnalyzer:
    """Bounded, provenance-preserving multi-variant code recovery."""

    def __init__(self, runner: ToolRunner | None = None) -> None:
        self._runner = runner or ToolRunner(
            {"pdftoppm", "ffmpeg"}, default_timeout_seconds=20, default_output_limit=2 * 1024 * 1024
        )
        self._decoder = RecursiveDecoder()

    def analyze(self, path: Path, filename: str, detected_type: str, workspace: Path) -> QRBarcodeAnalysis:
        available, unavailable = self._decoder_availability()
        sources, discovery_warnings = self._sources(path, filename, detected_type, workspace)
        attempts: list[RecoveryAttempt] = []
        variants: list[RecoveryVariant] = []
        findings: list[CodeFinding] = []
        structures: list[QRStructure] = []
        seen: set[tuple[str, str, str]] = set()

        for source in sources[:80]:
            try:
                source.image.load()
                image = source.image.convert("RGBA" if "A" in source.image.getbands() else "RGB")
            except (OSError, ValueError):
                continue
            if image.width * image.height > 2_560_000 or max(image.size) > 1600:
                image.thumbnail((1600, 1600), Image.Resampling.LANCZOS)
            candidates = self._variants(image, include_bit_planes=source.scan_bit_planes)
            decoded_for_source = False
            geometry_added = False
            for index, (label, candidate, provenance) in enumerate(candidates):
                results, structure = self._decode(candidate)
                if structure and not geometry_added:
                    structure.source = source.label
                    structures.append(structure)
                    geometry_added = True
                decoders_tried = available or ["none"]
                for decoder in decoders_tried:
                    succeeded = any(result.decoder == decoder for result in results)
                    attempts.append(RecoveryAttempt(
                        source=source.label, variant=label, decoder=decoder, success=succeeded,
                        detail="Payload decoded." if succeeded else "No validated payload returned.",
                    ))
                for result in results:
                    key = (result.symbology, result.value, source.label)
                    if key in seen:
                        continue
                    seen.add(key)
                    decoded_for_source = True
                    chain = self._secondary(result.value)
                    findings.append(CodeFinding(
                        finding_id=str(uuid4()), symbology=result.symbology,
                        decoded_value=result.value, source=source.label, page=source.page,
                        frame=source.frame, timestamp_seconds=source.timestamp,
                        bounding_box=result.box, decoder=result.decoder,
                        confidence="high" if label == "Original" else "medium",
                        recovery_method=" → ".join(item.operation for item in provenance) or "Direct detection",
                        provenance=[_step("Original evidence", "CTFKit", source=filename), *provenance,
                                    _step("Decode", result.decoder, symbology=result.symbology)],
                        secondary_analysis=chain,
                    ))
                # Keep a useful, bounded recovery preview instead of returning every generated image.
                if (results or label in {"Original", "Grayscale", "Adaptive threshold", "Inverted", "4× nearest upscale", "Perspective corrected"} or label.startswith("Region candidate")) and len(variants) < 16:
                    encoded, width, height = _png(candidate)
                    variants.append(RecoveryVariant(
                        variant_id=str(uuid4()), label=label, source=source.label,
                        width=width, height=height, image_base64=encoded,
                        transformations=provenance, best_candidate=bool(results),
                    ))
                # Direct success still permits other decoders on the same image, but avoids dozens of redundant transforms.
                if decoded_for_source and index == 0:
                    break

        if structures and not findings and variants:
            variants[-1].best_candidate = True
        warnings = discovery_warnings
        if not available:
            warnings.append(
                "No QR/barcode decoder is installed. Recovery variants were generated, but no payload can be claimed without a decoder."
            )
        return QRBarcodeAnalysis(
            findings=findings, attempts=attempts[:500], variants=variants,
            structures=structures[:40], decoders_available=available,
            decoders_unavailable=unavailable,
            scanned_sources=[source.label for source in sources[:80]], warnings=warnings,
        )

    @staticmethod
    def _decoder_availability() -> tuple[list[str], list[str]]:
        available: list[str] = []
        unavailable: list[str] = []
        try:
            import cv2  # type: ignore[import-not-found]  # noqa: F401
            available.append("OpenCV QRCodeDetector")
        except ImportError:
            unavailable.append("OpenCV QRCodeDetector")
        try:
            from pyzbar.pyzbar import decode  # type: ignore[import-not-found]  # noqa: F401
            available.append("pyzbar/zbar")
        except (ImportError, OSError):
            unavailable.append("pyzbar/zbar")
        try:
            import zxingcpp  # type: ignore[import-not-found]  # noqa: F401
            available.append("ZXing-C++")
        except ImportError:
            unavailable.append("ZXing-C++")
        return available, unavailable

    def _sources(self, path: Path, filename: str, detected_type: str, workspace: Path) -> tuple[list[_ImageSource], list[str]]:
        sources: list[_ImageSource] = []
        warnings: list[str] = []
        try:
            image = Image.open(path)
            frames = getattr(image, "n_frames", 1)
            selected = range(frames) if frames <= 40 else sorted({round(index * (frames - 1) / 39) for index in range(40)})
            timestamps: list[float] = []
            elapsed = 0.0
            for frame_index in range(frames):
                image.seek(frame_index)
                timestamps.append(elapsed)
                elapsed += float(image.info.get("duration", 0)) / 1000
            for frame_index in selected:
                image.seek(frame_index)
                frame = _bounded_copy(image, 1200)
                label = filename if frames == 1 else f"{filename} · frame {frame_index}"
                sources.append(_ImageSource(
                    label, frame, frame=frame_index if frames > 1 else None,
                    timestamp=timestamps[frame_index] if frames > 1 else None,
                    scan_bit_planes=frames == 1,
                ))
            if frames > 40:
                warnings.append(f"Animated image scanning used 40 representative frames from {frames} total frames.")
        except (UnidentifiedImageError, OSError, EOFError):
            pass

        if detected_type == "pdf":
            if self._runner.available("pdftoppm"):
                prefix = workspace / "pdf-page"
                try:
                    result = self._runner.run(
                        "pdftoppm", ["-png", "-r", "160", "-scale-to", "2200", "-f", "1", "-l", "30", str(path), str(prefix)],
                        cwd=workspace, timeout_seconds=30,
                    )
                except ToolExecutionError:
                    result = None
                    warnings.append("PDF rendering exceeded a safety limit or failed.")
                if result is not None and result.returncode == 0:
                    for page_path in sorted(workspace.glob("pdf-page-*.png")):
                        try:
                            page = int(page_path.stem.rsplit("-", 1)[-1])
                            sources.append(_ImageSource(f"{filename} · page {page}", _bounded_copy(Image.open(page_path)), page=page))
                        except (ValueError, OSError):
                            continue
                elif result is not None:
                    warnings.append("PDF rendering failed; embedded images may still be scanned.")
            else:
                warnings.append("pdftoppm is unavailable, so PDF pages could not be rendered for QR scanning.")

        if detected_type in {"docx", "xlsx", "pptx", "odt", "zip"}:
            try:
                with zipfile.ZipFile(path) as archive:
                    for member in archive.infolist():
                        if not member.filename.startswith(_OFFICE_IMAGE_PREFIXES) or member.file_size > 16 * 1024 * 1024:
                            continue
                        try:
                            embedded = _bounded_copy(Image.open(io.BytesIO(archive.read(member))))
                            sources.append(_ImageSource(f"{filename} · {member.filename}", embedded, scan_bit_planes=True))
                        except (UnidentifiedImageError, OSError, RuntimeError):
                            continue
            except (zipfile.BadZipFile, OSError):
                pass

        if detected_type in {"mp4", "mov", "avi", "mkv", "webm"}:
            if self._runner.available("ffmpeg"):
                output_pattern = workspace / "video-frame-%05d.png"
                try:
                    result = self._runner.run(
                        "ffmpeg", ["-hide_banner", "-loglevel", "error", "-i", str(path), "-vf", "fps=1/2,scale=1920:1080:force_original_aspect_ratio=decrease", "-frames:v", "60", str(output_pattern)],
                        cwd=workspace, timeout_seconds=45,
                    )
                except ToolExecutionError:
                    result = None
                    warnings.append("Video frame extraction exceeded a safety limit or failed.")
                if result is not None and result.returncode == 0:
                    for index, frame_path in enumerate(sorted(workspace.glob("video-frame-*.png"))):
                        sources.append(_ImageSource(
                            f"{filename} · {index * 2:.3f}s", _bounded_copy(Image.open(frame_path)),
                            frame=index, timestamp=float(index * 2),
                        ))
                    scene_pattern = workspace / "scene-frame-%04d.png"
                    try:
                        scene_result = self._runner.run(
                            "ffmpeg", ["-hide_banner", "-loglevel", "error", "-i", str(path),
                                       "-vf", "select=gt(scene\\,0.35),scale=1920:1080:force_original_aspect_ratio=decrease",
                                       "-vsync", "vfr", "-frames:v", "20", str(scene_pattern)],
                            cwd=workspace, timeout_seconds=30,
                        )
                    except ToolExecutionError:
                        scene_result = None
                        warnings.append("Scene-change frame extraction exceeded a safety limit or failed.")
                    if scene_result is not None and scene_result.returncode == 0:
                        for index, frame_path in enumerate(sorted(workspace.glob("scene-frame-*.png"))):
                            sources.append(_ImageSource(
                                f"{filename} · scene-change frame {index}", _bounded_copy(Image.open(frame_path)), frame=index,
                            ))
                elif result is not None:
                    warnings.append("Video frame extraction failed safely.")
            else:
                warnings.append("ffmpeg is unavailable, so representative video frames were not scanned.")
        return sources, warnings

    @staticmethod
    def _variants(
        image: Image.Image, *, include_bit_planes: bool = False
    ) -> list[tuple[str, Image.Image, list[RecoveryStep]]]:
        rgb = image.convert("RGB")
        gray = ImageOps.grayscale(rgb)
        variants: list[tuple[str, Image.Image, list[RecoveryStep]]] = [
            ("Original", rgb, []),
            ("Grayscale", gray, [_step("Grayscale")]),
            ("Contrast enhanced", ImageOps.autocontrast(gray, cutoff=1), [_step("Grayscale"), _step("Autocontrast", cutoff=1)]),
            ("Histogram equalized", ImageOps.equalize(gray), [_step("Grayscale"), _step("Histogram equalization")]),
            ("Brightness normalized", ImageEnhance.Brightness(ImageOps.autocontrast(gray)).enhance(1.15), [_step("Grayscale"), _step("Brightness normalization", factor=1.15)]),
            ("Sharpened", gray.filter(ImageFilter.UnsharpMask(radius=2, percent=180, threshold=2)), [_step("Grayscale"), _step("Unsharp mask", radius=2, percent=180)]),
            ("Denoised", gray.filter(ImageFilter.MedianFilter(size=3)), [_step("Grayscale"), _step("Median denoise", size=3)]),
            ("Otsu threshold", gray.point(lambda p: 255 if p > 127 else 0), [_step("Grayscale"), _step("Threshold", threshold=127)]),
            ("Inverted", ImageOps.invert(gray), [_step("Grayscale"), _step("Inversion")]),
        ]
        if max(image.size) <= 500:
            variants.append(("4× nearest upscale", gray.resize((gray.width * 4, gray.height * 4), Image.Resampling.NEAREST), [_step("Grayscale"), _step("Upscale", scale=4, interpolation="nearest")]))
        for channel in image.getbands():
            if channel in {"R", "G", "B", "A"}:
                variants.append((f"{channel} channel", image.getchannel(channel), [_step("Channel extraction", channel=channel)]))
        if include_bit_planes:
            for channel in image.getbands():
                if channel not in {"R", "G", "B", "A"}:
                    continue
                channel_values = np.asarray(image.getchannel(channel), dtype=np.uint8)
                for bit in range(8):
                    plane = (((channel_values >> bit) & 1) * 255).astype(np.uint8)
                    variants.append((
                        f"{channel} bit-plane {bit}", Image.fromarray(plane, mode="L"),
                        [_step("Channel extraction", channel=channel), _step("Bit-plane extraction", bit=bit)],
                    ))
        for angle in (90, 180, 270):
            variants.append((f"Rotated {angle}°", gray.rotate(angle, expand=True), [_step("Grayscale"), _step("Rotation", degrees=angle)]))
        if max(image.size) <= 1600:
            for angle in (-10, -5, 5, 10):
                variants.append((f"Deskew {angle:+d}°", gray.rotate(angle, expand=True, fillcolor=255), [_step("Grayscale"), _step("Fine rotation / deskew", degrees=angle)]))
        try:
            import cv2  # type: ignore[import-not-found]
            array = np.asarray(gray)
            bgr = np.asarray(rgb)[:, :, ::-1]
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(array)
            adaptive = cv2.adaptiveThreshold(array, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 31, 5)
            _level, otsu = cv2.threshold(array, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            variants.extend([
                ("CLAHE", Image.fromarray(clahe), [_step("Grayscale"), _step("CLAHE", "OpenCV", clip_limit=2.0, grid="8x8")]),
                ("Adaptive threshold", Image.fromarray(adaptive), [_step("Grayscale"), _step("Adaptive threshold", "OpenCV", block_size=31, constant=5)]),
                ("Otsu automatic threshold", Image.fromarray(otsu), [_step("Grayscale"), _step("Otsu threshold", "OpenCV")]),
                ("Adaptive threshold inverted", Image.fromarray(255 - adaptive), [_step("Grayscale"), _step("Adaptive threshold", "OpenCV", block_size=31, constant=5), _step("Inversion")]),
            ])
            detector = cv2.QRCodeDetector()
            detected, points = detector.detect(bgr)
            if detected and points is not None:
                corners = np.asarray(points).reshape(4, 2).astype(np.float32)
                side = max(128, int(max(
                    np.linalg.norm(corners[0] - corners[1]), np.linalg.norm(corners[1] - corners[2]),
                    np.linalg.norm(corners[2] - corners[3]), np.linalg.norm(corners[3] - corners[0]),
                )))
                target = np.array([[0, 0], [side - 1, 0], [side - 1, side - 1], [0, side - 1]], dtype=np.float32)
                matrix = cv2.getPerspectiveTransform(corners, target)
                rectified = cv2.warpPerspective(bgr, matrix, (side, side), borderValue=(255, 255, 255))
                variants.append(("Perspective corrected", Image.fromarray(cv2.cvtColor(rectified, cv2.COLOR_BGR2RGB)), [_step("Corner detection", "OpenCV"), _step("Perspective transformation / homography", "OpenCV", output_size=side)]))
            # Search large near-square rectangular regions; each crop is decoder-validated later.
            contours, _hierarchy = cv2.findContours(adaptive, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
            regions: list[tuple[int, int, int, int]] = []
            for contour in sorted(contours, key=cv2.contourArea, reverse=True)[:80]:
                x, y, width, height = cv2.boundingRect(contour)
                area_ratio = (width * height) / max(1, image.width * image.height)
                if 0.01 <= area_ratio <= 0.9 and 0.65 <= width / max(1, height) <= 1.5:
                    region = (x, y, width, height)
                    if all(abs(x - old[0]) + abs(y - old[1]) > 12 for old in regions):
                        regions.append(region)
                if len(regions) >= 4:
                    break
            for index, (x, y, width, height) in enumerate(regions):
                margin = max(4, round(max(width, height) * 0.08))
                left, top = max(0, x - margin), max(0, y - margin)
                right, bottom = min(image.width, x + width + margin), min(image.height, y + height + margin)
                crop = rgb.crop((left, top, right, bottom))
                variants.append((f"Region candidate {index + 1}", crop, [_step("Rectangular region search", "OpenCV"), _step("Crop", "Pillow", x=left, y=top, width=right-left, height=bottom-top)]))
            for space, conversion, names in (
                ("HSV", cv2.COLOR_BGR2HSV, ("H", "S", "V")),
                ("LAB", cv2.COLOR_BGR2LAB, ("L", "A", "B")),
            ):
                converted = cv2.cvtColor(bgr, conversion)
                for index, name in enumerate(names):
                    variants.append((f"{space} {name} channel", Image.fromarray(converted[:, :, index]), [_step("Color-space conversion", "OpenCV", space=space), _step("Channel extraction", "OpenCV", channel=name)]))
        except Exception:
            # Every OpenCV stage is optional; a malformed image or unsupported build
            # must not discard the Pillow variants already produced.
            pass
        return variants[:72]

    @staticmethod
    def _decode(image: Image.Image) -> tuple[list[_Decoded], QRStructure | None]:
        found: list[_Decoded] = []
        structure: QRStructure | None = None
        try:
            import cv2  # type: ignore[import-not-found]
            array = np.asarray(image.convert("RGB"))[:, :, ::-1]
            detector = cv2.QRCodeDetector()
            try:
                ok, values, points, _straight = detector.detectAndDecodeMulti(array)
            except (AttributeError, cv2.error):
                ok, values, points = False, (), None
            if ok and points is not None:
                for value, polygon in zip(values, points):
                    if not value:
                        continue
                    xs, ys = polygon[:, 0], polygon[:, 1]
                    box = BoundingBox(x=max(0, int(xs.min())), y=max(0, int(ys.min())), width=max(0, int(xs.max() - xs.min())), height=max(0, int(ys.max() - ys.min())))
                    found.append(_Decoded("QR Code", value, "OpenCV QRCodeDetector", box))
            if not found:
                value, points, straight = detector.detectAndDecode(array)
                if points is not None:
                    polygon = np.asarray(points).reshape(-1, 2)
                    xs, ys = polygon[:, 0], polygon[:, 1]
                    orientation = math.degrees(math.atan2(float(polygon[1, 1] - polygon[0, 1]), float(polygon[1, 0] - polygon[0, 0])))
                    modules = int(straight.shape[0]) if straight is not None and getattr(straight, "size", 0) else None
                    version = ((modules - 21) // 4 + 1) if modules and modules >= 21 and (modules - 21) % 4 == 0 else None
                    structure = QRStructure(source="", finder_patterns=3, estimated_version=version, estimated_modules=f"{modules} × {modules}" if modules else None, orientation_degrees=round(orientation, 2), decode_failed=not bool(value))
                    if value:
                        found.append(_Decoded("QR Code", value, "OpenCV QRCodeDetector", BoundingBox(x=max(0, int(xs.min())), y=max(0, int(ys.min())), width=max(0, int(xs.max() - xs.min())), height=max(0, int(ys.max() - ys.min())))))
        except Exception:
            pass
        try:
            from pyzbar.pyzbar import decode as zbar_decode  # type: ignore[import-not-found]
            for item in zbar_decode(image):
                value = item.data.decode("utf-8", errors="replace")
                decoded = _Decoded(_normalize_symbology(str(item.type)), value, "pyzbar/zbar", BoundingBox(x=max(0, item.rect.left), y=max(0, item.rect.top), width=max(0, item.rect.width), height=max(0, item.rect.height)))
                if value:
                    found.append(decoded)
        except (ImportError, OSError, RuntimeError, ValueError):
            pass
        try:
            import zxingcpp  # type: ignore[import-not-found]
            for item in zxingcpp.read_barcodes(np.asarray(image.convert("RGB"))):
                value = str(item.text)
                position = item.position
                corners = [position.top_left, position.top_right, position.bottom_right, position.bottom_left]
                xs = [int(point.x) for point in corners]
                ys = [int(point.y) for point in corners]
                decoded = _Decoded(
                    _normalize_symbology(str(item.format).replace("BarcodeFormat.", "")), value, "ZXing-C++",
                    BoundingBox(x=max(0, min(xs)), y=max(0, min(ys)), width=max(0, max(xs) - min(xs)), height=max(0, max(ys) - min(ys))),
                )
                if value:
                    found.append(decoded)
        except (ImportError, AttributeError, RuntimeError, ValueError):
            pass
        return found, structure

    def _secondary(self, value: str) -> QRDecodeResult | None:
        compact = "".join(value.split())
        strong: set[str] = set()
        if len(compact) >= 12 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", compact) and (compact.endswith("=") or len(compact) >= 20):
            strong.add("Base64")
        if len(compact) >= 16 and re.fullmatch(r"[A-Z2-7]+={0,6}", compact, re.IGNORECASE):
            strong.add("Base32")
        if len(value) >= 8 and not any(character.isspace() for character in value) and re.fullmatch(r"[0-9a-fA-F]+", value) and re.search(r"[a-fA-F]", value):
            strong.add("Hex")
        if len(compact) >= 16 and re.fullmatch(r"[01]+", compact):
            strong.add("Binary")
        if re.search(r"%[0-9a-fA-F]{2}", value):
            strong.add("URL")
        detections = [item for item in detect_encodings(value.encode()) if item.confidence >= 0.78 and item.name in strong]
        if not detections:
            return None
        result = self._decoder.analyze(DecodeRequest(
            input=value, max_depth=4, max_results=5, beam_width=16, timeout_ms=1000,
            flag_prefixes=_FLAG_PREFIXES,
        ))
        candidate = next((item for item in result.results if item.chain and item.output != value), None)
        if candidate is None:
            return QRDecodeResult(detected_encodings=[item.name for item in detections])
        return QRDecodeResult(
            detected_encodings=[item.name for item in detections],
            chain=[DecodeStep(transform=step.transform, parameter=step.parameter, output=candidate.output if index == len(candidate.chain) - 1 else "intermediate value") for index, step in enumerate(candidate.chain)],
            decoded=candidate.output, flags=list(dict.fromkeys(item.value for item in candidate.flags)),
        )


__all__ = ["QRBarcodeRecoveryAnalyzer"]
