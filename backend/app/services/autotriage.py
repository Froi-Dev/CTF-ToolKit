from __future__ import annotations

import tempfile
from functools import partial
from pathlib import Path
from time import perf_counter
from uuid import uuid4

from anyio import to_thread
from fastapi import UploadFile

from app.analyzers.forensics import FileTriageAnalyzer, TriageInput
from app.analyzers.network import NetworkPcapAnalyzer, PcapInput
from app.analyzers.network.parsing import capture_format
from app.analyzers.stego import ImageStegoAnalyzer, StegoInput
from app.core.errors import (
    ArtifactTooLargeError,
    InvalidArtifactError,
    ToolExecutionError,
    ToolNotAvailableError,
)
from app.schemas.autotriage import (
    AnalyzerRun,
    AutoTriageResponse,
    CapabilityStatus,
    TriageStatus,
)
from app.schemas.forensics import ForensicsTriageResponse
from app.schemas.network import NetworkAnalysisResponse
from app.schemas.stego import StegoAnalysisResponse

_UPLOAD_CHUNK_BYTES = 1024 * 1024


def _safe_display_name(filename: str | None) -> str:
    if not filename or "\x00" in filename:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    normalized = filename.replace("\\", "/")
    basename = normalized.rsplit("/", 1)[-1].strip()
    if not basename or basename in {".", ".."}:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    return basename[:255]


def _elapsed_ms(started: float) -> int:
    return max(0, round((perf_counter() - started) * 1000))


class AutoTriageService:
    """Select and run existing static analyzers against one safely stored upload."""

    def __init__(
        self,
        forensics: FileTriageAnalyzer | None = None,
        stego: ImageStegoAnalyzer | None = None,
        network: NetworkPcapAnalyzer | None = None,
    ) -> None:
        self._forensics = forensics or FileTriageAnalyzer()
        self._stego = stego or ImageStegoAnalyzer()
        self._network = network or NetworkPcapAnalyzer()

    async def analyze(self, upload: UploadFile) -> AutoTriageResponse:
        original_filename = _safe_display_name(upload.filename)
        maximum = min(
            self._forensics.policy.max_upload_bytes,
            self._stego.policy.max_upload_bytes,
            self._network.policy.max_upload_bytes,
        )
        artifact_id = str(uuid4())

        try:
            with tempfile.TemporaryDirectory(prefix="ctfkit-auto-triage-") as temporary:
                workspace = Path(temporary)
                artifact_path = workspace / f"artifact-{artifact_id}"
                size = 0
                with artifact_path.open("xb") as destination:
                    while chunk := await upload.read(_UPLOAD_CHUNK_BYTES):
                        size += len(chunk)
                        if size > maximum:
                            raise ArtifactTooLargeError(maximum)
                        destination.write(chunk)

                if size == 0:
                    raise InvalidArtifactError("A non-empty artifact is required.")

                return await to_thread.run_sync(
                    partial(
                        self._analyze_stored,
                        artifact_path,
                        workspace,
                        original_filename,
                        artifact_id,
                    )
                )
        finally:
            await upload.close()

    def _analyze_stored(
        self,
        artifact_path: Path,
        workspace: Path,
        original_filename: str,
        artifact_id: str,
    ) -> AutoTriageResponse:
        analysis_started = perf_counter()
        forensics_started = perf_counter()
        forensics = self._forensics.analyze(
            TriageInput(
                path=artifact_path,
                original_filename=original_filename,
                artifact_id=artifact_id,
                extraction_root=workspace / "forensics-extracted",
            )
        )
        runs = [
            AnalyzerRun(
                analyzer=self._forensics.name,
                category="forensics",
                status="completed",
                duration_ms=_elapsed_ms(forensics_started),
                message="Baseline static file triage completed.",
            )
        ]
        warnings = list(forensics.warnings)

        steganography: StegoAnalysisResponse | None = None
        if forensics.magic.detected_type in {"png", "jpeg"}:
            stego_started = perf_counter()
            stego_workspace = workspace / "steganography"
            stego_workspace.mkdir()
            try:
                steganography = self._stego.analyze(
                    StegoInput(
                        path=artifact_path,
                        original_filename=original_filename,
                        artifact_id=artifact_id,
                        workspace=stego_workspace,
                    )
                )
            except (InvalidArtifactError, OSError, ValueError) as exc:
                message = f"Image steganography analysis failed safely: {exc}"
                runs.append(
                    AnalyzerRun(
                        analyzer=self._stego.name,
                        category="steganography",
                        status="failed",
                        duration_ms=_elapsed_ms(stego_started),
                        message=message,
                    )
                )
                warnings.append(message)
            else:
                runs.append(
                    AnalyzerRun(
                        analyzer=self._stego.name,
                        category="steganography",
                        status="completed",
                        duration_ms=_elapsed_ms(stego_started),
                        message="Image structure, channels, bit planes, and LSB streams inspected.",
                    )
                )
                warnings.extend(steganography.warnings)
        else:
            runs.append(
                AnalyzerRun(
                    analyzer=self._stego.name,
                    category="steganography",
                    status="skipped",
                    duration_ms=0,
                    message="LSB analysis applies only to detected PNG and JPEG images.",
                )
            )

        network: NetworkAnalysisResponse | None = None
        with artifact_path.open("rb") as source:
            detected_capture = capture_format(source.read(4))
        if detected_capture is not None:
            network_started = perf_counter()
            network_workspace = workspace / "network"
            network_workspace.mkdir()
            try:
                network = self._network.analyze(
                    PcapInput(
                        path=artifact_path,
                        original_filename=original_filename,
                        artifact_id=artifact_id,
                        workspace=network_workspace,
                        capture_format=detected_capture,
                    )
                )
            except ToolNotAvailableError as exc:
                message = f"Network analysis unavailable: {exc}"
                runs.append(
                    AnalyzerRun(
                        analyzer=self._network.name,
                        category="network",
                        status="unavailable",
                        duration_ms=_elapsed_ms(network_started),
                        message=message,
                    )
                )
                warnings.append(message)
            except (InvalidArtifactError, ToolExecutionError, OSError, ValueError) as exc:
                message = f"Network analysis failed safely: {exc}"
                runs.append(
                    AnalyzerRun(
                        analyzer=self._network.name,
                        category="network",
                        status="failed",
                        duration_ms=_elapsed_ms(network_started),
                        message=message,
                    )
                )
                warnings.append(message)
            else:
                runs.append(
                    AnalyzerRun(
                        analyzer=self._network.name,
                        category="network",
                        status="completed",
                        duration_ms=_elapsed_ms(network_started),
                        message="Packet, protocol, stream, credential, file, and flag analysis completed.",
                    )
                )
                warnings.extend(network.warnings)
        else:
            runs.append(
                AnalyzerRun(
                    analyzer=self._network.name,
                    category="network",
                    status="skipped",
                    duration_ms=0,
                    message="Network analysis applies only to detected PCAP and PCAPNG captures.",
                )
            )

        return AutoTriageResponse(
            analysis_id=str(uuid4()),
            artifact_id=artifact_id,
            original_filename=original_filename,
            size=forensics.size,
            detected_type=forensics.magic.detected_type,
            mime_type=forensics.magic.mime_type,
            duration_ms=_elapsed_ms(analysis_started),
            analyzer_runs=runs,
            capabilities=self._capabilities(forensics, steganography, network, runs),
            forensics=forensics,
            steganography=steganography,
            network=network,
            warnings=list(dict.fromkeys(warnings)),
        )

    @staticmethod
    def _capabilities(
        forensics: ForensicsTriageResponse,
        stego: StegoAnalysisResponse | None,
        network: NetworkAnalysisResponse | None,
        runs: list[AnalyzerRun],
    ) -> list[CapabilityStatus]:
        stego_run = next(item for item in runs if item.category == "steganography")
        network_run = next(item for item in runs if item.category == "network")

        def capability(
            key: str,
            label: str,
            analyzer: str,
            status: TriageStatus,
            count: int,
            message: str,
        ) -> CapabilityStatus:
            return CapabilityStatus(
                key=key,  # type: ignore[arg-type]
                label=label,
                analyzer=analyzer,
                status=status,
                result_count=count,
                message=message,
            )

        image_count = 0 if stego is None else len(stego.png_chunks) + len(stego.jpeg_segments)
        lsb_count = 0 if stego is None else len(stego.lsb)
        packet_count = 0 if network is None else network.capture.analyzed_packet_count
        flag_count = len(forensics.flags)
        if stego is not None:
            flag_count += len(stego.flags)
        if network is not None:
            flag_count += len(network.flags)

        return [
            capability("file_identification", "File identification", forensics.analyzer, "completed", 1, forensics.magic.description),
            capability("hashes", "Cryptographic hashes", forensics.analyzer, "completed", 3, "MD5, SHA-1, and SHA-256 calculated."),
            capability("metadata", "Metadata", forensics.analyzer, "completed", len(forensics.metadata), "Format-aware metadata extracted."),
            capability("strings", "Strings", forensics.analyzer, "completed", len(forensics.strings), "ASCII and UTF-16 strings inspected."),
            capability("entropy", "Entropy", forensics.analyzer, "completed", 1, f"{forensics.entropy.bits_per_byte:.4f} bits per byte."),
            capability("signatures", "File signatures", forensics.analyzer, "completed", len(forensics.signatures), "Root and embedded signatures scanned."),
            capability("archives", "Archive inspection", forensics.analyzer, "completed", len(forensics.archives), "Supported archives inspected with extraction limits."),
            capability("embedded_files", "Embedded files", forensics.analyzer, "completed", len(forensics.embedded_files), "Embedded file candidates inspected and safely carved when bounded."),
            capability("flag_detection", "Flag candidates", "auto_triage", "completed", flag_count, "Regex matches remain unconfirmed candidates."),
            capability("image_structure", "Image structure", stego_run.analyzer, stego_run.status, image_count, stego_run.message),
            capability("lsb", "LSB / bit planes", stego_run.analyzer, stego_run.status, lsb_count, stego_run.message),
            capability("network_protocols", "Network protocols", network_run.analyzer, network_run.status, packet_count, network_run.message),
        ]
