from __future__ import annotations

import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from threading import Lock
from time import monotonic
from uuid import UUID, uuid4

from anyio import to_thread
from fastapi import UploadFile

from app.analyzers.network import NetworkPcapAnalyzer, PcapInput
from app.analyzers.network.capture_loader import inspect_capture
from app.analyzers.network.flag_hunter import normalize_flag_prefix
from app.analyzers.network.parsing import capture_format
from app.core.errors import ArtifactTooLargeError, InvalidArtifactError
from app.schemas.network import NetworkAnalysisProgress, NetworkAnalysisResponse

_UPLOAD_CHUNK_BYTES = 1024 * 1024
_MAX_PROGRESS_RECORDS = 128


@dataclass(slots=True)
class _ProgressEntry:
    status: str
    stage: str
    detail: str
    started: float
    updated_at: datetime


def _safe_display_name(filename: str | None) -> str:
    if not filename or "\x00" in filename:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    normalized = filename.replace("\\", "/")
    basename = normalized.rsplit("/", 1)[-1].strip()
    if not basename or basename in {".", ".."}:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    return basename[:255]


class NetworkAnalysisService:
    def __init__(self, analyzer: NetworkPcapAnalyzer | None = None) -> None:
        self._analyzer = analyzer or NetworkPcapAnalyzer()
        self._progress: dict[str, _ProgressEntry] = {}
        self._progress_lock = Lock()

    async def analyze(
        self,
        upload: UploadFile,
        custom_flag_prefix: str | None = None,
        progress_id: str | None = None,
    ) -> NetworkAnalysisResponse:
        normalized_progress_id = self._normalize_progress_id(progress_id)
        if normalized_progress_id:
            self._start_progress(normalized_progress_id)
        original_filename = _safe_display_name(upload.filename)
        try:
            normalized_prefix = normalize_flag_prefix(custom_flag_prefix)
        except ValueError as exc:
            raise InvalidArtifactError(str(exc)) from exc
        artifact_id = str(uuid4())
        maximum = self._analyzer.policy.max_upload_bytes

        try:
            with tempfile.TemporaryDirectory(prefix="ctfkit-pcap-") as temporary:
                workspace = Path(temporary)
                artifact_path = workspace / f"capture-{artifact_id}"
                size = 0
                header = bytearray()
                with artifact_path.open("xb") as destination:
                    while chunk := await upload.read(_UPLOAD_CHUNK_BYTES):
                        size += len(chunk)
                        if size > maximum:
                            raise ArtifactTooLargeError(maximum)
                        if len(header) < 4:
                            header.extend(chunk[: 4 - len(header)])
                        destination.write(chunk)
                        if normalized_progress_id and size % (8 * _UPLOAD_CHUNK_BYTES) < len(chunk):
                            self._update_progress(
                                normalized_progress_id,
                                "uploading",
                                "network.upload",
                                f"Received {size / (1024 * 1024):.1f} MiB",
                            )

                detected_format = capture_format(bytes(header))
                if detected_format is None:
                    raise InvalidArtifactError(
                        "The upload is not a PCAP or PCAPNG capture based on its file signature."
                    )
                descriptor = inspect_capture(artifact_path, detected_format)
                if normalized_progress_id:
                    self._update_progress(
                        normalized_progress_id,
                        "analyzing",
                        "network.capture",
                        f"Validated {detected_format.upper()} capture with {descriptor.packet_count} packet(s)",
                    )
                pcap_input = PcapInput(
                    path=artifact_path,
                    original_filename=original_filename,
                    artifact_id=artifact_id,
                    workspace=workspace,
                    capture_format=detected_format,
                    capture_descriptor=descriptor,
                    flag_prefixes=(normalized_prefix,) if normalized_prefix else (),
                )
                callback = (
                    partial(self._analysis_progress, normalized_progress_id)
                    if normalized_progress_id
                    else None
                )
                response = await to_thread.run_sync(
                    partial(self._analyzer.analyze, pcap_input, progress=callback)
                )
                if normalized_progress_id:
                    self._update_progress(
                        normalized_progress_id,
                        "complete",
                        "network.complete",
                        "Analysis complete",
                    )
                return response
        except Exception:
            if normalized_progress_id:
                self._update_progress(
                    normalized_progress_id,
                    "failed",
                    "network.failed",
                    "Analysis failed; see the returned API error for details",
                )
            raise
        finally:
            await upload.close()

    def get_progress(self, progress_id: str) -> NetworkAnalysisProgress | None:
        normalized = self._normalize_progress_id(progress_id)
        if normalized is None:
            return None
        with self._progress_lock:
            entry = self._progress.get(normalized)
            if entry is None:
                return None
            return NetworkAnalysisProgress(
                progress_id=normalized,
                status=entry.status,  # type: ignore[arg-type]
                stage=entry.stage,
                detail=entry.detail,
                elapsed_ms=max(0, round((monotonic() - entry.started) * 1000)),
                updated_at=entry.updated_at,
            )

    @staticmethod
    def _normalize_progress_id(progress_id: str | None) -> str | None:
        if not progress_id:
            return None
        try:
            return str(UUID(progress_id))
        except (ValueError, AttributeError) as exc:
            raise InvalidArtifactError("progress_id must be a valid UUID.") from exc

    def _start_progress(self, progress_id: str) -> None:
        with self._progress_lock:
            if len(self._progress) >= _MAX_PROGRESS_RECORDS:
                oldest = min(self._progress, key=lambda key: self._progress[key].updated_at)
                self._progress.pop(oldest, None)
            self._progress[progress_id] = _ProgressEntry(
                status="uploading",
                stage="network.upload",
                detail="Receiving capture upload",
                started=monotonic(),
                updated_at=datetime.now(UTC),
            )

    def _analysis_progress(self, progress_id: str, stage: str, detail: str | None) -> None:
        self._update_progress(progress_id, "analyzing", stage, detail or stage)

    def _update_progress(
        self,
        progress_id: str,
        status: str,
        stage: str,
        detail: str,
    ) -> None:
        with self._progress_lock:
            entry = self._progress.get(progress_id)
            if entry is None:
                return
            entry.status = status
            entry.stage = stage
            entry.detail = detail
            entry.updated_at = datetime.now(UTC)
