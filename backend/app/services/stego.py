from __future__ import annotations

import logging
import tempfile
import threading
from functools import partial
from pathlib import Path
from uuid import uuid4

from anyio import CapacityLimiter, to_thread
from fastapi import UploadFile

from app.analyzers.stego import ImageStegoAnalyzer, StegoInput
from app.analyzers.stego.image import _detect_image_format
from app.core.errors import (
    AnalysisBusyError,
    AnalysisFailedError,
    AnalysisResourceLimitError,
    ArtifactTooLargeError,
    InvalidArtifactError,
)
from app.schemas.stego import StegoAnalysisResponse

_UPLOAD_CHUNK_BYTES = 1024 * 1024
logger = logging.getLogger(__name__)


def _safe_display_name(filename: str | None) -> str:
    if not filename or "\x00" in filename:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    normalized = filename.replace("\\", "/")
    basename = normalized.rsplit("/", 1)[-1].strip()
    if not basename or basename in {".", ".."}:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    return basename[:255]


class StegoAnalysisService:
    def __init__(self, analyzer: ImageStegoAnalyzer | None = None) -> None:
        self._analyzer = analyzer or ImageStegoAnalyzer()
        self._worker_limiter = CapacityLimiter(1)
        self._request_slot = threading.Lock()

    async def analyze(
        self,
        upload: UploadFile,
        *,
        show_all: bool = False,
        deep_scan: bool = False,
    ) -> StegoAnalysisResponse:
        if not self._request_slot.acquire(blocking=False):
            await upload.close()
            raise AnalysisBusyError(self._analyzer.name)
        artifact_id = str(uuid4())

        try:
            original_filename = _safe_display_name(upload.filename)
            maximum = self._analyzer.policy.max_upload_bytes
            with tempfile.TemporaryDirectory(prefix="ctfkit-stego-") as temporary:
                workspace = Path(temporary)
                artifact_path = workspace / f"artifact-{artifact_id}"
                size = 0
                first_chunk = True
                with artifact_path.open("xb") as destination:
                    while chunk := await upload.read(_UPLOAD_CHUNK_BYTES):
                        if first_chunk:
                            first_chunk = False
                            if _detect_image_format(chunk[:12]) is None:
                                raise InvalidArtifactError(
                                    "Only PNG, BMP, GIF, TIFF, lossless WebP, and JPEG images are supported."
                                )
                        size += len(chunk)
                        if size > maximum:
                            raise ArtifactTooLargeError(maximum)
                        destination.write(chunk)

                if size == 0:
                    raise InvalidArtifactError("A non-empty image file is required.")

                stego_input = StegoInput(
                    path=artifact_path,
                    original_filename=original_filename,
                    artifact_id=artifact_id,
                    workspace=workspace,
                    show_all=show_all,
                    deep_scan=deep_scan,
                )
                try:
                    return await to_thread.run_sync(
                        partial(self._analyzer.analyze, stego_input),
                        limiter=self._worker_limiter,
                    )
                except InvalidArtifactError:
                    raise
                except MemoryError as exc:
                    logger.exception(
                        "Stego analysis exhausted memory",
                        extra={"artifact_id": artifact_id, "analyzer": self._analyzer.name},
                    )
                    raise AnalysisResourceLimitError(self._analyzer.name) from exc
                except Exception as exc:
                    logger.exception(
                        "Stego analysis failed",
                        extra={"artifact_id": artifact_id, "analyzer": self._analyzer.name},
                    )
                    raise AnalysisFailedError(self._analyzer.name) from exc
        finally:
            self._request_slot.release()
            await upload.close()
