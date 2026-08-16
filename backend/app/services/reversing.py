from __future__ import annotations

import tempfile
import struct
from functools import partial
from pathlib import Path
from uuid import uuid4

from anyio import to_thread
from fastapi import UploadFile

from app.analyzers.reversing import ReverseInput, StaticReverseAnalyzer
from app.core.errors import ArtifactTooLargeError, InvalidArtifactError
from app.schemas.reversing import ReverseAnalysisResponse

_UPLOAD_CHUNK_BYTES = 1024 * 1024


def _safe_display_name(filename: str | None) -> str:
    if not filename or "\x00" in filename:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    basename = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not basename or basename in {".", ".."}:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    return basename[:255]


class ReverseAnalysisService:
    def __init__(self, analyzer: StaticReverseAnalyzer | None = None) -> None:
        self._analyzer = analyzer or StaticReverseAnalyzer()

    async def analyze(
        self,
        upload: UploadFile,
        *,
        custom_flag_prefix: str | None = None,
    ) -> ReverseAnalysisResponse:
        original_filename = _safe_display_name(upload.filename)
        prefix = custom_flag_prefix.strip() if custom_flag_prefix else None
        if prefix and (not prefix.isascii() or not prefix.replace("_", "").isalnum()):
            raise InvalidArtifactError("The custom flag prefix must contain only ASCII letters, numbers, or underscores.")
        maximum = self._analyzer.policy.max_upload_bytes
        artifact_id = str(uuid4())
        try:
            with tempfile.TemporaryDirectory(prefix="ctfkit-reverse-") as temporary:
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
                    raise InvalidArtifactError("The uploaded artifact is empty.")
                analysis_input = ReverseInput(
                    path=artifact_path,
                    original_filename=original_filename,
                    artifact_id=artifact_id,
                    custom_flag_prefix=prefix,
                )
                try:
                    return await to_thread.run_sync(partial(self._analyzer.analyze, analysis_input))
                except (struct.error, IndexError, OverflowError) as exc:
                    raise InvalidArtifactError("The executable header is malformed or truncated.") from exc
                except ValueError as exc:
                    raise InvalidArtifactError(str(exc)) from exc
        finally:
            await upload.close()
