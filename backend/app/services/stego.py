from __future__ import annotations

import tempfile
from functools import partial
from pathlib import Path
from uuid import uuid4

from anyio import to_thread
from fastapi import UploadFile

from app.analyzers.stego import ImageStegoAnalyzer, StegoInput
from app.analyzers.stego.structures import JPEG_SIGNATURE, PNG_SIGNATURE
from app.core.errors import ArtifactTooLargeError, InvalidArtifactError
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


class StegoAnalysisService:
    def __init__(self, analyzer: ImageStegoAnalyzer | None = None) -> None:
        self._analyzer = analyzer or ImageStegoAnalyzer()

    async def analyze(self, upload: UploadFile) -> StegoAnalysisResponse:
        original_filename = _safe_display_name(upload.filename)
        maximum = self._analyzer.policy.max_upload_bytes
        artifact_id = str(uuid4())

        try:
            with tempfile.TemporaryDirectory(prefix="ctfkit-stego-") as temporary:
                workspace = Path(temporary)
                artifact_path = workspace / f"artifact-{artifact_id}"
                size = 0
                first_chunk = True
                with artifact_path.open("xb") as destination:
                    while chunk := await upload.read(_UPLOAD_CHUNK_BYTES):
                        if first_chunk:
                            first_chunk = False
                            if not chunk.startswith((PNG_SIGNATURE, JPEG_SIGNATURE)):
                                raise InvalidArtifactError(
                                    "Only PNG and JPEG images are supported for steganography analysis."
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
                )
                return await to_thread.run_sync(partial(self._analyzer.analyze, stego_input))
        finally:
            await upload.close()
