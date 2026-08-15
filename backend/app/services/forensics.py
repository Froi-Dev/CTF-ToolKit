from __future__ import annotations

import tempfile
from functools import partial
from pathlib import Path
from uuid import uuid4

from anyio import to_thread
from fastapi import UploadFile

from app.analyzers.forensics import FileTriageAnalyzer, TriageInput
from app.core.errors import ArtifactTooLargeError, InvalidArtifactError
from app.schemas.forensics import ForensicsTriageResponse

_UPLOAD_CHUNK_BYTES = 1024 * 1024


def _safe_display_name(filename: str | None) -> str:
    if not filename or "\x00" in filename:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    # Browsers normally provide a basename, but old clients can submit either slash style.
    normalized = filename.replace("\\", "/")
    basename = normalized.rsplit("/", 1)[-1].strip()
    if not basename or basename in {".", ".."}:
        raise InvalidArtifactError("A non-empty, valid filename is required.")
    return basename[:255]


class ForensicsTriageService:
    def __init__(self, analyzer: FileTriageAnalyzer | None = None) -> None:
        self._analyzer = analyzer or FileTriageAnalyzer()

    async def triage(self, upload: UploadFile) -> ForensicsTriageResponse:
        original_filename = _safe_display_name(upload.filename)
        maximum = self._analyzer.policy.max_upload_bytes
        artifact_id = str(uuid4())

        try:
            with tempfile.TemporaryDirectory(prefix="ctfkit-triage-") as temporary:
                workspace = Path(temporary)
                artifact_path = workspace / f"artifact-{artifact_id}"
                size = 0
                with artifact_path.open("xb") as destination:
                    while chunk := await upload.read(_UPLOAD_CHUNK_BYTES):
                        size += len(chunk)
                        if size > maximum:
                            raise ArtifactTooLargeError(maximum)
                        destination.write(chunk)

                triage_input = TriageInput(
                    path=artifact_path,
                    original_filename=original_filename,
                    artifact_id=artifact_id,
                    extraction_root=workspace / "extracted",
                )
                return await to_thread.run_sync(
                    partial(self._analyzer.analyze, triage_input)
                )
        finally:
            await upload.close()
