from __future__ import annotations

import re
import tempfile
from functools import partial
from pathlib import Path
from uuid import uuid4

from anyio import to_thread
from fastapi import UploadFile

from app.analyzers.forensics.audio import AudioAnalysisEngine, AudioInput
from app.analyzers.forensics.audio.engine import RawPcmOptions
from app.core.errors import ArtifactTooLargeError, InvalidArtifactError
from app.schemas.audio import AudioAnalysisResponse


_UPLOAD_CHUNK_BYTES = 1024 * 1024
_CUSTOM_PREFIX = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")


def _safe_filename(filename: str | None) -> str:
    if not filename or "\x00" in filename:
        raise InvalidArtifactError("A non-empty, valid audio filename is required.")
    basename = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not basename or basename in {".", ".."}:
        raise InvalidArtifactError("A non-empty, valid audio filename is required.")
    return basename[:255]


class AudioAnalysisService:
    def __init__(self, engine: AudioAnalysisEngine | None = None) -> None:
        self.engine = engine or AudioAnalysisEngine()

    async def analyze(
        self,
        upload: UploadFile,
        *,
        raw_sample_rate: int | None = None,
        raw_bit_depth: int | None = None,
        raw_endianness: str | None = None,
        raw_channels: int | None = None,
        raw_signed: bool | None = None,
        custom_flag_prefix: str | None = None,
    ) -> AudioAnalysisResponse:
        filename = _safe_filename(upload.filename)
        if custom_flag_prefix and not _CUSTOM_PREFIX.fullmatch(custom_flag_prefix):
            raise InvalidArtifactError("The custom flag prefix must contain 1–32 letters, numbers, underscores, or hyphens.")
        extension = Path(filename).suffix.lower()
        raw_options = None
        if extension in {".raw", ".pcm"}:
            if None in {raw_sample_rate, raw_bit_depth, raw_endianness, raw_channels, raw_signed}:
                raise InvalidArtifactError("RAW/PCM uploads require all sample-format parameters.")
            if raw_endianness not in {"little", "big"}:
                raise InvalidArtifactError("RAW PCM endianness must be 'little' or 'big'.")
            raw_options = RawPcmOptions(
                sample_rate=int(raw_sample_rate),
                bit_depth=int(raw_bit_depth),
                endianness=raw_endianness,
                channels=int(raw_channels),
                signed=bool(raw_signed),
            )

        maximum = self.engine.policy.max_upload_bytes
        try:
            with tempfile.TemporaryDirectory(prefix="ctfkit-audio-") as temporary:
                workspace = Path(temporary).resolve()
                destination = workspace / f"evidence-{uuid4()}"
                size = 0
                with destination.open("xb") as output:
                    while chunk := await upload.read(_UPLOAD_CHUNK_BYTES):
                        size += len(chunk)
                        if size > maximum:
                            raise ArtifactTooLargeError(maximum)
                        output.write(chunk)
                if size == 0:
                    raise InvalidArtifactError("An empty file cannot be analyzed as audio.")
                analysis_input = AudioInput(
                    path=destination,
                    original_filename=filename,
                    workspace=workspace,
                    raw_options=raw_options,
                    custom_flag_prefix=custom_flag_prefix,
                )
                return await to_thread.run_sync(partial(self.engine.analyze, analysis_input))
        finally:
            await upload.close()

